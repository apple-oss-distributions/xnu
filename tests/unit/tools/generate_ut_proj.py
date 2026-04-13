#!/usr/bin/env python3
import json
import argparse
import os
import pathlib
import xml.etree.ElementTree as ET
import uuid

# This scripts takes a compile_commands.json file that was generated using `make -C tests/unit cmds_json`
# and creates project files for an IDE that can be used for debugging user-space unit-tests
# The project is not able to build XNU or the test executable

SRC_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))

TESTS_UNIT_PREFIX = "tests/unit/"
TESTS_UNIT_BUILD_PREFIX = TESTS_UNIT_PREFIX + "build/sym/"

def parse_command(entry):
    file = entry['file']
    directory = entry["directory"]
    if not file.startswith(SRC_ROOT):
        full_file = directory + "/" + file
    else:
        full_file = file
    assert full_file.startswith(SRC_ROOT), "unexpected path" + full_file
    rel_file = full_file[len(SRC_ROOT)+1:]

    # arguments[0] is clang
    args = entry['arguments'][1:]

    args.extend(['-I', directory])
    return rel_file, args

# -------------------------------------- Xcode project ----------------------------------------
# an Xcode project is a plist with a list of objects. each object has an ID and objects reference
# each other by their ID.

def do_quote_lst(dash_split):
    output = []
    # change ' -DX=y z' to ' -DX="y z"'
    for i, s in enumerate(dash_split):
        if i == 0:
            continue # skip the clang executable
        if '=' in s:
            st = s.strip()
            eq_sp = st.split('=')
            if ' ' in eq_sp[1]:
                output.append(f'{eq_sp[0]}=\\"{eq_sp[1]}\\"')
                continue

        output.append(f"{s}")
    return " ".join(output)

class ObjType:
    def __init__(self, idprefix, type_name):
        self.type_name = type_name
        self.id_prefix = idprefix
        self.next_count = 1
    def make_id(self):
        id = f"{self.id_prefix:016d}{self.next_count:08d}"
        self.next_count += 1
        return id

class ObjRegistry:
    def __init__(self):
        self.types = {}  # map type-name to id-prefix (12 chars)
        self.next_type_prefix = 1

        self.objects = {} # map object-id to instance

    def register(self, type_name, obj):
        if type_name not in self.types:
            self.types[type_name] = ObjType(self.next_type_prefix, type_name)
            self.next_type_prefix += 1
        id = self.types[type_name].make_id()
        self.objects[id] = obj
        return id


obj_reg = ObjRegistry()

TYPE_SOURCE_C = "sourcecode.c.c"
TYPE_SOURCE_CPP = "sourcecode.cpp.cpp"
TYPE_SOURCE_ASM = "sourcecode.asm"
TYPE_HEADER = "sourcecode.c.h"
TYPE_STATIC_LIB = "archive.ar"
TYPE_EXE = '"compiled.mach-o.executable"'

class ObjList:
    def __init__(self, name=None):
        self.name = name
        self.objs = []
    def add(self, obj):
        self.objs.append(obj)
    def extend(self, lst):
        self.objs.extend(lst)

def tab(count):
    return '\t' * count

# The top-level object list is special in that it's grouped by the type of objects
# This class represents part of the top level objects list
class TopObjList(ObjList):
    def write(self, out, lvl):
        out.write(f"/* Begin {self.name} section */\n")
        for obj in self.objs:
            out.write(f"{tab(lvl)}{obj.id} = ")
            obj.write(out, lvl)
        out.write(f"/* End {self.name} section */\n\n")

# a property that is serilized as a list of ids
class IdList(ObjList):
    def write(self, out, lvl):
        out.write("(\n") # after =
        for obj in self.objs:
            out.write(f"{tab(lvl+1)}{obj.id} /* {obj.name} */,\n")
        out.write(f"{tab(lvl)});\n")

class StrList:
    def __init__(self, lst):
        self.lst = lst
    def write(self, out, lvl):
        out.write("(\n") # after =
        for v in self.lst:
            out.write(f"{tab(lvl+1)}{v},\n")
        out.write(f"{tab(lvl)});\n")
    @classmethod
    def list_sort_quote(cls, s):
        l = list(s)
        l.sort()
        return cls([f'"{d}"' for d in l])

class StrEval:
    def __init__(self, fn):
        self.fn = fn
    def write(self, out, lvl):
        out.write(self.fn() + ";\n")
class LateEval:
    def __init__(self, fn):
        self.fn = fn
    def write(self, out, lvl):
        self.fn().write(out, lvl)

class PDict:
    def __init__(self, isa, inline=False):
        self.d = {}
        self.p = []
        self.inline = inline
        if isa is not None:
            self.isa = self.padd("isa", isa)

    def padd(self, k, v, comment=None):
        self.p.append((k, v, comment))
        self.d[k] = v
        return v
    def pextend(self, d):
        for k, v in d.items():
            self.padd(k, v)

    def write(self, out, lvl):
        if self.inline:
            out.write("{")
            for k, v, comment in self.p:
                assert isinstance(v, str) or isinstance(v, int), "complex value inline"
                out.write(f"{k} = ")
                if comment is None:
                    out.write(f"{v}; ")
                else:
                    out.write(f"{v} /* {comment} */; ")
            out.write("};\n")
        else:
            out.write("{\n")  # comes after =
            for k, v, comment in self.p:
                out.write(f"{tab(lvl+1)}{k} = ")
                if isinstance(v, str) or isinstance(v, int):
                    if comment is None:
                        out.write(f"{v};\n")
                    else:
                        out.write(f"{v} /* {comment} */;\n")
                else:
                    v.write(out, lvl+1)
            out.write(f"{tab(lvl)}}};\n")


class File:
    def __init__(self, name, args):
        self.name = name.split('/')[-1]
        self.args = args
        self.ref = None

    def type_str(self):
        ext = os.path.splitext(self.name)[1]
        if ext == ".c":
            return TYPE_SOURCE_C
        if ext == ".h":
            return TYPE_HEADER
        if ext == ".cpp":
            return TYPE_SOURCE_CPP
        if ext == ".a":
            return TYPE_STATIC_LIB
        if ext == ".s":
            return TYPE_SOURCE_ASM
        if ext == '':
            return TYPE_EXE
        return None

class BuildFile(PDict):
    def __init__(self, file):
        PDict.__init__(self, "PBXBuildFile", inline=True)
        self.id = obj_reg.register("build_file", self)
        self.file = file
        self.name = file.name
        self.padd("fileRef", self.file.ref.id, comment=self.file.name)

class FileRef(PDict):
    def __init__(self, file):
        PDict.__init__(self, "PBXFileReference", inline=True)
        self.id = obj_reg.register("file_ref", self)
        self.file = file
        file.ref = self
        typ = self.file.type_str()
        assert typ is not None, "unknown file type " + self.file.name
        if typ == TYPE_STATIC_LIB or typ == TYPE_EXE:
            self.padd("explicitFileType", typ)
            self.padd("includeInIndex", 0)
            self.padd("path", f'"{self.file.name}"')
            self.padd("sourceTree", "BUILT_PRODUCTS_DIR")
        else:
            self.padd("lastKnownFileType", typ)
            self.padd("path", f'"{self.file.name}"')
            self.padd("sourceTree", '"<group>"')

    @property
    def name(self):
        return self.file.name

class Group(PDict):
    def __init__(self, name=None, path=None):
        PDict.__init__(self, "PBXGroup")
        self.id = obj_reg.register("group", self)
        self.children = self.padd("children", IdList())
        self.child_dict = {}  # map name to Group/FileRef
        if name is not None:
            self.name = self.padd("name", name)
        if path is not None:
            self.name = self.padd("path", f'"{path}"')
        self.padd("sourceTree", '"<group>"')

    def rec_add(self, sp_path, groups_lst, file_ref):
        elem = sp_path[0]
        if len(sp_path) == 1:
            assert elem not in self.child_dict, f"already have file elem {elem} in {self.name}"
            self.children.add(file_ref)
            self.child_dict[elem] = file_ref
            #file_ref.file.name = elem # remove the path from the name
        else:
            if elem in self.child_dict:
                g = self.child_dict[elem]
            else:
                g = Group(path=elem)
                groups_lst.add(g)
                self.children.add(g)
                self.child_dict[elem] = g
            g.rec_add(sp_path[1:], groups_lst, file_ref)

    def sort(self):
        self.children.objs.sort(key=lambda x: x.name)
        for elem in self.children.objs:
            if isinstance(elem, Group):
                elem.sort()

class BuildPhase(PDict):
    def __init__(self, isa, name):
        PDict.__init__(self, isa)
        self.id = obj_reg.register("build_phase", self)
        self.name = name
        self.padd("buildActionMask", 2147483647)
        self.files = self.padd("files", IdList())
        self.padd("runOnlyForDeploymentPostprocessing", 0)

class Target(PDict):
    def __init__(self, name, file_ref, cfg_lst, prod_type):
        PDict.__init__(self, "PBXNativeTarget")
        self.id = obj_reg.register("target", self)
        self.cfg_lst = self.padd("buildConfigurationList", cfg_lst.id)
        self.build_phases = self.padd("buildPhases", IdList())
        self.padd("buildRules", IdList())
        self.padd("dependencies", IdList())
        self.name = self.padd("name", name)
        self.padd("packageProductDependencies", IdList())
        self.padd("productName", name)
        self.padd("productReference", file_ref.id, comment=file_ref.name)
        self.padd("productType", prod_type)

class CfgList(PDict):
    def __init__(self, name):
        PDict.__init__(self, "XCConfigurationList")
        self.id = obj_reg.register("config_list", self)
        self.name = name # not used
        self.configs = self.padd("buildConfigurations", IdList())
        self.padd("defaultConfigurationIsVisible", 0)
        self.padd("defaultConfigurationName", StrEval(lambda: self.configs.objs[0].name))

class Config(PDict):
    def __init__(self, name):
        PDict.__init__(self, "XCBuildConfiguration")
        self.id = obj_reg.register("config", self)
        self.settings = self.padd("buildSettings", PDict(None))
        self.name = self.padd("name", name)

class Project(PDict):
    def __init__(self, cfg_lst, group_main, group_prod):
        PDict.__init__(self, "PBXProject")
        self.id = obj_reg.register("project", self)
        self.targets = IdList("targets")
        self.padd("attributes", LateEval(lambda: self.make_attr()))
        self.padd("buildConfigurationList", cfg_lst.id, comment=cfg_lst.name)
        self.padd("developmentRegion", "en")
        self.padd("hasScannedForEncodings", "0")
        self.padd("knownRegions", StrList(["en", "Base"]))
        self.padd("mainGroup", group_main.id)
        self.padd("minimizedProjectReferenceProxies", "1")
        self.padd("preferredProjectObjectVersion", "77")
        self.padd("productRefGroup", group_prod.id)
        self.padd("projectDirPath", '""')
        self.padd("projectRoot", '""')
        self.padd("targets", self.targets)

    def make_attr(self):
        a = PDict(None)
        a.padd("BuildIndependentTargetsInParallel", 1)
        a.padd("LastUpgradeCheck", 1700)
        ta = a.padd("TargetAttributes", PDict(None))
        for t in self.targets.objs:
            p = ta.padd(t.id, PDict(None))
            p.padd("CreatedOnToolsVersion", "17.0")
        return a


class PbxProj:
    def __init__(self):
        self.top_obj = []
        self.build_files = self.add_top(TopObjList("PBXBuildFile"))
        self.file_refs = self.add_top(TopObjList("PBXFileReference"))
        self.groups = self.add_top(TopObjList("PBXGroup"))
        self.build_phases = self.add_top(TopObjList("build phases"))
        self.targets = self.add_top(TopObjList("PBXNativeTarget"))
        self.projects = self.add_top(TopObjList("PBXProject"))
        self.configs = self.add_top(TopObjList("XCBuildConfiguration"))
        self.config_lists = self.add_top(TopObjList("XCConfigurationList"))

        self.group_main = self.add_group(Group())
        self.group_products = self.add_group(Group(name="Products"))
        self.group_main.children.add(self.group_products)

        self.cfg_prod_release = self.add_config(Config("Release"))
        self.cfg_prod_release.settings.pextend({"SDKROOT": "macosx",
                                           "MACOSX_DEPLOYMENT_TARGET": "14.1",
                                           })
        self.proj_cfg_lst = self.add_cfg_lst(CfgList("proj config list"))
        self.proj_cfg_lst.configs.add(self.cfg_prod_release)

        self.root_proj = Project(self.proj_cfg_lst, self.group_main, self.group_products)
        self.projects.add(self.root_proj)

        self.test_exec = []

    def add_top(self, t):
        self.top_obj.append(t)
        return t
    def add_group(self, g):
        self.groups.add(g)
        return g
    def add_build_phase(self, p):
        self.build_phases.add(p)
        return p
    def add_config(self, c):
        self.configs.add(c)
        return c
    def add_cfg_lst(self, c):
        self.config_lists.add(c)
        return c
    def add_target(self, t):
        self.targets.add(t)
        return t

    def add_xnu_archive(self):
        f = File("libkernel.a", [])
        fr = FileRef(f)
        self.file_refs.add(fr)
        self.group_products.children.add(fr)
        self.xnu_phase_headers = self.add_build_phase(BuildPhase("PBXHeadersBuildPhase", "Headers"))
        self.xnu_phase_sources = self.add_build_phase(BuildPhase("PBXSourcesBuildPhase", "Sources"))

        cfg_xnu_release = self.add_config(Config("Release"))
        cfg_xnu_release.settings.pextend( { "CODE_SIGN_STYLE": "Automatic",
                                            "EXECUTABLE_PREFIX": "lib",
                                            "PRODUCT_NAME": '"$(TARGET_NAME)"',
                                            "SKIP_INSTALL": "YES"})
        xnu_cfg_lst = self.add_cfg_lst(CfgList("target config list"))
        xnu_cfg_lst.configs.add(cfg_xnu_release)

        target = self.add_target(Target("xnu_static_lib", fr, xnu_cfg_lst, '"com.apple.product-type.library.static"'))
        target.build_phases.extend([self.xnu_phase_headers, self.xnu_phase_sources])
        self.root_proj.targets.add(target)

    def add_test_target(self, c_file_ref, c_build_file):
        name = os.path.splitext(os.path.split(c_file_ref.name)[1])[0]
        f = File(name, [])
        fr = FileRef(f)
        self.file_refs.add(fr)
        self.group_products.children.add(fr)
        phase_h = self.add_build_phase(BuildPhase("PBXHeadersBuildPhase", "Headers"))
        phase_src = self.add_build_phase(BuildPhase("PBXSourcesBuildPhase", "Sources"))
        phase_src.files.add(c_build_file)

        cfg_release = self.add_config(Config("Release"))
        cfg_release.settings.pextend( { "CODE_SIGN_STYLE": "Automatic",
                                        "PRODUCT_NAME": '"$(TARGET_NAME)"'})
        cfg_lst = self.add_cfg_lst(CfgList("target config list"))
        cfg_lst.configs.add(cfg_release)

        target = self.add_target(Target(name, fr, cfg_lst, '"com.apple.product-type.tool"'))
        target.build_phases.extend([phase_h, phase_src])
        self.root_proj.targets.add(target)
        self.test_exec.append(target)

    def add_file(self, file_path, flags):
        f = File(file_path, flags)
        fr = FileRef(f)
        bf = BuildFile(f)
        self.build_files.add(bf)
        self.file_refs.add(fr)
        self.group_main.rec_add(file_path.split('/'), self.groups, fr)
        typ = f.type_str()
        if typ == TYPE_HEADER:
            self.xnu_phase_headers.files.add(bf)
        elif typ in [TYPE_SOURCE_C, TYPE_SOURCE_CPP, TYPE_SOURCE_ASM]:
            self.xnu_phase_sources.files.add(bf)
        return fr, bf
    def add_ccj(self, ccj):
        test_targets = []
        for entry in ccj:
            src_file, flags = parse_command(entry)
            if src_file.endswith('dt_proxy.c'):
                continue
            fr, bf = self.add_file(src_file, flags)
            if src_file.startswith(TESTS_UNIT_PREFIX):
                test_targets.append((fr, bf))
        test_targets.sort(key=lambda x:x[1].name)
        for fr, bf in test_targets:
            self.add_test_target(fr, bf)

    def add_headers(self):
        for path in pathlib.Path(SRC_ROOT).rglob('*.h'):
            full_file = str(path)
            assert full_file.startswith(SRC_ROOT), "unexpected path" + full_file
            rel_file = full_file[len(SRC_ROOT)+1:]
            self.add_file(str(rel_file), None)

    def sort_groups(self):
        self.group_main.sort()

    def write(self, out):
        out.write("// !$*UTF8*$!\n{\n")
        out.write("\tarchiveVersion = 1;\n\tclasses = {\n\t};\n\tobjectVersion = 77;\n\tobjects = {\n\n")
        for t in self.top_obj:
            t.write(out, 2)
        out.write(f"\t}};\n\trootObject = {self.root_proj.id};\n")
        out.write("}")

    def make_settings(self):
        # go over all build files and find in their arguments a union of all the included folders
        # this is useful for file navigation in xcode to work correctly
        inc_dirs = set()
        common_defines = None
        for f in self.build_files.objs:
            file_defines = set()
            args = f.file.args
            if args is None:
                continue
            for i, arg in enumerate(args):
                if arg == '-I':
                    d = args[i + 1]
                    if d != ".":
                        inc_dirs.add(args[i + 1])
                elif arg == '-D':
                    file_defines.add(args[i+1])
            if common_defines is None:
                common_defines = file_defines
            else:
                common_defines = common_defines.intersection(file_defines)
        inc_str_lst = StrList.list_sort_quote(inc_dirs)
        self.cfg_prod_release.settings.padd("HEADER_SEARCH_PATHS", inc_str_lst)
        self.cfg_prod_release.settings.padd("SYSTEM_HEADER_SEARCH_PATHS", inc_str_lst)
        str_common_defs = StrList.list_sort_quote(common_defines)
        self.cfg_prod_release.settings.padd("GCC_PREPROCESSOR_DEFINITIONS", str_common_defs)

    def write_schemes(self, folder, container_dir):
        for target in self.test_exec:
            path = os.path.join(folder, target.name + ".xcscheme")
            out = open(path, "w")
            exec_path = SRC_ROOT + "/" + TESTS_UNIT_BUILD_PREFIX + target.name
            out.write(f'''<?xml version="1.0" encoding="UTF-8"?>
<Scheme
   LastUpgradeVersion = "1630"
   version = "1.7">
   <BuildAction
      parallelizeBuildables = "YES"
      buildImplicitDependencies = "YES"
      buildArchitectures = "Automatic">
      <BuildActionEntries>
         <BuildActionEntry
            buildForTesting = "NO"
            buildForRunning = "NO"
            buildForProfiling = "YES"
            buildForArchiving = "NO"
            buildForAnalyzing = "NO">
            <BuildableReference
               BuildableIdentifier = "primary"
               BlueprintIdentifier = "{target.id}"
               BuildableName = "{target.name}"
               BlueprintName = "{target.name}"
               ReferencedContainer = "container:{container_dir}">
            </BuildableReference>
         </BuildActionEntry>
      </BuildActionEntries>
   </BuildAction>
   <LaunchAction
      buildConfiguration = "Release"
      selectedDebuggerIdentifier = "Xcode.DebuggerFoundation.Debugger.LLDB"
      selectedLauncherIdentifier = "Xcode.DebuggerFoundation.Launcher.LLDB"
      launchStyle = "0"
      useCustomWorkingDirectory = "NO"
      ignoresPersistentStateOnLaunch = "NO"
      debugDocumentVersioning = "YES"
      debugServiceExtension = "internal"
      allowLocationSimulation = "YES"
      internalIOSLaunchStyle = "3"
      viewDebuggingEnabled = "No">
      <PathRunnable
         runnableDebuggingMode = "0"
         FilePath = "{exec_path}">
      </PathRunnable>
      <MacroExpansion>
         <BuildableReference
            BuildableIdentifier = "primary"
            BlueprintIdentifier = "{target.id}"
            BuildableName = "{target.name}"
            BlueprintName = "{target.name}"
            ReferencedContainer = "container:{container_dir}">
         </BuildableReference>
      </MacroExpansion>
   </LaunchAction>
</Scheme>   
''')
            print(f"Wrote {path}")

def gen_xcode(ccj):
    p = PbxProj()
    p.add_xnu_archive()
    p.add_ccj(ccj)
    p.add_headers()
    p.sort_groups()
    p.make_settings()

    output = os.path.join(SRC_ROOT, "ut_xnu_proj.xcodeproj")
    os.makedirs(output, exist_ok=True)
    proj_path = os.path.join(output, "project.pbxproj")
    p.write(open(proj_path, "w"))
    print(f'wrote file: {proj_path};')

    schemes_dir = output + "/xcshareddata/xcschemes"
    os.makedirs(schemes_dir, exist_ok=True)
    p.write_schemes(schemes_dir, output)
    print(f'wrote schemes to: {schemes_dir}')

# -------------------------------------- VSCode launch targets ----------------------------------------

class TargetsProject:
    def __init__(self):
        self.targets = []

    def add_ccj(self, ccj):
        for entry in ccj:
            src_file, flags = parse_command(entry)
            if src_file.startswith(TESTS_UNIT_PREFIX):
                name = os.path.splitext(src_file[len(TESTS_UNIT_PREFIX):])[0]
                self.targets.append(name)
        self.targets.sort()

class VsCodeLaunchJson(TargetsProject):
    def write(self, f):
        confs = []
        launch = {"version": "0.2.0", "configurations": confs }
        for t in self.targets:
            confs.append({
                "name": t,
                "type": "lldb-dap",
                "request": "launch",
                "program": "${workspaceFolder}/" + TESTS_UNIT_BUILD_PREFIX + t,
                "stopOnEntry": False,
                "cwd": "${workspaceFolder}",
                "args": [],
                "env": []
            })
        json.dump(launch, f, indent=4)


def gen_vscode(ccj):
    p = VsCodeLaunchJson()
    p.add_ccj(ccj)

    output = os.path.join(SRC_ROOT, ".vscode/launch.json")
    os.makedirs(os.path.join(SRC_ROOT, ".vscode"), exist_ok=True)
    if os.path.exists(output):
        print(f"deleting existing {output}")
        os.unlink(output)
    p.write(open(output, "w"))
    print(f"wrote {output}")

# -------------------------------------- CLion targets ----------------------------------------

def find_elem(root, tag, **kvarg):
    assert len(kvarg.items()) == 1
    key, val = list(kvarg.items())[0]
    for child in root:
        assert child.tag == tag, f'unexpected child.tag {child.tag}'
        if child.attrib[key] == val:
            return child
    return None

def get_elem(root, tag, **kvarg):
    child = find_elem(root, tag, **kvarg)
    key, val = list(kvarg.items())[0]
    if child is not None:
        return child, False
    comp = ET.SubElement(root, tag)
    comp.attrib[key] = val
    return comp, True


CLION_TOOLCHAIN_NAME = "System"
class CLionProject(TargetsProject):
    def _get_root(self, path):
        if os.path.exists(path):
            print(f"Parsing existing file {path}")
            root = ET.parse(path).getroot()
            assert root.tag == 'project', f'unexpected root.tag {root.tag}'
        else:
            root = ET.Element('project')
            root.attrib["version"] = "4"
        return root

    def _write(self, root, path):
        tree = ET.ElementTree(root)
        ET.indent(tree, space='  ', level=0)
        tree.write(open(path, "wb"), encoding="utf-8", xml_declaration=True)
        print(f"Wrote {path}")

    def make_custom_targets(self):
        # add a target that uses toolchain "System"
        path = os.path.join(SRC_ROOT, ".idea/customTargets.xml")
        root = self._get_root(path)
        comp, _ = get_elem(root, "component", name="CLionExternalBuildManager")
        # check if we already have the target we need
        for target in comp:
            if target.attrib["defaultType"] == "TOOL":
                target_name = target.attrib["name"]
                if len(target) == 1 and target[0].tag == "configuration":
                    conf = target[0]
                    if conf.attrib["toolchainName"] == CLION_TOOLCHAIN_NAME:
                        conf_name = conf.attrib["name"]
                        print(f"file {path} already has the needed target with name {target_name},{conf_name}")
                        return target_name, conf_name # it already exists, nothing to do
        # add a new target
        target_name = "test_default"
        conf_name = "test_default"

        target = ET.SubElement(comp, "target")
        target.attrib["id"] = str(uuid.uuid1())
        target.attrib["name"] = target_name
        target.attrib["defaultType"] = "TOOL"

        conf = ET.SubElement(target, "configuration")
        conf.attrib["id"] = str(uuid.uuid1())
        conf.attrib["name"] = conf_name
        conf.attrib["toolchainName"] = CLION_TOOLCHAIN_NAME
        print(f"Created target named {target_name}")
        self._write(root, path)
        return target_name, conf_name

    def add_to_workspace(self, target_name, conf_name):
        path = os.path.join(SRC_ROOT, ".idea/workspace.xml")
        root = self._get_root(path)
        comp, _ = get_elem(root, "component", name="RunManager")
        added_anything = False
        for t in self.targets:
            for conf in comp:
                if conf.tag != "configuration":
                    continue
                if "name" in conf.attrib and conf.attrib["name"] == t:  # already has this target
                    print(f"Found existing configuration named '{t}', not adding it")
                    break
            else:
                print(f"Adding configuration for '{t}'")
                proj_name = os.path.basename(SRC_ROOT)
                conf = ET.SubElement(comp, "configuration", name=t,
                                     type="CLionExternalRunConfiguration",
                                     factoryName="Application",
                                     REDIRECT_INPUT="false",
                                     ELEVATE="false",
                                     USE_EXTERNAL_CONSOLE="false",
                                     EMULATE_TERMINAL="false",
                                     PASS_PARENT_ENVS_2="true",
                                     PROJECT_NAME=proj_name,
                                     TARGET_NAME=target_name,
                                     CONFIG_NAME=conf_name,
                                     RUN_PATH=f"$PROJECT_DIR$/{TESTS_UNIT_BUILD_PREFIX}{t}")
                ET.SubElement(conf, "method", v="2")
                added_anything = True
        if added_anything:
            self._write(root, path)


def gen_clion(ccj):
    p = CLionProject()
    p.add_ccj(ccj)

    os.makedirs(os.path.join(SRC_ROOT, ".idea"), exist_ok=True)
    target_name, conf_name = p.make_custom_targets()
    p.add_to_workspace(target_name, conf_name)


def main():
    parser = argparse.ArgumentParser(description='Generate xcode project from compile_commands.json')
    parser.add_argument('mode', help='IDE to generate for', choices=['xcode', 'vscode', 'clion'])
    parser.add_argument('compile_commands', help='Path to compile_commands.json', nargs='*', default=os.path.join(SRC_ROOT, "compile_commands.json"))
    args = parser.parse_args()

    if not os.path.exists(args.compile_commands):
        print(f"Can't find input {args.compile_commands}")
        return 1

    ccj = json.load(open(args.compile_commands, 'r'))

    if args.mode == 'xcode':
        return gen_xcode(ccj)
    elif args.mode == 'vscode':
        return gen_vscode(ccj)
    elif args.mode == 'clion':
        return gen_clion(ccj)


if __name__ == '__main__':
    main()

