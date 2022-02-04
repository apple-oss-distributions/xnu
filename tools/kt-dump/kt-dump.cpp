// clang++ -o kt-dump{,.cpp} -Wall -std=c++20

#include <assert.h>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <optional>
#include <set>
#include <span>
#include <vector>

/*
 * kt-dump.cpp
 *
 * Tool to dump the kalloc type information from a given Mach-O binary.
 * Usage:
 * kt-dump [-f <simple|json|struct|stats>] <mach-o>
 *
 * The tool will scan the given Mach-O to find the __kalloc_type section.
 * It will then walk that section using the kalloc_type_view definition
 * provided below, in order to dump the type names and signatures that
 * have been compiled into the binary.
 *
 * The output "format" can be specified with the -f option. The default
 * format ("simple") will output the type name and the signature,
 * enclosed in square brackets. The "json" format will print a JSON
 * dictionary for each kalloc_type_view entry, including the type name,
 * its size and the signature. The "struct" output format will use
 * __builtin_dump_struct to dump a C-like representation of the view.
 * Finally, if the "stats" output format is chosen, the tool will only
 * show overall information about the __kalloc_type section.
 *
 * The tool supports both MH_KEXT_BUNDLE and kernel cache files. If a
 * FAT Mach-O is provided, it must contain an arm64 slice.
 */

/* Read in_path into out_vec */
static bool read_file(std::string in_path, std::vector<uint8_t> &out_vec);

/* Find a suitable arch span in a FAT file */
static std::optional<std::span<uint8_t> >
find_arm64_slice(const std::span<uint8_t> &contents);

/* Note: these must be kept in sync with the defs in kalloc.h/zalloc.h */
struct zone_view {
	void *zv_zone;
	void *zv_stats;
	const char *zv_name;
	void *zv_next;
};

struct kalloc_type_view {
	struct zone_view kt_zv;
	const char *kt_signature;
	uint32_t kt_flags;
	uint32_t kt_size;
	void *kt_site;
	void *unused;
};

template <typename T> struct macho_section {
	section_64 section;
	std::span<const T> contents;

	macho_section(const section_64 &sec, std::span<uint8_t> data)
		: section(sec),
		contents(reinterpret_cast<T *>(
			    data.subspan(sec.offset, sec.size / sizeof(T)).data()),
		    sec.size / sizeof(T))
	{
	}
};

int
main(int argc, char const *argv[])
{
	if (argc != 2 && argc != 4) {
		std::cout << "Usage: " << argv[0]
		          << " [-f <simple|json|struct|stats>] <mach-o>\n";
		return 1;
	}

	enum class out_fmt_type {
		SIMPLE,
		JSON,
		STRUCT,
		STATS
	} out_fmt = out_fmt_type::SIMPLE;
	std::string arg_str;
	std::vector<uint8_t> file_contents;
	uint32_t file_magic = 0;
	std::span<uint8_t> slice_contents;
	mach_header_64 *hdr = NULL;
	std::optional<macho_section<kalloc_type_view> > sec_types;
	std::optional<macho_section<char> > sec_cstring;
	struct {
		size_t uniq_structs_sz;
		size_t names_sz;
		size_t sig_sz;
	} stats = {};

	/* Parse command line args */
	for (int i = 1; i < argc; i++) {
		std::string arg(argv[i]);
		if (arg == "-f") {
			if (++i == argc) {
				std::cerr << "Option " << arg << " requires an argument\n";
				return 1;
			}
			arg = argv[i];
			if (arg == "simple") {
				out_fmt = out_fmt_type::SIMPLE;
			} else if (arg == "json" || arg == "JSON") {
				out_fmt = out_fmt_type::JSON;
			} else if (arg == "struct") {
				out_fmt = out_fmt_type::STRUCT;
			} else if (arg == "stats") {
				out_fmt = out_fmt_type::STATS;
			} else {
				std::cerr << "Unknown output format: " << arg << std::endl;
				return 1;
			}
		} else {
			/* Read the file specified as a positional arg */
			if (!read_file(arg, file_contents)) {
				std::cerr << "Failed to read file: " << arg << std::endl;
				return 1;
			}
		}
	}

	file_magic = *reinterpret_cast<uint32_t *>(file_contents.data());
	if (file_magic == MH_MAGIC_64) {
		/* Single arch Mach-O file: the slice covers the whole file */
		slice_contents = std::span(file_contents);
	} else if (file_magic == FAT_CIGAM) {
		/* FAT Mach-O: Retrieve the appropriate slice */
		auto arch_span = find_arm64_slice(file_contents);
		if (!arch_span) {
			std::cerr << "Could not find a suitable arch\n";
			return 1;
		}
		slice_contents = arch_span.value();
	} else {
		std::cerr << "Unsupported file magic: 0x" << std::hex << file_magic << "\n";
		return 1;
	}
	assert(slice_contents.size() > sizeof(*hdr));
	hdr = reinterpret_cast<mach_header_64 *>(slice_contents.data());
	if (hdr->magic != MH_MAGIC_64) {
		std::cerr << "Unsupported header magic: 0x" << std::hex << hdr->magic
		          << "\n";
		return 1;
	}

	for (uint32_t cmds_offset = sizeof(*hdr); cmds_offset < hdr->sizeofcmds;) {
		load_command *cmd =
		    reinterpret_cast<load_command *>(&slice_contents[cmds_offset]);
		cmds_offset += cmd->cmdsize;
		/* We only need to process LC_SEGMENT_64 */
		if (cmd->cmd != LC_SEGMENT_64) {
			continue;
		}

		segment_command_64 *seg_cmd = reinterpret_cast<segment_command_64 *>(cmd);
		std::span<section_64> sections(reinterpret_cast<section_64 *>(seg_cmd + 1),
		    seg_cmd->nsects);
		for (auto &sec : sections) {
			std::string segname(sec.segname);
			std::string sectname(sec.sectname);
			if (sectname == "__kalloc_type") {
				assert(!sec_types && "Multiple __kalloc_type sections?");
				assert(sec.size % sizeof(kalloc_type_view) == 0 &&
				    "Check the definition of kalloc_type_view");
				sec_types = macho_section<kalloc_type_view>(sec, slice_contents);
			} else if (segname == "__TEXT" && sectname == "__cstring") {
				sec_cstring = macho_section<char>(sec, slice_contents);
			}
		}
	}

	if (!sec_types) {
		std::cerr << "Could not find __kalloc_type section\n";
		return 1;
	}
	if (!sec_cstring) {
		std::cerr << "Could not find __TEXT,__cstring section\n";
		return 1;
	}

	std::set<std::pair<uint32_t, uint32_t> > dedup_entries;
	std::set<uint32_t> dedup_strings;

	for (auto &ktv : sec_types->contents) {
		uintptr_t name_p = reinterpret_cast<uintptr_t>(ktv.kt_zv.zv_name);
		uintptr_t signature_p = reinterpret_cast<uintptr_t>(ktv.kt_signature);
		/*
		 * Compute the offsets into the __cstring section.
		 * This works for both single kexts (MH_KEXT_BUNDLE) and kernel caches.
		 * For the former, the __cstring section addr is the offset of the section
		 * into the slice. For the latter, the __cstring section addr is the virtual
		 * address of the section, and the fields are pointers into such space.
		 */
		uint32_t name_off = (name_p - sec_cstring->section.addr) & 0xffffffff;
		uint32_t sig_off = (signature_p - sec_cstring->section.addr) & 0xffffffff;

		/* Only output the equal entries (same name/signature) once */
		if (!dedup_entries.insert(std::make_tuple(name_off, sig_off)).second) {
			continue;
		}

		stats.uniq_structs_sz += sizeof(ktv);

		const char *name = &sec_cstring->contents[name_off];
		const char *signature = &sec_cstring->contents[sig_off];
		if (dedup_strings.insert(name_off).second) {
			stats.names_sz += strlen(name) + 1;
		}
		if (dedup_strings.insert(sig_off).second) {
			stats.sig_sz += strlen(signature) + 1;
		}

		switch (out_fmt) {
		case out_fmt_type::SIMPLE:
			std::cout << name << " [" << signature << "]\n";
			break;
		case out_fmt_type::JSON:
			std::cout << "{\"name\":\"" << name << "\","
			          << "\"signature\":\"" << signature << "\","
			          << "\"size\":" << ktv.kt_size << "}\n";
			break;
		case out_fmt_type::STRUCT: {
			/* Make a copy and fill in the pointers to the cstring section */
			kalloc_type_view printable_view = ktv;
			printable_view.kt_zv.zv_name = name;
			printable_view.kt_signature = signature;
			__builtin_dump_struct(&printable_view, &printf);
		} break;
		case out_fmt_type::STATS:
			break;
		}
	}
	if (out_fmt == out_fmt_type::STATS) {
		std::cout << "__kalloc_type:      " << sec_types->section.size << std::endl;
		std::cout << "uniq structs:       " << stats.uniq_structs_sz << std::endl;
		std::cout << "names strings:      " << stats.names_sz << std::endl;
		std::cout << "signatures strings: " << stats.sig_sz << std::endl;
	}

	return 0;
}

static bool
read_file(std::string in_path, std::vector<uint8_t> &out_vec)
{
	std::filesystem::path path(in_path);
	std::ifstream file(path, std::ifstream::binary);
	size_t size(std::filesystem::file_size(path));
	out_vec.resize(size);
	file.read(reinterpret_cast<char *>(out_vec.data()), size);
	file.close();
	return true;
}

static std::optional<std::span<uint8_t> >
find_arm64_slice(const std::span<uint8_t> &contents)
{
	fat_header *fhdr = reinterpret_cast<fat_header *>(contents.data());
	std::span<fat_arch> fat_archs(
		reinterpret_cast<fat_arch *>(&contents[sizeof(fat_header)]),
		OSSwapInt32(fhdr->nfat_arch));
	std::optional<std::span<uint8_t> > chosen_span;
	for (auto &arch : fat_archs) {
		if (OSSwapInt32(arch.cputype) == CPU_TYPE_ARM64) {
			if (OSSwapInt32(arch.cpusubtype) == CPU_SUBTYPE_ARM64E || !chosen_span) {
				chosen_span =
		contents.subspan(OSSwapInt32(arch.offset), OSSwapInt32(arch.size));
			}
		}
	}
	return chosen_span;
}
