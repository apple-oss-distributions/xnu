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
#include <removefile.h>
#include <unistd.h>
#include <spawn.h>
#include <fcntl.h>
#include <uuid/uuid.h>

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

/* Note: these must be kept in sync with the defs in kalloc.h/zalloc.h */

__options_decl(kalloc_type_flags_t, uint32_t, {
	KT_DEFAULT        = 0x0001,
	KT_PRIV_ACCT      = 0x0002,
	KT_SHARED_ACCT    = 0x0004,
	KT_DATA_ONLY      = 0x0008,
	KT_VM             = 0x0010,
	KT_CHANGED        = 0x0020,
	KT_CHANGED2       = 0x0040,
	KT_PTR_ARRAY      = 0x0080,
	KT_NOSHARED       = 0x2000,
	KT_SLID           = 0x4000,
	KT_PROCESSED      = 0x8000,
	KT_HASH           = 0xffff0000,
});

__options_decl(kalloc_type_version_t, uint16_t, {
	KT_V1             = 0x0001,
});

/* fixme we need to recognize Intel for which this is 20*/
#define KHEAP_NUM_ZONES         22

struct zone_view {
	void *zv_zone;
	void *zv_stats;
	const char *zv_name;
	void *zv_next;
};

struct kalloc_type_view {
	struct zone_view    kt_zv;
	const char         *kt_signature;
	kalloc_type_flags_t kt_flags;
	uint32_t            kt_size;
	struct zone        *kt_zshared;
	struct zone        *kt_zsig;
};

struct kalloc_type_var_view {
	kalloc_type_version_t   kt_version;
	uint16_t                kt_size_hdr;
	/*
	 * Temporary: Needs to be 32bits cause we have many structs that use
	 * IONew/Delete that are larger than 32K.
	 */
	uint32_t                kt_size_type;
	struct zone_stats      *kt_stats;
	const char             *kt_name;
	struct zone_view       *kt_next;
	uint16_t                kt_heap_start;
	uint8_t                 kt_zones[KHEAP_NUM_ZONES];
	const char             *kt_sig_hdr;
	const char             *kt_sig_type;
	kalloc_type_flags_t     kt_flags;
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

	size_t
	elem_size() const
	{
		return sizeof(T);
	}

	size_t
	elem_count() const
	{
		return section.size / elem_size();
	}
};

int
printf_with_indent(const char *indent, const char *format, ...)
{
	int n = 0;

	va_list ap;
	if (*indent) {
		std::cout << indent;
		n += strlen(indent);
	}

	va_start(ap, format);
	n += vprintf(format, ap);
	va_end(ap);
	return n;
}

static inline const char *
decode_string(const macho_section<char> &sec_cstring, const char *string)
{
	/*
	 * Compute the offsets into the __cstring section.
	 * This works for both single kexts (MH_KEXT_BUNDLE) and kernel caches.
	 * For the former, the __cstring section addr is the offset of the section
	 * into the slice. For the latter, the __cstring section addr is the virtual
	 * address of the section, and the fields are pointers into such space.
	 */

	if (string) {
		uintptr_t string_p = reinterpret_cast<uintptr_t>(string);
		uint32_t string_off = (uint32_t)string_p;

		return &sec_cstring.contents[string_off - sec_cstring.section.offset];
	}

	return nullptr;
}

static enum class out_fmt_type {
	SIMPLE,
	JSON,
	STRUCT,
	STATS
} out_fmt = out_fmt_type::SIMPLE;

class image {
	const std::span<uint8_t> slice_contents;
	size_t slice_mh_offs;

	std::optional<macho_section<kalloc_type_view> > sec_types;
	std::optional<macho_section<kalloc_type_var_view> > sec_types_var;
	std::optional<macho_section<char> > sec_cstring;
	uuid_t img_uuid;

	std::set<std::pair<const char *, const char *> > dedup_entries;
	std::set<std::tuple<const char *, const char *, const char *> > dedup_entries_var;
	std::set<const char *> dedup_strings;

	struct {
		size_t uniq_structs = 0;
		size_t uniq_structs_var = 0;
		size_t names_sz = 0;
		size_t sig_sz = 0;
	} stats;

	void
	dump_types(const char *indent)
	{
		const char *sep = "\n";

		if (out_fmt == out_fmt_type::JSON) {
			std::cout << ",\n" << indent << "  \"fixed\": [";
		}

		for (auto &ktv : sec_types->contents) {
			const char *name = decode_string(*sec_cstring, ktv.kt_zv.zv_name);
			const char *sig = decode_string(*sec_cstring, ktv.kt_signature);

			/* Only output the equal entries (same name/signature) once */
			if (!dedup_entries.insert(std::make_tuple(name, sig)).second) {
				continue;
			}

			if (ktv.kt_flags & KT_DATA_ONLY) {
				sig = "data";
			}
			if (dedup_strings.insert(name).second) {
				stats.names_sz += strlen(name) + 1;
			}
			if (dedup_strings.insert(sig).second) {
				stats.sig_sz += strlen(sig) + 1;
			}

			stats.uniq_structs++;
			if (out_fmt != out_fmt_type::STRUCT) {
				name += strlen("site.");
			}

			switch (out_fmt) {
			case out_fmt_type::SIMPLE:
				std::cout << indent << name << " [" << sig << "]\n";
				break;
			case out_fmt_type::JSON:
				std::cout << sep << indent
				          << "    { \"name\": \"" << name << "\", "
				          << "\"size\": " << ktv.kt_size << ", "
				          << "\"sig\": \"" << sig << '"'
				          << " }";
				sep = ",\n";
				break;
			case out_fmt_type::STRUCT: {
				/* Make a copy and fill in the pointers to the cstring section */
				kalloc_type_view printable_view = ktv;
				printable_view.kt_zv.zv_name = name;
				printable_view.kt_signature = sig;
				__builtin_dump_struct(&printable_view, &printf_with_indent, indent);
			} break;
			case out_fmt_type::STATS:
				break;
			}
		}

		if (out_fmt == out_fmt_type::JSON) {
			std::cout << std::endl << indent << "  ]";
		}
	}

	void
	dump_types_var(const char *indent)
	{
		const char *sep = "\n";

		if (out_fmt == out_fmt_type::JSON) {
			std::cout << ",\n" << indent << "  \"var\": [";
		}

		for (auto &ktv : sec_types_var->contents) {
			const char *name = decode_string(*sec_cstring, ktv.kt_name);
			const char *sig_hdr = decode_string(*sec_cstring, ktv.kt_sig_hdr);
			const char *sig_type = decode_string(*sec_cstring, ktv.kt_sig_type);

			/* Only output the equal entries (same name/signature) once */
			if (!dedup_entries_var.insert(std::make_tuple(name, sig_hdr, sig_type)).second) {
				continue;
			}

			if (dedup_strings.insert(name).second) {
				stats.names_sz += strlen(name) + 1;
			}
			if (sig_hdr && dedup_strings.insert(sig_hdr).second) {
				stats.sig_sz += strlen(sig_hdr) + 1;
			}
			if (dedup_strings.insert(sig_type).second) {
				stats.sig_sz += strlen(sig_type) + 1;
			}

			if (ktv.kt_flags & KT_DATA_ONLY) {
				sig_type = "data";
				if (ktv.kt_size_hdr) {
					sig_hdr = "data";
				}
			}
			stats.uniq_structs_var++;
			if (out_fmt != out_fmt_type::STRUCT) {
				name += strlen("site.");
			}

			switch (out_fmt) {
			case out_fmt_type::SIMPLE:
				if (sig_hdr) {
					std::cout << indent << name
					          << " [" << sig_hdr << ", " << sig_type << "]\n";
				} else {
					std::cout << indent << name
					          << " [, " << sig_type << "]\n";
				}
				break;
			case out_fmt_type::JSON:
				std::cout << sep << indent
				          << "    { \"name\": \"" << name << "\", ";
				if (sig_hdr) {
					std::cout << "\"size_hdr\": " << ktv.kt_size_hdr << ", "
					          << "\"sig_hdr\": \"" << sig_hdr << "\", ";
				}
				std::cout << "\"size_type\": " << ktv.kt_size_type << ", "
				          << "\"sig_type\": \"" << sig_type << '"'
				          << " }";
				sep = ",\n";
				break;
			case out_fmt_type::STRUCT: {
				/* Make a copy and fill in the pointers to the cstring section */
				kalloc_type_var_view printable_view = ktv;
				printable_view.kt_name = name;
				printable_view.kt_sig_hdr = sig_hdr;
				printable_view.kt_sig_type = sig_type;
				__builtin_dump_struct(&printable_view, &printf_with_indent, indent);
			} break;
			case out_fmt_type::STATS:
				break;
			}
		}

		if (out_fmt == out_fmt_type::JSON) {
			std::cout << std::endl << indent << "  ]";
		}
	}

	const mach_header_64 *
	mh_hdr() const
	{
		return reinterpret_cast<const mach_header_64 *>(slice_contents.data() + slice_mh_offs);
	}

public:
	image(std::span<uint8_t> contents, size_t mh_offs = 0)
		: slice_contents{contents}, slice_mh_offs{mh_offs}
	{
		auto *hdr = mh_hdr();
		std::span<uint8_t> commands = contents.subspan(mh_offs + sizeof(*hdr));

		assert(hdr->magic == MH_MAGIC_64);

		for (size_t i = 0; i < hdr->ncmds; i++) {
			auto *cmd = reinterpret_cast<const load_command *>(commands.data());

			commands = commands.subspan(cmd->cmdsize);

			switch (cmd->cmd) {
			case LC_SEGMENT_64:
				break;
			case LC_UUID:
				uuid_copy(img_uuid, reinterpret_cast<const uuid_command *>(cmd)->uuid);
				continue;
			default:
				continue;
			}

			auto *seg_cmd = reinterpret_cast<const segment_command_64 *>(cmd);
			const std::span<section_64> sections((section_64 *)(seg_cmd + 1), seg_cmd->nsects);

			for (auto &sec : sections) {
				std::string_view segname(sec.segname);
				std::string_view sectname(sec.sectname);

				if (sectname == "__kalloc_type") {
					assert(!sec_types && "Multiple __kalloc_type sections?");
					sec_types = macho_section<kalloc_type_view>(sec, slice_contents);
					assert(sec.size % sec_types->elem_size() == 0 &&
					    "Check the definition of kalloc_type_view");
				} else if (sectname == "__kalloc_var") {
					assert(!sec_types_var && "Multiple __kalloc_var sections?");
					sec_types_var = macho_section<kalloc_type_var_view>(sec, slice_contents);
					assert(sec.size % sec_types_var->elem_size() == 0 &&
					    "Check the definition of kalloc_type_var_view");
				} else if (segname == "__TEXT" && sectname == "__cstring") {
					assert(!sec_cstring && "Multiple __kalloc_var sections?");
					sec_cstring = macho_section<char>(sec, slice_contents);
				}
			}
		}
	}

	~image() = default;

	std::string
	uuid() const
	{
		uuid_string_t to_str;
		uuid_unparse_upper(img_uuid, to_str);
		return std::string{to_str};
	}

	const char *
	slice() const
	{
		auto *hdr = mh_hdr();
		cpu_type_t cpu;
		cpu_subtype_t sub;

		if (hdr->magic == MH_CIGAM_64) {
			cpu = OSSwapInt32(hdr->cputype);
			sub = OSSwapInt32(hdr->cpusubtype & CPU_SUBTYPE_MASK);
		} else {
			cpu = hdr->cputype;
			sub = hdr->cpusubtype & OSSwapInt32(CPU_SUBTYPE_MASK);
		}

		if (cpu == CPU_TYPE_ARM64) {
			if (sub == CPU_SUBTYPE_ARM64E) {
				return "arm64e";
			}
			return "arm64";
		}

		/* other slices unsupported for now */
		return nullptr;
	}

	void
	dump(const std::string &imgname, const char *indent = "")
	{
		if (out_fmt == out_fmt_type::JSON) {
			std::cout << indent << "{\n"
			          << indent << "  \"image\": \"" << imgname << "\",\n"
			          << indent << "  \"slice\": \"" << slice() << "\",\n"
			          << indent << "  \"uuid\": \"" << uuid() << '"';
		} else {
			std::cout << imgname << " (" << slice() << ", " << uuid() << ")\n";
		}

		if (sec_types) {
			dump_types(indent);
		}

		if (sec_types_var) {
			dump_types_var(indent);
		}

		if (out_fmt == out_fmt_type::JSON) {
			std::cout << std::endl << indent << "}";
		}

		if (out_fmt == out_fmt_type::STATS) {
			if (auto &sec = *sec_types; sec_types) {
				auto ucount = stats.uniq_structs;
				auto usize  = ucount * sec.elem_size();

				std::cout << indent << "__kalloc_type:      " << std::endl;
				std::cout << indent << "  total structs:    " << sec.elem_count() << std::endl;
				std::cout << indent << "  unique structs:   " << ucount << std::endl;
				std::cout << indent << "  total  size:      " << sec.section.size << std::endl;
				std::cout << indent << "  unique size:      " << usize << std::endl;
			}
			if (auto &sec = *sec_types_var; sec_types_var) {
				auto ucount = stats.uniq_structs_var;
				auto usize  = ucount * sec.elem_size();

				std::cout << indent << "__kalloc_var:       " << std::endl;
				std::cout << indent << "  total structs:    " << sec.elem_count() << std::endl;
				std::cout << indent << "  unique structs:   " << ucount << std::endl;
				std::cout << indent << "  total  size:      " << sec.section.size << std::endl;
				std::cout << indent << "  unique size:      " << usize << std::endl;
			}
			std::cout << indent << "names strings:      " << stats.names_sz << std::endl;
			std::cout << indent << "signatures strings: " << stats.sig_sz << std::endl;
		}

		stats = {};
		dedup_entries.clear();
		dedup_entries_var.clear();
		dedup_strings.clear();
	}
};

static int
do_simple_macho(const std::string filename, std::span<uint8_t> contents)
{
	image img{contents};
	img.dump(filename);
	return 0;
}

static int
do_fat_macho(const std::string filename, std::span<uint8_t> contents)
{
	fat_header *fhdr = reinterpret_cast<fat_header *>(contents.data());
	std::span<fat_arch> fat_archs(
		reinterpret_cast<fat_arch *>(&contents[sizeof(fat_header)]),
		OSSwapInt32(fhdr->nfat_arch));
	const char *sep = "\n";

	if (out_fmt == out_fmt_type::JSON) {
		std::cout << "[";
	}

	for (auto &arch : fat_archs) {
		image img{contents.subspan(OSSwapInt32(arch.offset), OSSwapInt32(arch.size))};

		if (out_fmt == out_fmt_type::JSON) {
			std::cout << sep;
		} else {
			std::cout << std::endl;
		}
		img.dump(filename, "  ");
		sep = ",\n";
	}

	if (out_fmt == out_fmt_type::JSON) {
		std::cout << "\n]";
	}

	return 0;
}

static int
do_fileset(std::span<uint8_t> contents)
{
	auto *hdr = reinterpret_cast<const mach_header_64 *>(contents.data());
	std::span<uint8_t> commands = contents.subspan(sizeof(*hdr));
	const char *sep = "\n";

	if (hdr->cputype != CPU_TYPE_ARM64) {
		std::cerr << "unsupported cpu type";
		return 1;
	}

	if (out_fmt == out_fmt_type::JSON) {
		std::cout << "[";
	}

	for (size_t i = 0; i < hdr->ncmds; i++) {
		auto *cmd = reinterpret_cast<const segment_command_64 *>(commands.data());

		commands = commands.subspan(cmd->cmdsize);

		if (cmd->cmd != LC_FILESET_ENTRY) {
			continue;
		}

		auto *fec = reinterpret_cast<const fileset_entry_command *>(cmd);
		const char *name = reinterpret_cast<const char *>(cmd) + fec->entry_id.offset;
		image img{contents, fec->fileoff};

		if (out_fmt == out_fmt_type::JSON) {
			std::cout << sep;
		} else {
			std::cout << std::endl;
		}
		img.dump(name, "  ");
		sep = ",\n";
	}

	if (out_fmt == out_fmt_type::JSON) {
		std::cout << "]";
	}

	return 0;
}

void
read_file(std::filesystem::path &path, std::vector<uint8_t> &contents)
{
	std::ifstream file(path, std::ifstream::binary);
	size_t size(std::filesystem::file_size(path));

	contents.resize(size);
	file.read(reinterpret_cast<char *>(contents.data()), size);
	file.close();
}

enum class file_kind {
	UNKNOWN,
	MACHO,
	FAT_MACHO,
	FILESET,
	IMG4,
};

static file_kind
recognize_file(const std::vector<uint8_t> &contents)
{
	const mach_header_64 *hdr;

	if (contents.size() < sizeof(mach_header_64)) {
		return file_kind::UNKNOWN;
	}

	hdr = reinterpret_cast<const mach_header_64 *>(contents.data());
	if (hdr->magic == MH_MAGIC_64) {
		switch (hdr->filetype) {
		case MH_FILESET:
			return file_kind::FILESET;
		default:
			return file_kind::MACHO;
		}
	}

	if (hdr->magic == FAT_CIGAM) {
		return file_kind::FAT_MACHO;
	}

	if (memcmp("IM4P", contents.data() + 8, 4) == 0) {
		return file_kind::IMG4;
	}

	return file_kind::UNKNOWN;
}

static int
call_cmd_silent(const char *const *args)
{
	posix_spawn_file_actions_t facts;
	extern char **environ;
	pid_t pid;
	int rc;

	posix_spawn_file_actions_init(&facts);
	posix_spawn_file_actions_addopen(&facts,
	    STDIN_FILENO, "/dev/null", O_RDONLY, 0777);
	posix_spawn_file_actions_addopen(&facts,
	    STDOUT_FILENO, "/dev/null", O_WRONLY, 0777);
	posix_spawn_file_actions_addopen(&facts,
	    STDERR_FILENO, "/dev/null", O_WRONLY, 0777);
	rc = posix_spawnp(&pid, args[0], &facts, nullptr,
	    (char *const *)args, environ);
	posix_spawn_file_actions_destroy(&facts);

	if (rc != 0) {
		return 1;
	}

	waitpid(pid, &rc, 0);
	if (!WIFEXITED(rc) || WEXITSTATUS(rc)) {
		return 1;
	}

	return 0;
}

static int
do_file(const std::filesystem::path &path, std::vector<uint8_t> &contents)
{
	int status = 0;

	switch (recognize_file(contents)) {
	case file_kind::MACHO:
		return do_simple_macho(path.filename().string(), contents);
	case file_kind::FAT_MACHO:
		return do_fat_macho(path.filename().string(), contents);
	case file_kind::FILESET:
		return do_fileset(contents);
	case file_kind::IMG4:
		break;
	case file_kind::UNKNOWN:
		std::cerr << "Unsupported file type\n";
		return 1;
	}

	char tmp_tpl[] = "/tmp/kt-dump.XXXXXX";
	char *tmp_dir = mkdtemp(tmp_tpl);

	if (tmp_dir == NULL) {
		std::cerr << "Unable to make temporary directory to unpack img4\n";
		return 1;
	}

	std::filesystem::path compressed_kc{tmp_dir};
	std::filesystem::path uncompressed_kc{tmp_dir};

	compressed_kc /= "compressed.kc";
	uncompressed_kc /= "uncompressed.kc";

	static const char *const img4args[] = {
		"img4utility",
		"--copyBinary",
		"--input",
		path.c_str(),
		"--output",
		compressed_kc.c_str(),
		NULL,
	};

	static const char *const ct_args[] = {
		"compression_tool",
		"-decode",
		"-v",
		"-v",
		"-v",
		"-i",
		compressed_kc.c_str(),
		"-o",
		uncompressed_kc.c_str(),
		NULL,
	};

	if (call_cmd_silent(img4args)) {
		std::cerr << "Unable to unpack img4 image\n";
		status = 1;
	} else if (call_cmd_silent(ct_args)) {
		std::cerr << "Unable to decompress KC\n";
		status = 1;
	} else {
		read_file(uncompressed_kc, contents);
	}

	removefile_state_t s = removefile_state_alloc();
	removefile(tmp_dir, s, REMOVEFILE_RECURSIVE);
	removefile_state_free(s);

	return status ?: do_file(path, contents);
}

int
main(int argc, char const *argv[])
{
	if (argc != 2 && argc != 4) {
		std::cout << "Usage: " << argv[0]
		          << " [-f <simple|json|struct|stats>] <mach-o>\n";
		return 1;
	}

	std::string path_arg;

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
			path_arg = arg;
		}
	}

	if (path_arg.length() == 0) {
		std::cerr << "no file specified\n";
		return 1;
	}

	std::filesystem::path path(path_arg);
	std::vector<uint8_t> contents;

	read_file(path, contents);
	return do_file(path, contents);
}
