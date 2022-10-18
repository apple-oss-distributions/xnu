#ifndef _CHUNKLIST_H
#define _CHUNKLIST_H

#include <libkern/crypto/sha2.h>

/*
 * Chunklist file format
 */
#define CHUNKLIST_MAGIC                 0x4C4B4E43
#define CHUNKLIST_FILE_VERSION_10       1
#define CHUNKLIST_CHUNK_METHOD_10       1
#define CHUNKLIST_SIGNATURE_METHOD_REV1 1
#define CHUNKLIST_REV1_SIG_LEN          256
#define CHUNKLIST_PUBKEY_LEN            (2048/8)
#define CHUNKLIST_SIGNATURE_LEN         (2048/8)

struct chunklist_hdr {
	uint32_t cl_magic;
	uint32_t cl_header_size;
	uint8_t  cl_file_ver;
	uint8_t  cl_chunk_method;
	uint8_t  cl_sig_method;
	uint8_t  __unused1;
	uint64_t cl_chunk_count;
	uint64_t cl_chunk_offset;
	uint64_t cl_sig_offset;
} __attribute__((packed));

struct chunklist_chunk {
	uint32_t chunk_size;
	uint8_t  chunk_sha256[SHA256_DIGEST_LENGTH];
} __attribute__((packed));

struct chunklist_pubkey {
	const boolean_t is_production;
	const uint8_t key[CHUNKLIST_PUBKEY_LEN];
};

int authenticate_root_with_chunklist(const char *rootdmg_path, boolean_t *out_enforced);
int authenticate_root_version_check(void);
int authenticate_bootkc_uuid(void);
int authenticate_libkern_uuid(void);
#endif /* _CHUNKLIST_H */
