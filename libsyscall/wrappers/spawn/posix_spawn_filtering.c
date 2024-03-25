/*
 * Copyright (c) 2021 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#include <spawn_filtering_private.h>

#if POSIX_SPAWN_FILTERING_ENABLED

#include <spawn.h>
#include <spawn_private.h>
#include <sys/spawn_internal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

extern void __posix_spawnattr_init(struct _posix_spawnattr *psattrp);

/*
 * Actual syscall wrappers.
 */
extern int __posix_spawn(pid_t * __restrict, const char * __restrict,
    struct _posix_spawn_args_desc *, char *const argv[__restrict],
    char *const envp[__restrict]);
extern int __execve(const char *fname, char * const *argp, char * const *envp);
extern int __open_nocancel(const char *path, int oflag, mode_t mode);
extern ssize_t __read_nocancel(int, void *, size_t);
extern int __close_nocancel(int fd);

static const char *
_simple_getenv(char * const *envp, const char *var)
{
	size_t var_len = strlen(var);

	for (char * const *p = envp; p && *p; p++) {
		size_t p_len = strlen(*p);

		if (p_len >= var_len && memcmp(*p, var, var_len) == 0 &&
		    (*p)[var_len] == '=') {
			return &(*p)[var_len + 1];
		}
	}

	return NULL;
}

/*
 * Read filtering rules from /usr/local/share/posix_spawn_filtering_rules, and
 * if the target being launched matches, apply changes to the posix_spawn
 * request. Example contents of the file:
 *
 * binary_name:Calculator
 * binary_name:ld
 * path_start:/opt/bin/
 * add_env:DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib
 * binpref:x86_64
 * alt_rosetta:1
 *
 * In this case, if we're launching either Calculator or ld, or anything in
 * /opt/bin (arbitrarily deep), DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib
 * will be added to the environment of the target, it will be launched with
 * x86_64 binpref, and alternative rosetta runtime.
 *
 * Unrecognized lines are silently skipped. All lines must be 1023 characters
 * or shorter.
 *
 * We need to be careful in this codepath (and in all called functions) because
 * we can be called as part of execve() and that's required to be
 * async-signal-safe by POSIX. We're also replacing one syscall with multiple,
 * so we need to watch out to preserve cancellation/EINTR semantics, and avoid
 * changing errno.
 */
static bool
evaluate_rules(const char *rules_file_path, const char *fname, char **envs,
    size_t envs_capacity, char *env_storage, size_t env_storage_capacity,
    cpu_type_t *type, cpu_subtype_t *subtype, uint32_t *psa_options)
{
	int saveerrno = errno;
	int fd = -1;

	/*
	 * Preflight check on rules_file_path to avoid triggering sandbox reports in
	 * case the process doesn't have access. We don't care about TOCTOU here.
	 *
	 * access() does not have a cancellation point, so it's already nocancel.
	 */
	if (access(rules_file_path, R_OK) != 0) {
		errno = saveerrno;
		return false;
	}

	while (1) {
		fd = __open_nocancel(rules_file_path, O_RDONLY | O_CLOEXEC, 0);
		if (fd >= 0) {
			break;
		}
		if (errno == EINTR) {
			continue;
		}
		errno = saveerrno;
		return false;
	}

	const char *fname_basename = fname;
	const char *slash_pos;
	while ((slash_pos = strchr(fname_basename, '/')) != NULL) {
		fname_basename = slash_pos + 1;
	}

	bool fname_matches = false;

	char read_buffer[1024];
	size_t bytes = 0;
	while (1) {
		if (sizeof(read_buffer) - bytes <= 0) {
			break;
		}

		bzero(read_buffer + bytes, sizeof(read_buffer) - bytes);
		size_t read_result = __read_nocancel(fd,
		    read_buffer + bytes, sizeof(read_buffer) - bytes);

		if (read_result == 0) {
			break;
		} else if (read_result < 0) {
			if (errno == EINTR) {
				continue;
			} else {
				break;
			}
		}
		bytes += read_result;

		while (bytes > 0) {
			char *newline_pos = memchr(read_buffer, '\n', bytes);
			if (newline_pos == NULL) {
				break;
			}

			char *line = read_buffer;
			size_t line_length = newline_pos - read_buffer;
			*newline_pos = '\0';

			/* 'line' now has a NUL-terminated string of 1023 chars max */
			if (memcmp(line, "binary_name:", strlen("binary_name:")) == 0) {
				char *binary_name = line + strlen("binary_name:");
				if (strcmp(fname_basename, binary_name) == 0) {
					fname_matches = true;
				}
			} else if (memcmp(line, "path_start:", strlen("path_start:")) == 0) {
				char *path_start = line + strlen("path_start:");
				if (strncmp(fname, path_start, strlen(path_start)) == 0) {
					fname_matches = true;
				}
			} else if (memcmp(line, "add_env:", strlen("add_env:")) == 0) {
				char *add_env = line + strlen("add_env:");
				size_t env_size = strlen(add_env) + 1;
				if (env_storage_capacity >= env_size && envs_capacity > 0) {
					memcpy(env_storage, add_env, env_size);
					envs[0] = env_storage;

					envs += 1;
					envs_capacity -= 1;
					env_storage += env_size;
					env_storage_capacity -= env_size;
				}
			} else if (memcmp(line, "binpref:", strlen("binpref:")) == 0) {
				char *binpref = line + strlen("binpref:");
				if (strcmp(binpref, "x86_64") == 0) {
					*type = CPU_TYPE_X86_64;
					*subtype = CPU_SUBTYPE_ANY;
				}
			} else if (memcmp(line, "alt_rosetta:", strlen("alt_rosetta:")) == 0) {
				char *alt_rosetta = line + strlen("alt_rosetta:");
				if (strcmp(alt_rosetta, "1") == 0) {
					*psa_options |= PSA_OPTION_ALT_ROSETTA;
				}
			} else if (memcmp(line, "has_sec_transition:", strlen("has_sec_transition:")) == 0) {
				char *enable_sec_transitions = line + strlen("has_sec_transition:");
				if (strcmp(enable_sec_transitions, "1") == 0) {
					*psa_options |= PSA_OPTION_USE_SEC_TRANSITION_SHIMS;
				}
			}

			memmove(read_buffer, newline_pos + 1, sizeof(read_buffer) - line_length);
			bytes -= line_length + 1;
		}
	}

	__close_nocancel(fd);
	errno = saveerrno;
	return fname_matches;
}

/*
 * Apply posix_spawn filtering rules, and invoke a possibly modified posix_spawn
 * call. Returns true if the posix_spawn was handled/invoked (and populates the
 * 'ret' outparam in that case), false if the filter does not apply and the
 * caller should proceed to call posix_spawn/exec normally.
 *
 * We need to be careful in this codepath (and in all called functions) because
 * we can be called as part of execve() and that's required to be
 * async-signal-safe by POSIX. We're also replacing one syscall with multiple,
 * so we need to watch out to preserve cancellation/EINTR semantics, and avoid
 * changing errno.
 */
__attribute__((visibility("hidden")))
bool
_posix_spawn_with_filter(pid_t *pid, const char *fname, char * const *argp,
    char * const *envp, struct _posix_spawn_args_desc *adp, int *ret)
{
	/*
	 * For testing, the path to the rules file can be overridden with an env var.
	 * It's hard to get access to 'environ' or '_NSGetEnviron' here so instead
	 * peek into the envp arg of posix_spawn/exec, even though we should really
	 * inspect the parent's env instead. For testing only purposes, it's fine.
	 */
	const char *rules_file_path =
	    _simple_getenv(envp, "POSIX_SPAWN_FILTERING_RULES_PATH")
	    ?: "/usr/local/share/posix_spawn_filtering_rules";

	/*
	 * Stack-allocated storage for extra env vars to add to the posix_spawn call.
	 * 16 env vars, and 1024 bytes total should be enough for everyone.
	 */
  #define MAX_EXTRA_ENVS 16
  #define MAX_ENV_STORAGE_SIZE 1024
	char env_storage[MAX_ENV_STORAGE_SIZE];
	bzero(env_storage, sizeof(env_storage));
	char *envs_to_add[MAX_EXTRA_ENVS];
	bzero(envs_to_add, sizeof(envs_to_add));
	cpu_type_t cputype_binpref = 0;
	cpu_subtype_t cpusubtype_binpref = 0;
	uint32_t psa_options = 0;
	bool should_apply_rules = evaluate_rules(rules_file_path, fname,
	    envs_to_add, sizeof(envs_to_add) / sizeof(envs_to_add[0]),
	    env_storage, sizeof(env_storage),
	    &cputype_binpref, &cpusubtype_binpref,
	    &psa_options);

	if (!should_apply_rules) {
		return false;
	}

	/*
	 * Create stack-allocated private copies of args_desc and spawnattr_t structs
	 * that we can modify.
	 */
	struct _posix_spawn_args_desc new_ad;
	bzero(&new_ad, sizeof(new_ad));
	struct _posix_spawnattr new_attr;
	__posix_spawnattr_init(&new_attr);
	if (adp != NULL) {
		memcpy(&new_ad, adp, sizeof(new_ad));
	}
	if (new_ad.attrp != NULL) {
		memcpy(&new_attr, new_ad.attrp, sizeof(new_attr));
	}
	new_ad.attrp = &new_attr;

	/*
	 * Now 'new_ad' and 'new_attr' are always non-NULL and okay to be modified.
	 */
	if (cputype_binpref != 0) {
		for (int i = 0; i < NBINPREFS; i++) {
			new_attr.psa_binprefs[i] = 0;
			new_attr.psa_subcpuprefs[i] = CPU_SUBTYPE_ANY;
		}
		new_attr.psa_binprefs[0] = cputype_binpref;
		new_attr.psa_subcpuprefs[0] = cpusubtype_binpref;
	}

	if (psa_options != 0) {
		new_attr.psa_options |= psa_options;
	}

	/*
	 * Count old envs.
	 */
	size_t envp_count = 0;
	char *const *ep = envp;
	while (*ep++) {
		envp_count += 1;
	}

	/*
	 * Count envs to add.
	 */
	size_t envs_to_add_count = 0;
	ep = envs_to_add;
	while (envs_to_add_count < MAX_EXTRA_ENVS && *ep++) {
		envs_to_add_count += 1;
	}

	/*
	 * Make enough room for old and new envs plus NULL at the end.
	 */
	char *new_envp[envs_to_add_count + envp_count + 1];

	/*
	 * Prepend the new envs so that they get picked up by Libc's getenv and common
	 * simple_getenv implementations. It's technically undefined what happens if
	 * a name occurs multiple times, but the common implementations pick the first
	 * entry.
	 */
	bzero(&new_envp[0], sizeof(new_envp));
	memcpy(&new_envp[0], &envs_to_add[0], envs_to_add_count * sizeof(void *));
	memcpy(&new_envp[envs_to_add_count], envp, envp_count * sizeof(void *));

	*ret = __posix_spawn(pid, fname, &new_ad, argp, new_envp);
	return true;
}

__attribute__((visibility("hidden")))
int
_execve_with_filter(const char *fname, char * const *argp, char * const *envp)
{
	int ret = 0;

	/*
	 * Rewrite the execve() call into a posix_spawn(SETEXEC) call. We need to be
	 * careful in this codepath (and in all called functions) because execve is
	 * required to be async-signal-safe by POSIX.
	 */
	struct _posix_spawn_args_desc ad;
	bzero(&ad, sizeof(ad));

	struct _posix_spawnattr attr;
	__posix_spawnattr_init(&attr);
	attr.psa_flags |= POSIX_SPAWN_SETEXEC;

	ad.attrp = &attr;
	ad.attr_size = sizeof(struct _posix_spawnattr);

	if (_posix_spawn_with_filter(NULL, fname, argp, envp, &ad, &ret)) {
		if (ret == 0) {
			return 0;
		} else {
			errno = ret;
			return -1;
		}
	}

	ret = __execve(fname, argp, envp);
	return ret;
}

#endif /* POSIX_SPAWN_FILTERING_ENABLED */
