/*
 * Copyright (c) 2015-2020 Apple Inc. All rights reserved.
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

#include <stdbool.h>
#include <firehose/tracepoint_private.h>
#include <kern/assert.h>
#include <kern/counter.h>
#include <kern/locks.h>
#include <pexpert/pexpert.h>
#include <sys/param.h>

#if __has_feature(ptrauth_calls)
#include <mach/vm_param.h>
#include <ptrauth.h>
#endif /* __has_feature(ptrauth_calls) */

#include "log_encode.h"
#include "log_internal.h"
#include "log_mem.h"

#define LOG_FMT_MAX_PRECISION (1024)
#define log_context_cursor(ctx) &(ctx)->ctx_hdr->hdr_data[(ctx)->ctx_content_off]
#define TRACEPOINT_BUF_MAX_SIZE (64)

typedef struct {
	uint8_t *tp_buf;
	size_t  tp_size;
} tracepoint_buf_t;

SCALABLE_COUNTER_DEFINE(oslog_p_fmt_invalid_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_p_fmt_max_args_msgcount);
SCALABLE_COUNTER_DEFINE(oslog_p_truncated_msgcount);

extern boolean_t doprnt_hide_pointers;

static bool
is_digit(char ch)
{
	return (ch >= '0') && (ch <= '9');
}

static bool
is_kernel_pointer(void *arg, size_t arg_len)
{
	if (arg_len < sizeof(void *)) {
		return false;
	}

	unsigned long long value = 0;
	assert(arg_len <= sizeof(value));
	(void) memcpy(&value, arg, arg_len);

#if __has_feature(ptrauth_calls)
	/**
	 * Strip out the pointer authentication code before
	 * checking whether the pointer is a kernel address.
	 */
	value = (unsigned long long)VM_KERNEL_STRIP_PTR(value);
#endif /* __has_feature(ptrauth_calls) */

	return value >= VM_MIN_KERNEL_AND_KEXT_ADDRESS && value <= VM_MAX_KERNEL_ADDRESS;
}

static void
log_context_cursor_advance(os_log_context_t ctx, size_t amount)
{
	ctx->ctx_content_off += amount;
	assert(log_context_cursor(ctx) <= (ctx->ctx_buffer + ctx->ctx_buffer_sz));
}

static bool
log_fits(os_log_context_t ctx, size_t data_size)
{
	return (ctx->ctx_content_off + data_size) <= ctx->ctx_content_sz;
}

static bool
log_fits_cmd(os_log_context_t ctx, size_t data_size)
{
	return log_fits(ctx, sizeof(*ctx->ctx_hdr) + data_size);
}

static void
log_range_update(os_log_fmt_range_t range, uint16_t offset, uint16_t length)
{
	range->offset = offset;
	/*
	 * Truncated flag may have already been set earlier, hence do not
	 * overwrite it blindly.
	 */
	if (length < range->length) {
		range->truncated = true;
	}
	range->length = length;
}

/*
 * Stores a command in the main section. The value itself is wrapped in
 * the os_log_fmt_cmd_t struct.
 */
static void
log_add_cmd(os_log_context_t ctx, os_log_fmt_cmd_type_t type, uint8_t flags,
    void *arg, size_t arg_size)
{
	os_log_fmt_cmd_t cmd;
	const size_t cmd_sz = sizeof(*cmd) + arg_size;

	assert(log_fits_cmd(ctx, cmd_sz));
	assert(arg_size <= UINT8_MAX);

	cmd = (os_log_fmt_cmd_t)log_context_cursor(ctx);
	cmd->cmd_type = type;
	cmd->cmd_flags = flags;
	cmd->cmd_size = (uint8_t)arg_size;
	(void) memcpy(cmd->cmd_data, arg, cmd->cmd_size);

	assert(cmd_sz == sizeof(*cmd) + cmd->cmd_size);
	log_context_cursor_advance(ctx, cmd_sz);
}

/*
 * Collect details about argument which needs to be stored in the pubdata
 * section.
 */
static void
log_collect_public_range_data(os_log_context_t ctx, os_log_fmt_range_t range, void *arg)
{
	ctx->ctx_pubdata[ctx->ctx_pubdata_cnt++] = (char *)arg;
	ctx->ctx_pubdata_sz += range->length;
}

static void
log_add_range_data(os_log_context_t ctx, os_log_fmt_range_t range, void *arg)
{
	assert(log_fits(ctx, range->length));
	(void) memcpy(log_context_cursor(ctx), arg, range->length);
	log_context_cursor_advance(ctx, range->length);
}

static struct os_log_fmt_range_s
log_create_range(os_log_context_t ctx, size_t arg_len)
{
	const size_t final_arg_len = MIN(arg_len, UINT16_MAX);

	return (struct os_log_fmt_range_s) {
		       .offset = ctx->ctx_pubdata_sz,
		       .length = (uint16_t)final_arg_len,
		       .truncated = (final_arg_len < arg_len)
	};
}

static int
log_add_range_arg(os_log_context_t ctx, os_log_fmt_cmd_type_t type, os_log_fmt_cmd_flags_t flags,
    void *arg, size_t arg_len)
{
	struct os_log_fmt_range_s range;

	if (!log_fits_cmd(ctx, sizeof(range))) {
		return ENOMEM;
	}

	range = log_create_range(ctx, arg_len);

	if (flags == OSLF_CMD_FLAG_PUBLIC) {
		if (ctx->ctx_pubdata_cnt == OS_LOG_MAX_PUB_ARGS) {
			return ENOMEM;
		}
		assert(ctx->ctx_pubdata_cnt < OS_LOG_MAX_PUB_ARGS);
		log_collect_public_range_data(ctx, &range, arg);
	}
	log_add_cmd(ctx, type, flags, &range, sizeof(range));
	ctx->ctx_hdr->hdr_cmd_cnt++;

	return 0;
}

/*
 * Adds a scalar argument value to the main section.
 */
static int
log_add_arg(os_log_context_t ctx, os_log_fmt_cmd_type_t type, void *arg, size_t arg_len)
{
	assert(type == OSLF_CMD_TYPE_COUNT || type == OSLF_CMD_TYPE_SCALAR);
	assert(arg_len < UINT16_MAX);

	if (log_fits_cmd(ctx, arg_len)) {
		log_add_cmd(ctx, type, OSLF_CMD_FLAG_PUBLIC, arg, arg_len);
		ctx->ctx_hdr->hdr_cmd_cnt++;
		return 0;
	}

	return ENOMEM;
}

static void
log_encode_public_data(os_log_context_t ctx)
{
	const uint16_t orig_content_off = ctx->ctx_content_off;
	os_log_fmt_hdr_t const hdr = ctx->ctx_hdr;
	os_log_fmt_cmd_t cmd = (os_log_fmt_cmd_t)hdr->hdr_data;

	assert(ctx->ctx_pubdata_cnt <= hdr->hdr_cmd_cnt);

	for (int i = 0, pub_i = 0; i < hdr->hdr_cmd_cnt; i++, cmd = (os_log_fmt_cmd_t)(cmd->cmd_data + cmd->cmd_size)) {
		if (cmd->cmd_type != OSLF_CMD_TYPE_STRING) {
			continue;
		}

		os_log_fmt_range_t const range __attribute__((aligned(8))) = (os_log_fmt_range_t)&cmd->cmd_data;

		// Fix offset and length of the argument data in the hdr.
		log_range_update(range, ctx->ctx_content_off - orig_content_off,
		    MIN(range->length, ctx->ctx_content_sz - ctx->ctx_content_off));

		if (range->truncated) {
			ctx->ctx_truncated = true;
		}

		assert(pub_i < ctx->ctx_pubdata_cnt);
		log_add_range_data(ctx, range, ctx->ctx_pubdata[pub_i++]);
	}
}

static bool
log_expand(os_log_context_t ctx, size_t new_size)
{
	assert(new_size > ctx->ctx_buffer_sz);

	if (!oslog_is_safe()) {
		return false;
	}

	size_t final_size = new_size;

	void *buf = logmem_alloc_locked(ctx->ctx_logmem, &final_size);
	if (!buf) {
		return false;
	}
	assert(final_size >= new_size);

	// address length header + already stored data
	const size_t hdr_size = (uint8_t *)ctx->ctx_hdr - ctx->ctx_buffer;
	const size_t copy_size = hdr_size + sizeof(*ctx->ctx_hdr) + ctx->ctx_content_sz;
	assert(copy_size <= new_size);
	(void) memcpy(buf, ctx->ctx_buffer, copy_size);

	if (ctx->ctx_allocated) {
		logmem_free_locked(ctx->ctx_logmem, ctx->ctx_buffer, ctx->ctx_buffer_sz);
	}

	ctx->ctx_buffer = buf;
	ctx->ctx_buffer_sz = final_size;
	ctx->ctx_content_sz = (uint16_t)(ctx->ctx_buffer_sz - hdr_size - sizeof(*ctx->ctx_hdr));
	ctx->ctx_hdr = (os_log_fmt_hdr_t)&ctx->ctx_buffer[hdr_size];
	ctx->ctx_allocated = true;

	return true;
}

static int
log_encode_fmt_arg(void *arg, size_t arg_len, os_log_fmt_cmd_type_t type, os_log_context_t ctx)
{
	int rc = 0;

	switch (type) {
	case OSLF_CMD_TYPE_COUNT:
	case OSLF_CMD_TYPE_SCALAR:
		// Scrub kernel pointers.
		if (doprnt_hide_pointers && is_kernel_pointer(arg, arg_len)) {
			rc = log_add_range_arg(ctx, type, OSLF_CMD_FLAG_PRIVATE, NULL, 0);
			ctx->ctx_hdr->hdr_flags |= OSLF_HDR_FLAG_HAS_PRIVATE;
		} else {
			rc = log_add_arg(ctx, type, arg, arg_len);
		}
		break;
	case OSLF_CMD_TYPE_STRING:
		rc = log_add_range_arg(ctx, type, OSLF_CMD_FLAG_PUBLIC, arg, arg_len);
		ctx->ctx_hdr->hdr_flags |= OSLF_HDR_FLAG_HAS_NON_SCALAR;
		break;
	default:
		panic("Unsupported log value type");
	}

	return rc;
}

static int
log_encode_fmt(os_log_context_t ctx, const char *format, va_list args)
{
	const char *position = format;

	while ((position = strchr(position, '%'))) {
		position++; // Look at character(s) after %.

		int type = OST_INT;
		boolean_t has_precision = false;
		int precision = 0;

		for (bool done = false; !done; position++) {
			union os_log_fmt_types_u value;
			size_t str_length;
			int err = 0;

			switch (position[0]) {
			case '%':
				// %% prints % character
				done = true;
				break;

			/* type of types or other */
			case 'l': // longer
				type++;
				break;

			case 'h': // shorter
				type--;
				break;

			case 'z':
				type = OST_SIZE;
				break;

			case 'j':
				type = OST_INTMAX;
				break;

			case 't':
				type = OST_PTRDIFF;
				break;

			case 'q':
				type = OST_LONGLONG;
				break;

			case '.': // precision
				if (position[1] == '*') {
					// Dynamic precision, argument holds actual value.
					precision = va_arg(args, int);
					position++;
				} else {
					// Static precision, the value follows in the fmt.
					precision = 0;
					while (is_digit(position[1])) {
						if (precision < LOG_FMT_MAX_PRECISION) {
							precision = 10 * precision + (position[1] - '0');
						}
						position++;
					}
					precision = MIN(precision, LOG_FMT_MAX_PRECISION);
				}
				err = log_encode_fmt_arg(&precision, sizeof(precision), OSLF_CMD_TYPE_COUNT, ctx);
				// A negative precision is treated as though it were missing.
				if (precision >= 0) {
					has_precision = true;
				}
				break;

			case '-': // left-align
			case '+': // force sign
			case ' ': // prefix non-negative with space
			case '#': // alternate
			case '\'': // group by thousands
				break;

			/* fixed types */
			case 'd': // integer
			case 'i': // integer
			case 'o': // octal
			case 'u': // unsigned
			case 'x': // hex
			case 'X': // upper-hex
				switch (type) {
				case OST_CHAR:
					value.ch = (char) va_arg(args, int);
					err = log_encode_fmt_arg(&value.ch, sizeof(value.ch), OSLF_CMD_TYPE_SCALAR, ctx);
					break;

				case OST_SHORT:
					value.s = (short) va_arg(args, int);
					err = log_encode_fmt_arg(&value.s, sizeof(value.s), OSLF_CMD_TYPE_SCALAR, ctx);
					break;

				case OST_INT:
					value.i = va_arg(args, int);
					err = log_encode_fmt_arg(&value.i, sizeof(value.i), OSLF_CMD_TYPE_SCALAR, ctx);
					break;

				case OST_LONG:
					value.l = va_arg(args, long);
					err = log_encode_fmt_arg(&value.l, sizeof(value.l), OSLF_CMD_TYPE_SCALAR, ctx);
					break;

				case OST_LONGLONG:
					value.ll = va_arg(args, long long);
					err = log_encode_fmt_arg(&value.ll, sizeof(value.ll), OSLF_CMD_TYPE_SCALAR, ctx);
					break;

				case OST_SIZE:
					value.z = va_arg(args, size_t);
					err = log_encode_fmt_arg(&value.z, sizeof(value.z), OSLF_CMD_TYPE_SCALAR, ctx);
					break;

				case OST_INTMAX:
					value.im = va_arg(args, intmax_t);
					err = log_encode_fmt_arg(&value.im, sizeof(value.im), OSLF_CMD_TYPE_SCALAR, ctx);
					break;

				case OST_PTRDIFF:
					value.pd = va_arg(args, ptrdiff_t);
					err = log_encode_fmt_arg(&value.pd, sizeof(value.pd), OSLF_CMD_TYPE_SCALAR, ctx);
					break;

				default:
					return EINVAL;
				}
				done = true;
				break;

			case 'p': // pointer
				value.p = va_arg(args, void *);
				err = log_encode_fmt_arg(&value.p, sizeof(value.p), OSLF_CMD_TYPE_SCALAR, ctx);
				done = true;
				break;

			case 'c': // char
				value.ch = (char) va_arg(args, int);
				err = log_encode_fmt_arg(&value.ch, sizeof(value.ch), OSLF_CMD_TYPE_SCALAR, ctx);
				done = true;
				break;

			case 's': // string
				value.pch = va_arg(args, char *);
				if (!value.pch) {
					str_length = 0;
				} else if (has_precision) {
					assert(precision >= 0);
					str_length = strnlen(value.pch, precision);
				} else {
					str_length = strlen(value.pch) + 1;
				}
				err = log_encode_fmt_arg(value.pch, str_length, OSLF_CMD_TYPE_STRING, ctx);
				done = true;
				break;

			case 'm':
				value.i = 0; // Does %m make sense in the kernel?
				err = log_encode_fmt_arg(&value.i, sizeof(value.i), OSLF_CMD_TYPE_SCALAR, ctx);
				done = true;
				break;

			case '0' ... '9':
				// Skipping field width, libtrace takes care of it.
				break;

			default:
				return EINVAL;
			}

			if (slowpath(err)) {
				return err;
			}
		}
	}

	return 0;
}

OS_ALWAYS_INLINE
static inline void
tracepoint_buf_add(tracepoint_buf_t *tp, const void *data, size_t size)
{
	assert((tp->tp_size + size) <= TRACEPOINT_BUF_MAX_SIZE);
	memcpy(&tp->tp_buf[tp->tp_size], data, size);
	tp->tp_size += size;
}

static void
tracepoint_buf_location(tracepoint_buf_t *tpb, uintptr_t loc, size_t loc_size)
{
	if (loc_size == sizeof(uintptr_t)) {
#if __LP64__
		loc_size = 6; // 48 bits are enough
#endif
		tracepoint_buf_add(tpb, (uintptr_t[]){ loc }, loc_size);
	} else {
		assert(loc_size == sizeof(uint32_t));
		tracepoint_buf_add(tpb, (uint32_t[]){ (uint32_t)loc }, loc_size);
	}
}

static void
os_log_context_prepare_header(os_log_context_t ctx, size_t hdr_size)
{
	assert(hdr_size > 0 && hdr_size <= TRACEPOINT_BUF_MAX_SIZE);
	ctx->ctx_hdr = (os_log_fmt_hdr_t)&ctx->ctx_buffer[hdr_size];
	bzero(ctx->ctx_hdr, sizeof(*ctx->ctx_hdr));
	ctx->ctx_content_sz = (uint16_t)(ctx->ctx_buffer_sz - hdr_size - sizeof(*ctx->ctx_hdr));
}

/*
 * Encodes argument (meta)data into a format consumed by libtrace. Stores
 * metadada for all arguments first. Metadata also include scalar argument
 * values. Second step saves data which are encoded separately from respective
 * metadata (like strings).
 */
bool
os_log_context_encode(os_log_context_t ctx, const char *fmt, va_list args,
    uintptr_t loc, size_t loc_size, uint16_t subsystem_id)
{
	tracepoint_buf_t tpb = {
		.tp_buf     = ctx->ctx_buffer,
		.tp_size    = 0
	};

	tracepoint_buf_location(&tpb, loc, loc_size);
	if (os_log_subsystem_id_valid(subsystem_id)) {
		tracepoint_buf_add(&tpb, &subsystem_id, sizeof(subsystem_id));
	}
	os_log_context_prepare_header(ctx, tpb.tp_size);

	va_list args_copy;
	va_copy(args_copy, args);

	int rc = log_encode_fmt(ctx, fmt, args);

	va_end(args_copy);

	switch (rc) {
	case EINVAL:
		// Bogus/Unsupported fmt string
		counter_inc(&oslog_p_fmt_invalid_msgcount);
		return false;
	case ENOMEM:
		/*
		 * The fmt contains unreasonable number of arguments (> 32) and
		 * we ran out of space. We could call log_expand()
		 * here and retry. However, using such formatting strings rather
		 * seem like a misuse of the logging system, hence error.
		 */
		counter_inc(&oslog_p_fmt_max_args_msgcount);
		return false;
	case 0:
		break;
	default:
		panic("unhandled return value");
	}

	if (ctx->ctx_pubdata_sz == 0) {
		goto finish;
	}

	/*
	 * Logmem may not have been set up yet when logging very early during
	 * the boot. Be sure to check its state.
	 */
	if (!log_fits(ctx, ctx->ctx_pubdata_sz) && logmem_ready(ctx->ctx_logmem)) {
		size_t space_needed = log_context_cursor(ctx) + ctx->ctx_pubdata_sz - ctx->ctx_buffer;
		space_needed = MIN(space_needed, logmem_max_size(ctx->ctx_logmem));
		(void) log_expand(ctx, space_needed);
	}

	log_encode_public_data(ctx);

	if (ctx->ctx_truncated) {
		counter_inc(&oslog_p_truncated_msgcount);
	}
finish:
	ctx->ctx_content_sz = (uint16_t)(log_context_cursor(ctx) - ctx->ctx_buffer);
	ctx->ctx_content_off = 0;
	return true;
}

void
os_log_context_init(os_log_context_t ctx, logmem_t *logmem, uint8_t *buffer, size_t buffer_sz)
{
	assert(logmem);
	assert(buffer);
	assert(buffer_sz > 0);

	bzero(ctx, sizeof(*ctx));
	ctx->ctx_logmem = logmem;
	ctx->ctx_buffer = buffer;
	ctx->ctx_buffer_sz = buffer_sz;
}

void
os_log_context_free(os_log_context_t ctx)
{
	if (ctx->ctx_allocated) {
		logmem_free_locked(ctx->ctx_logmem, ctx->ctx_buffer, ctx->ctx_buffer_sz);
	}
}
