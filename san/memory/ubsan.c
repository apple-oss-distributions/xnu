/*
 * Copyright (c) 2018-2021 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <stdatomic.h>
#include <kern/debug.h>
#include <kern/assert.h>
#include <libkern/libkern.h>
#include "ubsan.h"

static const uint32_t line_acquired = 0x80000000UL;
static const char *get_mismatch_kind(uint8_t kind);

/*
 * A simple JSON serializer. Character quoting is not supported.
 */

static size_t
ubsan_buf_available(const ubsan_buf_t *ub)
{
	assert(ub->ub_buf_size >= ub->ub_written);
	return ub->ub_buf_size - ub->ub_written;
}

static void
ubsan_buf_rewind(ubsan_buf_t *ub, size_t mark)
{
	assert(mark < ub->ub_buf_size);
	ub->ub_written = mark;
	ub->ub_buf[ub->ub_written] = '\0';
}

__printflike(2, 0)
static void
ubsan_json_log_ap(ubsan_buf_t *ub, const char *fmt, va_list ap)
{
	const size_t available = ubsan_buf_available(ub);

	if (available == 0) {
		return;
	}

	int n = vsnprintf(&ub->ub_buf[ub->ub_written], available, fmt, ap);
	assert(n >= 0);

	if (n <= available) {
		ub->ub_written += n;
	} else {
		ub->ub_err = true;
		ub->ub_written = ub->ub_buf_size;
	}
}

__printflike(2, 3)
static void
ubsan_json_log(ubsan_buf_t *ub, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ubsan_json_log_ap(ub, fmt, ap);
	va_end(ap);
}

static bool
ubsan_json_struct_is_empty(const ubsan_buf_t *ub)
{
	if (ub->ub_written == 0) {
		return true;
	}
	char prev_c = ub->ub_buf[ub->ub_written - 1];
	return prev_c == '{' || prev_c == '[';
}

static int64_t
signed_num(size_t bit_width, uint64_t value)
{
	switch (bit_width / 8) {
	case sizeof(int8_t):
		return (int8_t)value;
	case sizeof(int16_t):
		return (int16_t)value;
	case sizeof(int32_t):
		return (int32_t)value;
	case sizeof(int64_t):
		return (int64_t)value;
	default:
		panic("Invalid bit width %lu", bit_width);
	}
}

static void
ubsan_json_struct_begin(ubsan_buf_t *ub, const char *section_name, bool is_array)
{
	if (!ubsan_json_struct_is_empty(ub)) {
		ubsan_json_log(ub, ",");
	}

	if (section_name) {
		assert(section_name[0] != '\0');
		ubsan_json_log(ub, "\"%s\":", section_name);
	}

	ubsan_json_log(ub, is_array ? "[" : "{");

	if (ubsan_buf_available(ub) == 0 || ub->ub_err) {
		ub->ub_err = true;
		return;
	}
	ub->ub_buf_size--; // Reserve for ] or }
}

static void
ubsan_json_struct_end(ubsan_buf_t *ub, bool is_array)
{
	ub->ub_buf_size++; // Reserved for ] or }
	assert(ub->ub_buf[ub->ub_written - 1] != ',');
	ubsan_json_log(ub, is_array ? "]" : "}");
}

static void
ubsan_json_obj_begin(ubsan_buf_t *ub, const char *section_name)
{
	ubsan_json_struct_begin(ub, section_name, false);
}

static void
ubsan_json_obj_end(ubsan_buf_t *ub)
{
	ubsan_json_struct_end(ub, false);
}

static void
ubsan_json_array_begin(ubsan_buf_t *ub, const char *section_name)
{
	ubsan_json_struct_begin(ub, section_name, true);
}

static void
ubsan_json_array_end(ubsan_buf_t *ub)
{
	ubsan_json_struct_end(ub, true);
}

__printflike(4, 0)
static void
ubsan_json_kv_ap(ubsan_buf_t *ub, bool quote, const char *key, const char *fmt, va_list ap)
{
	assert(key && key[0] != '\0');
	assert(fmt && fmt[0] != '\0');

	if (!ubsan_json_struct_is_empty(ub)) {
		ubsan_json_log(ub, ",");
	}

	ubsan_json_log(ub, "\"%s\":", key);

	if (quote) {
		ubsan_json_log(ub, "\"");
		ubsan_json_log_ap(ub, fmt, ap);
		ubsan_json_log(ub, "\"");
	} else {
		ubsan_json_log_ap(ub, fmt, ap);
	}
}

__printflike(4, 5)
static void
ubsan_json_kv(ubsan_buf_t *ub, int quote, const char *key, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ubsan_json_kv_ap(ub, quote, key, fmt, ap);
	va_end(ap);
}

__printflike(3, 4)
static void
ubsan_json_fmt(ubsan_buf_t *ub, const char *key, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	ubsan_json_kv_ap(ub, true, key, fmt, ap);
	va_end(ap);
}

static void
ubsan_json_unum(ubsan_buf_t *ub, const char *key, uint64_t number)
{
	ubsan_json_kv(ub, false, key, "%llu", number);
}

static void
ubsan_json_snum(ubsan_buf_t *ub, const char *key, int64_t number)
{
	ubsan_json_kv(ub, false, key, "%lld", number);
}

static void
ubsan_json_num(ubsan_buf_t *ub, const char *key, struct san_type_desc *std, uint64_t value)
{
	if (std->issigned) {
		ubsan_json_snum(ub, key, signed_num(1 << std->width, value));
	} else {
		ubsan_json_unum(ub, key, value);
	}
}

static void
ubsan_json_bool(ubsan_buf_t *ub, const char *key, bool value)
{
	ubsan_json_kv(ub, false, key, "%s", value ? "true" : "false");
}

static void
ubsan_json_str(ubsan_buf_t *ub, const char *key, const char *string)
{
	const char *str_value = string;
	bool quote = true;

	if (!str_value) {
		str_value = "null";
		quote = false;
	}

	ubsan_json_kv(ub, quote, key, "%s", str_value);
}

static void
ubsan_json_loc(ubsan_buf_t *ub, const char *desc, struct san_src_loc *loc)
{
	ubsan_json_obj_begin(ub, desc);

	ubsan_json_str(ub, "file", loc->filename);
	ubsan_json_unum(ub, "line", loc->line & ~line_acquired);
	ubsan_json_unum(ub, "column", loc->col);

	ubsan_json_obj_end(ub);
}

static void
ubsan_json_type(ubsan_buf_t *ub, const char *section, uint64_t *value, struct san_type_desc *std)
{
	if (section) {
		ubsan_json_obj_begin(ub, section);
	}

	if (value) {
		ubsan_json_num(ub, "value", std, *value);
	}
	ubsan_json_str(ub, "type", std->name);
	ubsan_json_bool(ub, "signed", std->issigned);
	ubsan_json_unum(ub, "width", 1 << std->width);

	if (section) {
		ubsan_json_obj_end(ub);
	}
}

/*
 * return true for the first visit to this loc, false every subsequent time
 */
static bool
ubsan_loc_acquire(struct san_src_loc *loc)
{
	uint32_t line = loc->line;
	if (line & line_acquired) {
		return false;
	}
	uint32_t acq = line | line_acquired;
	return atomic_compare_exchange_strong((_Atomic uint32_t *)&loc->line, &line, acq);
}

static void
format_overflow(ubsan_violation_t *v, ubsan_buf_t *ub)
{
	static const char *const overflow_str[] = {
		NULL,
		"add",
		"sub",
		"mul",
		"divrem",
		"negate",
		NULL
	};
	struct san_type_desc *ty = v->overflow->ty;

	ubsan_json_fmt(ub, "problem", "type overflow");
	ubsan_json_str(ub, "op", overflow_str[v->ubsan_type]);
	ubsan_json_type(ub, "lhs", &v->lhs, ty);
	ubsan_json_unum(ub, "rhs", v->rhs);
}

static void
format_shift(ubsan_violation_t *v, ubsan_buf_t *ub)
{
	ubsan_json_str(ub, "problem", "bad shift");
	ubsan_json_type(ub, "lhs", &v->lhs, v->shift->lhs_t);
	ubsan_json_type(ub, "rhs", &v->rhs, v->shift->rhs_t);
}

static const char *
get_mismatch_kind(uint8_t kind)
{
	static const char *const mismatch_kinds[] = {
		"load of",
		"store to",
		"reference binding to",
		"member access within",
		"member call on",
		"constructor call on",
		"downcast of",
		"downcast of",
		"upcast of",
		"cast to virtual base of",
		"_Nonnull binding to"
	};

	return (kind < (sizeof(mismatch_kinds) / sizeof(mismatch_kinds[0])))
	       ? mismatch_kinds[kind]
	       : "some";
}

static void
format_type_mismatch(ubsan_violation_t *v, ubsan_buf_t *ub)
{
	const char *kind = get_mismatch_kind(v->align->kind);
	const size_t alignment = 1 << v->align->align;
	uintptr_t addr = (uintptr_t)v->lhs;

	ubsan_json_str(ub, "problem", "type mismatch");

	if (!addr) {
		ubsan_json_fmt(ub, "kind", "%s NULL pointer", kind);
		ubsan_json_str(ub, "type", v->align->ty->name);
		return;
	}

	if (alignment && (addr & (alignment - 1))) {
		ubsan_json_fmt(ub, "kind", "%s misaligned", kind);
		ubsan_json_unum(ub, "required", alignment);
	} else {
		ubsan_json_fmt(ub, "kind", "%s insufficient size", kind);
	}
	ubsan_json_type(ub, NULL, (uint64_t *)&addr, v->align->ty);
}

static void
format_oob(ubsan_violation_t *v, ubsan_buf_t *ub)
{
	ubsan_json_str(ub, "problem", "OOB array indexing");
	ubsan_json_type(ub, "array", NULL, v->oob->array_ty);
	ubsan_json_type(ub, "idx", &v->lhs, v->oob->index_ty);
}

static void
format_nullability_arg(ubsan_violation_t *v, ubsan_buf_t *ub)
{
	struct ubsan_nullability_arg_desc *data = v->nonnull_arg;

	ubsan_json_str(ub, "problem", "nullability");
	ubsan_json_snum(ub, "arg", data->arg_index);
	ubsan_json_str(ub, "attr", v->lhs ? "nonnull" : "_Nonnull");
	ubsan_json_loc(ub, "declared", &data->attr_loc);
}

static void
format_nonnull_return(ubsan_violation_t *v, ubsan_buf_t *ub)
{
	ubsan_json_str(ub, "problem", "nonnull return");
	ubsan_json_str(ub, "attr", v->lhs ? "returns_nonnull" : "_Nonnull");
	ubsan_json_loc(ub, "declared", (struct san_src_loc *)v->rhs);
}

static void
format_load_invalid_value(ubsan_violation_t *v, ubsan_buf_t *ub)
{
	ubsan_json_str(ub, "problem", "invalid load");
	ubsan_json_type(ub, NULL, &v->lhs, v->invalid->type);
}

static void
format_missing_return(ubsan_violation_t *v __unused, ubsan_buf_t *ub)
{
	ubsan_json_str(ub, "problem", "missing return");
}

static void
format_float_cast_overflow(ubsan_violation_t *v, ubsan_buf_t *ub)
{
	struct ubsan_float_desc *data = v->flt;
	/*
	 * Cannot print out offending value (e.g. using %A, %f and so on) as kernel logging
	 * does not support float types (yet).
	 */
	ubsan_json_str(ub, "problem", "cast overflow");
	ubsan_json_str(ub, "src", data->type_from->name);
	ubsan_json_str(ub, "to", data->type_to->name);
}

static const char *
get_implicit_conv_type(unsigned char kind)
{
	static const char * const conv_types[] = {
		"integer truncation",
		"unsigned integer truncation",
		"signed integer truncation",
		"integer sign change",
		"signed integer truncation or sign change"
	};
	static const size_t conv_types_cnt = sizeof(conv_types) / sizeof(conv_types[0]);

	return kind < conv_types_cnt ? conv_types[kind] : "unknown implicit integer conversion";
}

static void
format_implicit_conversion(ubsan_violation_t *v, ubsan_buf_t *ub)
{
	struct ubsan_implicit_conv_desc *data = v->implicit;

	ubsan_json_str(ub, "problem", get_implicit_conv_type(data->kind));
	ubsan_json_type(ub, "lhs", &v->lhs, data->type_to);
	ubsan_json_type(ub, "rhs", &v->rhs, data->type_from);
}

static void
format_function_type_mismatch(ubsan_violation_t *v, ubsan_buf_t *ub)
{
	ubsan_json_str(ub, "problem", "bad indirect call");
	ubsan_json_type(ub, NULL, &v->lhs, v->func_mismatch->type);
}

static void
format_vla_bound_not_positive(ubsan_violation_t *v, ubsan_buf_t *ub)
{
	ubsan_json_str(ub, "problem", "non-positive VLA bound");
	ubsan_json_type(ub, NULL, &v->lhs, v->vla_bound->type);
}

static void
format_invalid_builtin(ubsan_violation_t *v, ubsan_buf_t *ub)
{
	ubsan_json_str(ub, "problem", "invalid builtin");
	ubsan_json_str(ub, "op", v->invalid_builtin->kind == 0 ? "ctz()" : "clz()");
}

static void
format_ptr_overflow(ubsan_violation_t *v, ubsan_buf_t *ub)
{
	ubsan_json_str(ub, "problem", "pointer overflow");
	ubsan_json_unum(ub, "lhs", v->lhs);
	ubsan_json_unum(ub, "rhs", v->rhs);
}

static void
format_unreachable(ubsan_buf_t *ub)
{
	ubsan_json_str(ub, "problem", "unreachable");
}

void
ubsan_json_init(ubsan_buf_t *ub, char *buf, size_t bufsize)
{
	assert(bufsize > sizeof("{\"count\":9999,\"violations\":[]}"));
	assert(buf);

	ub->ub_buf = buf;
	ub->ub_buf_size = bufsize;
	ub->ub_written = 0;
	ub->ub_err = false;
}

void
ubsan_json_begin(ubsan_buf_t *ub, size_t nentries)
{
	ub->ub_buf_size--; // for '\0'

	ubsan_json_obj_begin(ub, NULL);
	ubsan_json_unum(ub, "count", nentries);
	ubsan_json_array_begin(ub, "violations");

	assert(!ub->ub_err);
}

size_t
ubsan_json_finish(ubsan_buf_t *ub)
{
	ub->ub_buf_size++; // for '\0'
	ub->ub_err = false;

	ubsan_json_array_end(ub);
	ubsan_json_obj_end(ub);

	assert(!ub->ub_err);
	return ub->ub_written;
}

bool
ubsan_json_format(ubsan_violation_t *v, ubsan_buf_t *ub)
{
	const size_t mark = ub->ub_written;

	ubsan_json_obj_begin(ub, NULL);

	switch (v->ubsan_type) {
	case UBSAN_OVERFLOW_add ... UBSAN_OVERFLOW_negate:
		format_overflow(v, ub);
		break;
	case UBSAN_UNREACHABLE:
		format_unreachable(ub);
		break;
	case UBSAN_SHIFT:
		format_shift(v, ub);
		break;
	case UBSAN_TYPE_MISMATCH:
		format_type_mismatch(v, ub);
		break;
	case UBSAN_POINTER_OVERFLOW:
		format_ptr_overflow(v, ub);
		break;
	case UBSAN_OOB:
		format_oob(v, ub);
		break;
	case UBSAN_NULLABILITY_ARG:
		format_nullability_arg(v, ub);
		break;
	case UBSAN_NULLABILITY_RETURN:
		format_nonnull_return(v, ub);
		break;
	case UBSAN_MISSING_RETURN:
		format_missing_return(v, ub);
		break;
	case UBSAN_FLOAT_CAST_OVERFLOW:
		format_float_cast_overflow(v, ub);
		break;
	case UBSAN_IMPLICIT_CONVERSION:
		format_implicit_conversion(v, ub);
		break;
	case UBSAN_FUNCTION_TYPE_MISMATCH:
		format_function_type_mismatch(v, ub);
		break;
	case UBSAN_VLA_BOUND_NOT_POSITIVE:
		format_vla_bound_not_positive(v, ub);
		break;
	case UBSAN_INVALID_BUILTIN:
		format_invalid_builtin(v, ub);
		break;
	case UBSAN_LOAD_INVALID_VALUE:
		format_load_invalid_value(v, ub);
		break;
	default:
		panic("unknown violation");
	}

	ubsan_json_loc(ub, "source", v->loc);
	ubsan_json_obj_end(ub);

	if (ub->ub_err) {
		ubsan_buf_rewind(ub, mark);
	}
	assert(ub->ub_buf[ub->ub_written] == '\0');

	return !ub->ub_err;
}

enum UBFatality { Fatal, FleshWound };

static void
ubsan_handle(ubsan_violation_t *v, enum UBFatality fatality)
{
	if (!ubsan_loc_acquire(v->loc)) {
		/* violation site already reported */
		return;
	}
	ubsan_log_append(v);

	if (fatality != Fatal) {
		return;
	}

	static char buf[512] = { 0 };
	ubsan_buf_t ubsan_buf;

	ubsan_json_init(&ubsan_buf, buf, sizeof(buf));

	if (ubsan_json_format(v, &ubsan_buf)) {
		printf("UBSan: %s", buf);
	}
}

void
__ubsan_handle_builtin_unreachable(struct ubsan_unreachable_desc *desc)
{
	ubsan_violation_t v = { UBSAN_UNREACHABLE, 0, 0, .unreachable = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_shift_out_of_bounds(struct ubsan_shift_desc *desc, uint64_t lhs, uint64_t rhs)
{
	ubsan_violation_t v = { UBSAN_SHIFT, lhs, rhs, .shift = desc, &desc->loc };
	ubsan_handle(&v, FleshWound);
}

void
__ubsan_handle_shift_out_of_bounds_abort(struct ubsan_shift_desc *desc, uint64_t lhs, uint64_t rhs)
{
	ubsan_violation_t v = { UBSAN_SHIFT, lhs, rhs, .shift = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

#define DEFINE_OVERFLOW(op) \
	void __ubsan_handle_##op##_overflow(struct ubsan_overflow_desc *desc, uint64_t lhs, uint64_t rhs) { \
	        ubsan_violation_t v = { UBSAN_OVERFLOW_##op, lhs, rhs, .overflow = desc, &desc->loc }; \
	        ubsan_handle(&v, FleshWound); \
	} \
	void __ubsan_handle_##op##_overflow_abort(struct ubsan_overflow_desc *desc, uint64_t lhs, uint64_t rhs) { \
	        ubsan_violation_t v = { UBSAN_OVERFLOW_##op, lhs, rhs, .overflow = desc, &desc->loc }; \
	        ubsan_handle(&v, Fatal); \
	}

DEFINE_OVERFLOW(add)
DEFINE_OVERFLOW(sub)
DEFINE_OVERFLOW(mul)
DEFINE_OVERFLOW(divrem)
DEFINE_OVERFLOW(negate)

void
__ubsan_handle_type_mismatch_v1(struct ubsan_align_desc *desc, uint64_t val)
{
	ubsan_violation_t v = { UBSAN_TYPE_MISMATCH, val, 0, .align = desc, &desc->loc };
	ubsan_handle(&v, FleshWound);
}

void
__ubsan_handle_type_mismatch_v1_abort(struct ubsan_align_desc *desc, uint64_t val)
{
	ubsan_violation_t v = { UBSAN_TYPE_MISMATCH, val, 0, .align = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_pointer_overflow(struct ubsan_ptroverflow_desc *desc, uint64_t before, uint64_t after)
{
	ubsan_violation_t v = { UBSAN_POINTER_OVERFLOW, before, after, .ptroverflow = desc, &desc->loc };
	ubsan_handle(&v, FleshWound);
}

void
__ubsan_handle_pointer_overflow_abort(struct ubsan_ptroverflow_desc *desc, uint64_t before, uint64_t after)
{
	ubsan_violation_t v = { UBSAN_POINTER_OVERFLOW, before, after, .ptroverflow = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_out_of_bounds(struct ubsan_oob_desc *desc, uint64_t idx)
{
	ubsan_violation_t v = { UBSAN_OOB, idx, 0, .oob = desc, &desc->loc };
	ubsan_handle(&v, FleshWound);
}

void
__ubsan_handle_out_of_bounds_abort(struct ubsan_oob_desc *desc, uint64_t idx)
{
	ubsan_violation_t v = { UBSAN_OOB, idx, 0, .oob = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_nullability_arg(struct ubsan_nullability_arg_desc *desc)
{
	ubsan_violation_t v = { UBSAN_NULLABILITY_ARG, 0, 0, .nonnull_arg = desc, &desc->loc };
	ubsan_handle(&v, FleshWound);
}

void
__ubsan_handle_nullability_arg_abort(struct ubsan_nullability_arg_desc *desc)
{
	ubsan_violation_t v = { UBSAN_NULLABILITY_ARG, 0, 0, .nonnull_arg = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_nonnull_arg(struct ubsan_nullability_arg_desc *desc)
{
	ubsan_violation_t v = { UBSAN_NULLABILITY_ARG, 1, 0, .nonnull_arg = desc, &desc->loc };
	ubsan_handle(&v, FleshWound);
}

void
__ubsan_handle_nonnull_arg_abort(struct ubsan_nullability_arg_desc *desc)
{
	ubsan_violation_t v = { UBSAN_NULLABILITY_ARG, 1, 0, .nonnull_arg = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_nullability_return_v1(struct ubsan_nullability_ret_desc *desc, uint64_t declaration)
{
	ubsan_violation_t v = { UBSAN_NULLABILITY_RETURN, 0, (uint64_t)&desc->loc, .nonnull_ret = desc, (struct san_src_loc *)declaration };
	ubsan_handle(&v, FleshWound);
}

void
__ubsan_handle_nullability_return_v1_abort(struct ubsan_nullability_ret_desc *desc, uint64_t declaration)
{
	ubsan_violation_t v = { UBSAN_NULLABILITY_RETURN, 0, (uint64_t)&desc->loc, .nonnull_ret = desc, (struct san_src_loc *)declaration };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_nonnull_return_v1(struct ubsan_nullability_ret_desc *desc, uint64_t declaration)
{
	ubsan_violation_t v = { UBSAN_NULLABILITY_RETURN, 1, (uint64_t)&desc->loc, .nonnull_ret = desc, (struct san_src_loc *)declaration };
	ubsan_handle(&v, FleshWound);
}

void
__ubsan_handle_nonnull_return_v1_abort(struct ubsan_nullability_ret_desc *desc, uint64_t declaration)
{
	ubsan_violation_t v = { UBSAN_NULLABILITY_RETURN, 1, (uint64_t)&desc->loc, .nonnull_ret = desc, (struct san_src_loc *)declaration };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_missing_return(struct ubsan_missing_ret_desc *desc)
{
	ubsan_violation_t v = { UBSAN_MISSING_RETURN, 0, 0, .missing_ret = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_missing_return_abort(struct ubsan_missing_ret_desc *desc)
{
	ubsan_violation_t v = { UBSAN_MISSING_RETURN, 0, 0, .missing_ret = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_float_cast_overflow(struct ubsan_float_desc *desc, uint64_t value)
{
	ubsan_violation_t v = { UBSAN_FLOAT_CAST_OVERFLOW, value, 0, .flt = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_float_cast_overflow_abort(struct ubsan_float_desc *desc, uint64_t value)
{
	ubsan_violation_t v = { UBSAN_FLOAT_CAST_OVERFLOW, value, 0, .flt = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_implicit_conversion(struct ubsan_implicit_conv_desc *desc, uint64_t from, uint64_t to)
{
	ubsan_violation_t v = { UBSAN_IMPLICIT_CONVERSION, from, to, .implicit = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_implicit_conversion_abort(struct ubsan_implicit_conv_desc *desc, uint64_t from, uint64_t to)
{
	ubsan_violation_t v = { UBSAN_IMPLICIT_CONVERSION, from, to, .implicit = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_function_type_mismatch(struct ubsan_func_type_mismatch_desc *desc, uint64_t func)
{
	ubsan_violation_t v = { UBSAN_FUNCTION_TYPE_MISMATCH, func, 0, .func_mismatch = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_function_type_mismatch_abort(struct ubsan_func_type_mismatch_desc *desc, uint64_t func)
{
	ubsan_violation_t v = { UBSAN_FUNCTION_TYPE_MISMATCH, func, 0, .func_mismatch = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_vla_bound_not_positive(struct ubsan_vla_bound_desc *desc, uint64_t length)
{
	ubsan_violation_t v = { UBSAN_VLA_BOUND_NOT_POSITIVE, length, 0, .vla_bound = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_vla_bound_not_positive_abort(struct ubsan_vla_bound_desc *desc, uint64_t length)
{
	ubsan_violation_t v = { UBSAN_VLA_BOUND_NOT_POSITIVE, length, 0, .vla_bound = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_invalid_builtin(struct ubsan_invalid_builtin *desc)
{
	ubsan_violation_t v = { UBSAN_INVALID_BUILTIN, 0, 0, .invalid_builtin = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_invalid_builtin_abort(struct ubsan_invalid_builtin *desc)
{
	ubsan_violation_t v = { UBSAN_INVALID_BUILTIN, 0, 0, .invalid_builtin = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_load_invalid_value(struct ubsan_load_invalid_desc *desc, uint64_t invalid_value)
{
	ubsan_violation_t v = { UBSAN_LOAD_INVALID_VALUE, invalid_value, 0, .invalid = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}

void
__ubsan_handle_load_invalid_value_abort(struct ubsan_load_invalid_desc *desc, uint64_t invalid_value)
{
	ubsan_violation_t v = { UBSAN_LOAD_INVALID_VALUE, invalid_value, 0, .invalid = desc, &desc->loc };
	ubsan_handle(&v, Fatal);
}
