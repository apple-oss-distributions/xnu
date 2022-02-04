#!/usr/bin/sed -nEf

#
# Rules go 3 by 3:
#
# 1. try to rewrite `bitmap_t * __indexable foo`
#    into `bitmap_t *foo` removing all spaces.
#
# 2. try to rewrite `static inline bitmap_t * __indexable`
#    into `static inline bitmap_t *` collapsing redundant spaces.
#
# 3. just eliminate all other kinds of use of the keyword that missed (1) or (2).
#
s/\* *(__bidi_indexable|__indexable|__single|__unsafe_indexable) /*/g
s/ (__bidi_indexable|__indexable|__single|__unsafe_indexable)( |$)/\2/g
s/(__bidi_indexable|__indexable|__single|__unsafe_indexable)//g

#
# Those are approximate because matching parenthesis requires a C parser.
# There's a bound-attributes-check.pl that will make sure we didn't leave any.
#
s/\* *(__counted_by|__sized_by|__ended_by)\([^()]*\)/*/g
s/ (__counted_by|__sized_by|__ended_by)\([^()]*\)( |$)/\2/g
s/(__counted_by|__sized_by|__ended_by)\([^()]*\)//g

/^__ASSUME_PTR_ABI_SINGLE_BEGIN$/d
/^__ASSUME_PTR_ABI_SINGLE_END$/d
s/ __ASSUME_PTR_ABI_SINGLE_BEGIN//g
s/ __ASSUME_PTR_ABI_SINGLE_END$//g
s/__ASSUME_PTR_ABI_SINGLE_BEGIN //g
s/__ASSUME_PTR_ABI_SINGLE_END //g

#
# Finally, print lines we didn't suppress
#
p
