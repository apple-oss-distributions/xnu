#!/usr/bin/perl
#
# Used to validate that strip-bound-attributes.sed hasn't left
# any bound-checks markings behind.
#

while (<>) {
    exit 1 if /__bidi_indexable/;
    exit 1 if /__indexable/;
    exit 1 if /__single/;
    exit 1 if /__unsafe_indexable/;
    exit 1 if /__counted_by/;
    exit 1 if /__sized_by/;
    exit 1 if /__ended_by/;
    exit 1 if /__unsafe_forge_bidi_indexable/;
    exit 1 if /__unsafe_forge_single/;
    exit 1 if /__ASSUME_PTR_ABI_SINGLE_BEGIN/;
    exit 1 if /__ASSUME_PTR_ABI_SINGLE_END/;
    exit 1 if /XNU_BOUND_CHECKS/;
}

exit 0;
