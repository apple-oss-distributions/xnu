// To apply, at the top of xnu.git:
// $ spatch --max-width=80 --use-gitgrep --in-place --include-headers --sp-file tools/cocci/zalloc.cocci -dir .
//
// This might need to be run several times

@ using "zalloc.iso" @
expression D, E, F, G;
type T;
identifier V;
@@
(
- kheap_alloc(KHEAP_DATA_BUFFERS, E, F)
+ kalloc_data(E, F)
|
- (T)kheap_alloc(KHEAP_DATA_BUFFERS, E, F)
+ (T)kalloc_data(E, F)
|
- kheap_alloc_tag(KHEAP_DATA_BUFFERS, E, F, G)
+ kalloc_data_tag(E, F, G)
|
- kheap_free(KHEAP_DATA_BUFFERS, E, F)
+ kfree_data(E, F)
|
- kheap_free_addr(KHEAP_DATA_BUFFERS, E)
+ kfree_data_addr(E)
)

// vim:ft=diff:
