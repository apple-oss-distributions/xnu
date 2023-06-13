//
// Make sure that the forward declaration header can be included in C++03.
//

#include <libkern/c++/bounded_ptr_fwd.h>
#include <darwintest.h>

T_GLOBAL_META(
	T_META_NAMESPACE("bounded_ptr_cxx03"),
	T_META_CHECK_LEAKS(false),
	T_META_RUN_CONCURRENTLY(true)
	);

T_DECL(fwd_decl, "bounded_ptr_cxx03.fwd_decl") {
	T_PASS("bounded_ptr_cxx03.fwd_decl compiled successfully");
}
