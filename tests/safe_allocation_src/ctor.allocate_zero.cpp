//
// Tests for
//  explicit safe_allocation(size_t n, allocate_memory_zero_t);
//

#include <libkern/c++/safe_allocation.h>
#include <darwintest.h>
#include "test_utils.h"

struct T {
	int i;
};

template <typename T>
static void
tests()
{
	{
		test_safe_allocation<T> const array(10, libkern::allocate_memory_zero);
		CHECK(array.data() != nullptr);
		CHECK(array.size() == 10);
		CHECK(array.begin() == array.data());
		CHECK(array.end() == array.data() + 10);

		auto const byteArray = reinterpret_cast<uint8_t const*>(array.data());
		size_t const byteLength = array.size() * sizeof(T);
		for (size_t i = 0; i != byteLength; ++i) {
			CHECK(byteArray[i] == 0);
		}
	}
}

T_DECL(ctor_allocate_zero, "safe_allocation.ctor.allocate_zero") {
	tests<T>();
	tests<T const>();
	tests<int>();
	tests<int const>();
}
