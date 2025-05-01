//
// Tests for
//  __unsafe_forge_span functions
//

#include <span>
#include <vector>
#include <os/cxx_safe_buffers.h>
#include <darwintest.h>

#define CHECK(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

struct S {
	int i;
};

template <typename T>
static void
tests()
{
	{
		T * p = new T[10];
		std::span<T> span = os::span::__unsafe_forge_span(p, 10);

		CHECK(span.data() == p && span.size() == 10);
		delete[] p;
	}
	{
		const T * p = new T[10];
		std::span<const T> span = os::span::__unsafe_forge_span(p, 10);

		CHECK(span.data() == p && span.size() == 10);
		delete[] p;
	}
	{
		std::vector<T> v;
		std::span<T> span = os::span::__unsafe_forge_span(v.begin(), v.end());

		CHECK(span.data() == v.data() && span.size() == 0);
	}
	{
		T * p = new T[10];
		std::span<T> span = os::unsafe_forge_span(p, 10);
		std::span<T, 10> span2 = os::unsafe_forge_span<T, 10>(p);

		CHECK(span.data() == p && span.size() == 10);
		CHECK(span2.data() == p && span2.size() == 10);
		delete[] p;
	}
	{
		std::vector<T> v;
		std::span<T> span = os::unsafe_forge_span(v.begin(), v.end());

		CHECK(span.data() == v.data() && span.size() == 0);
	}
}

T_DECL(unsafe_forge_span, "cxx_safe_buffers.unsafe_forge_span")
{
	tests<S>();
}
