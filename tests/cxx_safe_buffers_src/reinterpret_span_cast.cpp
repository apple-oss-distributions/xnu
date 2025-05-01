/*
 * Tests for reinterpret_span_cast template in cxx_safe_buffers.h
 */
#include <os/cxx_safe_buffers.h>
#include <vector>
#include <darwintest.h>
#include <darwintest_utils.h>
#define CHECK(...) T_ASSERT_TRUE((__VA_ARGS__), # __VA_ARGS__)

struct A {
	int a[2];
};

struct B {
	int b[3];
};

struct C : B {
	int c[3];
};

struct D {
	std::uint8_t a[2];
};

struct NoPadding {
	char a;
	char b;

	int c;
};

struct WithPaddingMiddle {
	char a;
	int b;

	char c;
};

struct PaddingEnd {
	int a;
	char c;
};


static void
tests()
{
	{
		// convert span<int> to span<byte>
		std::array<int, 3> a1{{1, 2, 3}};
		std::span<int> sp{a1}; // static-extent std::span
		std::span<std::byte> writable_sp = os::reinterpret_span_cast<std::byte>(sp);
		std::span<const std::byte> nonwritable_sp = os::reinterpret_span_cast<const std::byte>(sp);
		CHECK(writable_sp.size() == sp.size_bytes() && nonwritable_sp.size() == sp.size_bytes());
	}

	{
		// convert span<byte> to span<A>
		std::vector<std::byte> vec {std::byte{0}, std::byte{1}, std::byte{2}, std::byte{3},
			                    std::byte{4}, std::byte{5}, std::byte{6}, std::byte{7}};
		std::span<std::byte> sp{vec}; // dynamic-extent std::span
		std::span<A> span_a = os::reinterpret_span_cast<A>(sp);
		CHECK(sp.size() == span_a.size_bytes());
	}

	{
		// convert to a span of unrelated type
		std::array<A, 3> arr;
		std::span<A> span_a = arr;
		std::span<B> span_b = os::reinterpret_span_cast<B>(span_a);
		CHECK(span_b.size() == 2);
	}

	{
		// convert to a span of extended type
		B array[4];
		std::span<B> span_b = array;
		std::span<C> span_c = os::reinterpret_span_cast<C>(span_b);
		CHECK(2 * span_c.size() == span_b.size());
	}

	{
		//convert to a span of base type
		C array[4];
		std::span<C> span_c = array;
		std::span<B> span_b = os::reinterpret_span_cast<B>(span_c);
		CHECK(2 * span_c.size() == span_b.size());
	}
	{
		std::array<std::uint8_t, 12> buf;
		std::span<std::uint8_t> sp = buf;
		std::span<D> span_d = os::reinterpret_span_cast<D>(sp);
		CHECK(span_d.size() == 6);
	}
}

static void
trapping_test()
{
	pid_t pid = fork(); // Fork a new process
	T_ASSERT_POSIX_SUCCESS(pid, "forked %d", pid);

	if (pid == 0) {
		// convert to a span of unrelated type
		A array[2];
		std::span<A> span_a = {array, 2};
		// This invocation will cause a run time trap in child process.
		std::span<B> span_b = os::reinterpret_span_cast<B>(span_a);

		exit(0); // Exit child process
	}

	int status = 0, signal = 0;

	// wait for the child process to finish
	T_ASSERT_FALSE(dt_waitpid(pid, &status, &signal, 0), "wait for child (%d) complete with signal %d", pid, signal);
	// child process must trigger an execution trap
	T_ASSERT_TRUE(WIFSIGNALED(signal), "Child process successfully triggered an execution trap");
}


T_DECL(reinterpret_span_cast, "cxx_safe_buffers.reinterpret_span_cast")
{
	tests();
	trapping_test();
}
