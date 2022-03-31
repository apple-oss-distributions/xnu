#ifndef _OS_CPP_UTIL_H
#define _OS_CPP_UTIL_H

#include <sys/cdefs.h>
#include <sys/_types/_size_t.h>

#if __has_feature(cxx_nullptr) && __has_feature(cxx_decltype)
# define OS_HAS_NULLPTR 1
#endif

#if __has_feature(cxx_rvalue_references) || __has_extension(cxx_rvalue_references)
# define OS_HAS_RVALUE_REFERENCES 1
#endif

void* operator new(size_t, void*) noexcept;

namespace os {
#if OS_HAS_NULLPTR
typedef decltype(nullptr) nullptr_t;
#endif

/*
 * Reference removal
 */

template <class _T> struct remove_reference       {typedef _T type;};
template <class _T> struct remove_reference<_T&>  {typedef _T type;};
template <class _T> struct remove_reference<_T &&> {typedef _T type;};
template <class _T> using remove_reference_t = typename remove_reference<_T>::type;

/*
 * Pointer removal
 */

template <class _T> struct remove_pointer                     {typedef _T type;};
template <class _T> struct remove_pointer<_T*>                {typedef _T type;};
template <class _T> struct remove_pointer<_T* const>          {typedef _T type;};
template <class _T> struct remove_pointer<_T* volatile>       {typedef _T type;};
template <class _T> struct remove_pointer<_T* const volatile> {typedef _T type;};
template <class _T> using remove_pointer_t = typename remove_pointer<_T>::type;

/*
 * Const removal
 */

template <class _T> struct remove_const           {typedef _T type;};
template <class _T> struct remove_const<const _T> {typedef _T type;};
template <class _T> using remove_const_t = typename remove_const<_T>::type;

/*
 * Volatile removal
 */

template <class _T> struct remove_volatile              {typedef _T type;};
template <class _T> struct remove_volatile<volatile _T> {typedef _T type;};
template <class _T> using remove_volatile_t = typename remove_volatile<_T>::type;

/*
 * Extent removal
 */

template<class _T> struct remove_extent { typedef _T type; };
template<class _T> struct remove_extent<_T[]> { typedef _T type; };
template<class _T, size_t N> struct remove_extent<_T[N]> { typedef _T type; };
template <class _T> using remove_extent_t = typename remove_extent<_T>::type;


template <class T> struct is_lvalue_reference { static constexpr bool value = false; };
template <class T> struct is_lvalue_reference<T&> { static constexpr bool value = true; };

/*
 * is_same
 */

template<class T, class U> struct is_same { static constexpr bool value = false; };
template<class T> struct is_same<T, T> { static constexpr bool value = true; };

/*
 * Move
 */

template <class _T>
inline typename remove_reference<_T>::type &&
move(_T && _t)
{
	typedef typename os::remove_reference<_T>::type _U;
	return static_cast<_U &&>(_t);
}

template <class T>
T*
move(T* first, T* last, T* d_first)
{
	for (; first != last; ++d_first, (void)++first) {
		*d_first = os::move(*first);
	}
	return d_first;
}

template <class T>
constexpr T && forward(os::remove_reference_t<T>&t) noexcept {
	return static_cast<T &&>(t);
}

template <class T>
constexpr T && forward(os::remove_reference_t<T>&& t) noexcept {
	static_assert(!os::is_lvalue_reference<T>::value,
	    "can not forward an rvalue as an lvalue");
	return static_cast<T &&>(t);
}

// Moves [first, last) into the range ending at d_last,
// proceeding backwards (from last to first)
// UB if d_last is within (first, last]
template <class T>
T*
move_backward(T* first, T* last, T* d_last)
{
	while (first != last) {
		*(--d_last) = os::move(*(--last));
	}
	return d_last;
}

template <class T>
T*
uninitialized_move(T* first, T* last, T* d_first)
{
	for (; first != last; ++d_first, (void) ++first) {
		::new (static_cast<void*>(d_first)) T(os::move(*first));
	}
	return first;
}

template <class T>
void
destroy(T* first, T* last)
{
	for (; first != last; ++first) {
		first->~T();
	}
}

template <class T>
void
uninitialized_value_construct(T* first, T* last)
{
	for (; first != last; ++first) {
		::new (static_cast<void*>(first)) T();
	}
}
}

#endif /* _OS_CPP_UTIL_H */
