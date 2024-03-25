# String handling in xnu

xnu implements most POSIX C string functions, including the inherited subset of
standard C string functions. Unfortunately, poor design choices have made many
of these functions, including the more modern `strl` functions, confusing or
unsafe. In addition, the advent of -fbounds-safety support in xnu is forcing
some string handling practices to be revisited. This document explains the
failings of POSIX C string functions, xnu's `strbuf` functions, and their
intersection with the -fbounds-safety C extension.

## The short-form guidance

* Use `strbuf*` when you have the length for all the strings;
* use `strl*` when you have the length of _one_ string, and the other is
  guaranteed to be NUL-terminated;
* use `str*` when you don't have the length for any of the strings, and they
  are all guaranteed to be NUL-terminated;
* stop using `strn*` functions.

# The problems with string functions

POSIX string handling functions come in many variants:

* `str` functions (strlen, strcat, etc), unsafe for writing;
* `strn` functions (strnlen, strncat, etc), unsafe for writing;
* `strl` functions (strlcpy, strlcat, etc), safe but easily misunderstood.

`str` functions for writing (`strcpy`, `strcat`, etc) are **all** unsafe
because they don't care about the bounds of the output buffer. Most or all of
these functions have been deprecated or outright removed from xnu. You should
never use `str` functions to write to strings. Functions that simply read
strings (`strlen`, `strcmp`, `strchr`, etc) are generally found to be safe
because there is no confusion that their input must be NUL-terminated and there
is no danger of writing out of bounds (out of not writing at all).

`strn` functions for writing (`strncpy`, `strncat`, etc) are **all** unsafe.
`strncpy` doesn't NUL-terminate the output buffer, and `strncat` doesn't accept
a length for the output buffer. **All** new string buffers should include space
for a NUL terminator. `strn` functions for reading (`strncmp`, `strnlen`) are
_generally_ safe, but `strncmp` can cause confusion over which string is bound
by the given size. In extreme cases, this can create information disclosure
bugs or stability issues.

`strl` functions, in POSIX, only come in writing variants, and they always
NUL-terminate their output. This makes the writing part safe. (xnu adds `strl`
comparison functions, which do no writing and are also safe.) However, these
functions assume the output pointer is a buffer and the input is a NUL-
terminated string. Because of coexistence with `strn` functions that make no
such assumption, this mental model isn't entirely adopted by many users. For
instance, the following code is buggy:

```c
char output[4];
char input[8] = "abcdefgh"; /* not NUL-terminated */
strlcpy(output, input, sizeof(output));
```

`strlcpy` returns the length of the input string; in xnu's implementation,
literally by calling `strlen(input)`. Even though only 3 characters are written
to `output` (plus a NUL), `input` is read until reaching a NUL character. This
is always a problem from the perspective of memory disclosures, and in some
cases, it can also lead to stability issues.

# Changes with -fbounds-safety

When enabling -fbounds-safety, character buffers and NUL-terminated strings are
two distinct types, and they do not implicitly convert to each other. This
prevents confusing the two in the way that is problematic with `strlcpy`, for
instance. However, it creates new problems:

* What is the correct way to transform a character buffer into a NUL-terminated
  string?
* When -fbounds-safety flags that the use of a string function was improper,
  what is the solution?

The most common use of character buffers is to build a string, and then this
string is passed without bounds as a NUL-terminated string to downstream users.
-fbounds-safety and XNU enshrine this practice with the following additions:

* `tsnprintf`: like `snprintf`, but it returns a NUL-terminated string;
* `strbuf` functions, explicitly accepting character buffers and a distinct
  count for each:
  * `strbuflen(buffer, length)`: like `strnlen`;
  * `strbufcmp(a, alen, b, len)`: like `strcmp`;
  * `strbufcasecmp(a, alen, b, blen)`: like `strcasecmp`;
  * `strbufcpy(a, alen, b, blen)`: like `strlcpy` but returns `a` as a NUL-
    terminated string;
  * `strbufcat(a, alen, b, blen)`: like `strlcat` but returns `a` as a NUL-
    terminated string;
* `strl` (new) functions, accepting _one_ character buffer of a known size and
  _one_ NUL-terminated string:
  * `strlcmp(a, b, alen)`: like `strcmp`;
  * `strlcasecmp(a, b, alen)`: like `strcasecmp`.

`strbuf` functions additionally all have overloads accepting character arrays
in lieu of a pointer+length pair: `strbuflen(array)`, `strbufcmp(a, b)`,
`strbufcasecmp(a, b)`, `strbufcpy(a, b)`, `strbufcat(a, b)`.

If the destination array of `strbufcpy` or `strbufcat` has a size of 0, they
return NULL without doing anything else. Otherwise, the destination is always
NUL-terminated and returned as a NUL-terminated string pointer.

With -fbounds-safety enabled, the final operation modifying the character array
should always return a NUL-terminated version of it. For instance, this plain C
code:

```c
char thread_name[MAXTHREADNAMESIZE];
(void) snprintf(thread_name, sizeof(thread_name),
        "dlil_input_%s", ifp->if_xname);
thread_set_thread_name(inp->dlth_thread, thread_name);
```

becomes:

```c
char thread_name_buf[MAXTHREADNAMESIZE];
const char *__null_terminated thread_name;
thread_name = tsnprintf(thread_name_buf, sizeof(thread_name_buf),
        "dlil_input_%s", ifp->if_xname);
thread_set_thread_name(inp->dlth_thread, thread_name);
```

Although `tsnprintf` and `strbuf` functions return a `__null_terminated`
pointer to you for convenience, not all use cases are resolved by calling
`tsnprintf` or `strbufcpy` once. As a quick reference, with -fbounds-safety
enabled, you can use `__unsafe_null_terminated_from_indexable(p_start, p_nul)`
to convert a character array to a `__null_terminated` string if you need to
perform more manipulations. (`p_start` is a pointer to the first character, and
`p_nul` is a pointer to the NUL character in that string.) For instance, if you
build a string with successive calls to `scnprintf`, you would use
`__unsafe_null_terminated_from_indexable` at the end of the sequence to get your
NUL-terminated string pointer.

# I have a choice between `strn*`, `strl*`, `strbuf*`. Which one do I use?

You might come across cases where the same function in different families would
seem like they all do the trick. For instance:

```c
struct foo {
    char buf1[10];
    char buf2[16];
};

void bar(struct foo *f) {
    /* how do I test whether buf1 and buf2 contain the same string? */
    if (strcmp(f->buf1, f->buf2) == 0) { /* ... */ }
    if (strncmp(f->buf1, f->buf2, sizeof(f->buf1)) == 0) { /* ... */ }
    if (strlcmp(f->buf1, f->buf2, sizeof(f->buf1)) == 0) { /* ... */ }
    if (strbufcmp(f->buf1, f->buf2) == 0) { /* ... */ }
}
```

Without -fbounds-safety, these all work the same, but when you enable it,
`strbufcmp` could be the only one that builds. If you do not have the privilege
of -fbounds-safety to guide you to the best choice, as a rule of thumb, you
should prefer APIs in the following order:

1. `strbuf*` APIs;
2. `strl*` APIs;
3. `str*` APIs.

That is, to implement `bar`, you have a choice of `strcmp`, `strncmp` and
`strbufcmp`, and you should prefer `strbufcmp`.

`strn` functions are **never** recommended. You should use `strbuflen` over
`strnlen` (they do the same thing, but having a separate `strbuflen` function
makes the guidance to avoid `strn` functions easier), and you should use
`strbufcmp`, `strlcmp` or even `strcmp` over `strncmp` (depending on whether
you know the length of each string, of just one, or of neither).
