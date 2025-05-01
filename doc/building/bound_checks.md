# Bounds checking

The goal of -fbounds-safety is to prevent buffer overflows from escalating into
security issues. However, that escalation is prevented by crashing the program,
which, in the case of the kernel, means panicking the system. While panicking
is a lesser evil than allowing an attacker to compromise the system, it is
still a drastic measure.

xnu's build system supports several options controlling the enforcement of
bounds checks via clang's -fbounds-safety extension. This document describes a
process that implements our best practices to adopt -fbounds-safety in existing
code.

# Controllable aspects of -fbounds-safety

-fbounds-safety is enabled at a file granularity in the xnu build system.
Whether a given file builds with -fbounds-safety is controlled by the build
system's configuration `files` under each kernel component. For instance, one of
the first components in xnu to enable -fbounds-safety is bsd/net: as a result,
bsd/conf/files is where build system modifications were made.

There are five options that control aspects related to -fbounds-safety:

* whether -fbounds-safety is enabled at all;
* when it is disabled, whether we should allow `__indexable` and
  `__bidi_indexable` in source (or emit a compile-time error if they're used);
* when it is enabled, whether a trap should be a panic, or whether it should
  only report a telemetry event;
* when it is set to panic, whether we should optimize for code size at the
  expense of the quality of debug information.
* which set of new bounds checks (`-fbounds-safety-bringup-missing-checks`) are enabled

## Code size tradeoffs

We can ask clang to give us one trap instruction per function, which can have
significant positive effects on code size and performance. However, every bounds
check in that function will jump to that trap instruction when they fail. Debug
information on the trap instruction will be meaningless and the debugger won't
know where we came from. This manifests as a "function(), file.c:0" call stack
entry in the backtrace.

On the other hand, we can ask clang to give us one trap instruction per bounds
check. In that configuration, we get arguably bad codegen, but the backtrace is
always immediately readable and the trap location shows correctly in the
debugger.

To debug a panic in a build optimizing for code size, we can read disassembly
and make inferences based on register values. For instance, if we look at one
bounds check failing if register `x8` is greater than register `x9`, and in the
context of our panic we know that `x8` is 0x0 and `x9` is 0x1000, then we know
we can't possibly have failed because of that bounds check. There are scripts
to automate this reasoning–ask the -fbounds-safety DRIs for help if you run into
this situation.

## Bounds checking adoption level options

* (nothing): -fbounds-safety is disabled; it is an error to use `__indexable`
  and `__bidi_indexable` in source.
* `bound-checks-pending`: -fbounds-safety is disabled, but `__indexable` and
  `__bidi_indexable` are defined to nothing instead of causing compile-time
  errors.
* `bound-checks`: -fbounds-safety is enabled; failing bounds checks panic;
  optimize for code size at the detriment of debuggability.
* `bound-checks-debug`: -fbounds-safety is enabled; failing bounds checks panic;
  optimize for debug information at the detriment of efficient code.
* `bound-checks-soft`: -fbounds-safety is disabled for RELEASE kernels;
  for all other kernel configurations failing bounds checks generate a telemetry event
  instead of panicking; optimize for debug information at the detriment of efficient code.
* `bound-checks-seed`: -fbounds-safety is enabled. For RELEASE kernels, failing checks
  generate a telemetry event instead of panicking; for all other kernel configurations
  failing bound checks panic.

These options are mutually exclusive.

### Bounds checking adoption level modifier options

In addition to the bounds checking adoption level options (e.g.
`bounds-checks-debug`), modifier options can be added to the selected adoption
level. Note it is invalid to use these options without first specifying a
`bound-check*` level option (i.e. any level except "nothing").
Furthermore, the bound-check level option must appear before any modifiers (see examples below).

* `bound-checks-new-checks`: If building with `-fbounds-safety` this causes
  `-fbounds-safety-bringup-missing-checks` to be added to the compiler flags.

Examples:

```
# ok: `-fbounds-safety -fbounds-safety-bringup-missing-checks` passed to compiler
test.c optional bounds-checks bound-checks-new-checks

# invalid: An adoption level that's not "nothing" needs to be specified
test.c optional bound-checks-new-checks

# invalid: `bounds-checks` needs to be specified first
test.c optional bound-checks-new-checks bounds-checks
```

# The process of enabling bound-checks

`bound-checks` is the final, desirable bounds checking adoption level
configuration option. We do not enable `bound-checks` lightly, as it can
introduce new reasons that xnu panics. We have found that the following process
consistently helps land code changes that stick, and help reduce the likelihood
of introducing problems that turn into bad kernels.

## Step 1: adopt -fbounds-safety at desk

When enabling -fbounds-safety, clang generates new diagnostics that ensure at
compile-time that bounds could be known at runtime (if necessary) for all 
pointers, and new diagnostics for when a bounds check is likely (or guaranteed)
to fail at runtime. The first step to adopting -fbounds-safety is making code
changes to xnu such that it builds without any diagnostics, and testing at desk
that your changes did not impact kernel functionality.

For this step, you use `bound-checks-debug`. `bound-checks-debug` enables the
entire breadth of -fbounds-safety diagnostics and gives you the most easily
debugged bounds checks. You should also use bound-checks-debug for xnu changes
that you send to integration testing.

## Step 2: separate adoption from enablement

Once you're confident in your code changes, everything builds, at-desk testing
is successful and integration testing is happy, you start two pull requests:

* one pull request with the necessary adoption code changes, configuring the
  file to build with `bound-checks-pending`;
* one pull request that changes `bound-checks-pending` to `bound-checks-soft`.

This strategy can save your change and other people's changes even in the face
of small errors. Read on to "where bound-checks-soft comes in" for more details.

### Where bound-checks-pending comes in

The configuration status quo of any file in xnu is to build with no options
relating to -fbounds-safety. In this mode, -fbounds-safety's `__indexable` and
`__bidi_indexable` keywords are **undefined**. It is a syntax error to use them.
This is because `__indexable` and `__bidi_indexable` pointers are not
ABI-compatible with plain C: if they were defined to nothing instead, and a use
of `__indexable` or `__bidi_indexable` slipped into a header used by a set of
files heterogeneously enabling -fbounds-safety, they could cause ABI breaks that
would manifest as opaque runtime crashes instead of compile-time errors.

However, adopting -fbounds-safety may require the explicit use of `__indexable`
or `__bidi_indexable` pointers that are confined to the file being modified.
Until `bound-checks-soft` is enabled, it must still be possible to build that
file without -fbounds-safety. This is where `bound-checks-pending` comes in:
this flag causes `__indexable` and `__bidi_indexable` to expand to nothing, and
it disables warnings that will frequently trip in plain C files that are
compatible with -fbounds-safety (such as -Wself-assign). This allows files that
are compatible with -fbounds-safety to continue to build without it, while
minimizing the risk of ABI incompatibilities.

### Where bound-checks-soft comes in

Using `bound-checks-soft` means that if a problem slips through qualification,
the kernel is still probably livable. A kernel that is unlivable due to panics
creates significant drag over the entire software development organization, and
fixing it will be a same-day emergency that you will need to firefight and then
root-cause. This **will** take precedence over any other work that you could
rather be doing. On the other hand, "soft traps" generate telemetry without
panicking. Kernels with known soft trap triggers are un-shippable, but they may
still be livable. As a result, fixing these problems is merely very important.

`bound-checks-soft` is enabled separately from the code change because even
though `bound-checks-soft` is ideally non-fatal, failing a bounds check in
certain conditions can still result in an un-livable kernel (for instance,
if a check fails in a long, tight loop). If such a serious issue slips into
qualification, integrators only need to back out the `bound-checks-soft` change
(falling back to `bound-checks-pending`) instead of reverting your entire
change. Reverting entire changes is a very destructive integration action: any
_other_ changes that rely on your modifications may need to be cascaded out of
the build as well. Given unfortunate-enough timing, there _may not be time_ to
re-nominate feature work that must be backed out. Significant -fbounds-safety
adoption experience in xnu and other projects has taught us that bundling in
non-trivial code changes with the enablement of -fbounds-safety is a recipe for
sadness and reprised work.

### Where bound-checks-seed comes in

If you want to enable `bound-checks` for internal users but want to use
`bound-checks-soft` for external users in order to collect telemetry
(e.g. during seeding), use `bound-checks-seed`.
The expectation is that, once the telemetry is collected, you will change the
file to `bound-checks` or disable -fbounds-safety.
Due to security concerns, namely non fatal traps, `bound-checks-seed`
is not meant to be shipped to customers outside of seeding.

## Step 3: enable bound-checks

We let changes with `bound-checks-soft` steep in internal releases to build up
confidence that bounds checks don't trip during regular operations. During this
period, failing bounds checks create telemetry events that are collected by
XNU engineers instead of bringing down the system. Although failing bounds
checks are never desirable, it is better to catch them at that stage than at any
point after.

Once we have confidence that a file doesn't cause issues when -fbounds-safety is
enabled, we can change `bound-checks-soft` to the plain `bound-checks`. This is
simply done with another pull request.

Read "where bound-checks-seed comes in" for a different approach if you need
a higher confidence level before enabling `bound-checks`.

