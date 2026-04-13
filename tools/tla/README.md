XNU TLA specs
=============

This folder contains formal TLA+ specs of different algorithms used in XNU.

To perform spec checking, use the wrappers provided in the directory:

    $ ./scripts/get_tla
    $ ./scripts/pcal <spec.tla>
    # possibly tweak <spec.cfg>
    $ ./scripts/tlc <spec.tla> | tee spec.log


Plusacl Tips and tricks
-----------------------

A few things that are worth keeping in mind when writing a spec:

Views should be used to reduce useless state. In particular, the following
variables can be elided from the spec View:

- function arguments that are never modified and copy a local state,
  by definition they are not meaningful and duplicate state, unfortunately
  after a function is called, they aren't reset which makes TLC believe
  this is new state.

  Note that if the argument is being mutated by the function, or is an atomic
  copy of global concurrent state, then this an invalid optimization.

- return values tend to be global variables and similarly to function arguments
  they tend to replicate something that's already part of the state and isn't
  being reset after use and similarly make TLC believe this is new state.


PlusCal also doesn't have a notion of "scope" for variables, so going out of
scope must be implemented by hand bey resetting variables to `defaultInitValue`
when their value is no longer used. This similarly makes TLC converge faster
by avoiding unnecessary pollution of the state due to historical artefacts.


rwlock.tla
----------

Model of the new implementation of the reader-writer lock. The model is generic
and takes several shortcuts:

- it doesn't model memory ordering or arm64 instructions;
- it doesn't model all fastpaths;
- its wait queue modeling is similarly more atomic than reality.

The point of the model is to validate basic properties:

- read/write mutual exclusion;
- write/write mutual exclusion;
- no threads can end up blocked forever and not being woken up.

The model allows for each process to do `Steps` operations in a row,
and the model checks threads complete.


