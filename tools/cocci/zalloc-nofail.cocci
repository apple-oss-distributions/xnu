// To apply, at the top of xnu.git:
// $ spatch --max-width=80 --use-gitgrep --in-place --include-headers --sp-file tools/cocci/zalloc.cocci -dir .
//
// This might need to be run several times

@ using "zalloc.iso" @
expression E, F;
type T;
identifier V;
identifier NI =~ "_NULL$";
@@
(

(
  E = zalloc_flags(F, \(Z_NOFAIL\|Z_NOFAIL | ...\));
|
  E = kalloc_type(F, \(Z_NOFAIL\|Z_NOFAIL | ...\));
|
  E = \(kalloc_data\|kalloc_flags\)(F, \(Z_NOFAIL\|Z_NOFAIL | ...\));
|
- E = zalloc(F);
+ E = zalloc_flags(F, Z_WAITOK | Z_NOFAIL);
|
  E = zalloc_flags(F, \(Z_WAITOK\| Z_WAITOK | ...\)
+ | Z_NOFAIL
  );
|
  E = kalloc_type(T, \(Z_WAITOK\| Z_WAITOK | ...\)
+ | Z_NOFAIL
  );
|
  E = \(kalloc_data\|kalloc_flags\)(sizeof(F), \(Z_WAITOK\| Z_WAITOK | ...\)
+ | Z_NOFAIL
  );
|
- E = kalloc(sizeof(F));
+ E = kalloc_flags(sizeof(F), Z_WAITOK | Z_NOFAIL);
)
  ...
(
- if (\(E\|E != 0\|E != NULL\|E != NI\)) {
  ...
- }
|
- if (\(!E\|E == 0\|E == NULL\|E == NI\)) {
- ...
- }
|
- assert(\(E\|E != 0\|E != NULL\|E != NI\));
)

|

(
  T V = zalloc_flags(F, \(Z_NOFAIL\|Z_NOFAIL | ...\));
|
  T V = kalloc_type(T, \(Z_NOFAIL\|Z_NOFAIL | ...\));
|
  T V = \(kalloc_data\|kalloc_flags\)(F, \(Z_NOFAIL\|Z_NOFAIL | ...\));
|
- T V = kalloc(sizeof(F));
+ T V = kalloc_flags(sizeof(F), Z_WAITOK | Z_NOFAIL);
|
  T V = kalloc_type(T, \(Z_WAITOK\| Z_WAITOK | ...\)
+ | Z_NOFAIL
  );
|
  T V = \(kalloc_data\|kalloc_flags\)(sizeof(F), \(Z_WAITOK\| Z_WAITOK | ...\)
+ | Z_NOFAIL
  );
)
  ...
(
- if (\(V\|V != 0\|V != NULL\|V != NI\)) {
  ...
- }
|
- if (\(!V\|V == 0\|V == NULL\|V == NI\)) {
- ...
- }
|
- assert(\(V\|V != 0\|V != NULL\|V != NI\));
)

)

// vim:ft=diff:
