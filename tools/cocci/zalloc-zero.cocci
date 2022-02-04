// To apply, at the top of xnu.git:
// $ spatch --max-width=80 --use-gitgrep --in-place --include-headers --sp-file tools/cocci/zalloc.cocci -dir .
//
// This might need to be run several times

@ using "zalloc.iso" @
expression E, F, G;
type T;
identifier V;
@@
(

(
  E = zalloc_flags(F, \(Z_ZERO\|Z_ZERO | ...\));
|
  E = kalloc_type(F, \(Z_ZERO\|Z_ZERO | ...\));
|
  E = \(kalloc_data\|kalloc_flags\)(F, \(Z_ZERO\|Z_ZERO | ...\));
|
- E = zalloc(F);
+ E = zalloc_flags(F, Z_WAITOK | Z_ZERO);
|
  E = zalloc_flags(F, \(Z_WAITOK\| Z_WAITOK | ...\)
+ | Z_ZERO
  );
)
  ...
- bzero(E, G);

|

(
- E = kalloc(F);
+ E = kalloc_flags(F, Z_WAITOK | Z_ZERO);
|
  E = kalloc_type(T, \(Z_WAITOK\| Z_WAITOK | ...\)
+ | Z_ZERO
  );
|
  E = \(kalloc_data\|kalloc_flags\)(F, \(Z_WAITOK\| Z_WAITOK | ...\)
+ | Z_ZERO
  );
)
  ...
- bzero(E, F);

|


- T V = zalloc(F);
+ T V = zalloc_flags(F, Z_WAITOK | Z_ZERO);
  ...
- bzero(V, G);

|

(
  T V = zalloc_flags(F, \(Z_ZERO\|Z_ZERO | ...\));
|
  T V = kalloc_type(T, \(Z_ZERO\|Z_ZERO | ...\));
|
  T V = \(kalloc_data\|kalloc_flags\)(F, \(Z_ZERO\|Z_ZERO | ...\));
|
- T V = kalloc(F);
+ T V = kalloc_flags(F, Z_WAITOK | Z_ZERO);
|
  T V = kalloc_type(T, \(Z_WAITOK\| Z_WAITOK | ...\)
+ | Z_ZERO
  );
|
  T V = \(zalloc_flags\|kalloc_data\|kalloc_flags\)(F, \(Z_WAITOK\| Z_WAITOK | ...\)
+ | Z_ZERO
  );
)
  ...
- bzero(V, F);

)

// vim:ft=diff:
