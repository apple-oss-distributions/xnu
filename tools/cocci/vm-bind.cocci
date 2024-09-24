@@
identifier Fn =~ "^vm_sanitize_";
expression Arg, kr;
expression list trailer;
@@

- Arg = Fn(&kr, trailer);
+ kr = Fn(&Arg, trailer);
+ if (__improbable(kr != KERN_SUCCESS)) {
+     return replace_with_cleanup_func();
+ }

@@
identifier Fn;
expression Arg1, Arg2, Arg3, kr;
expression list trailer;
@@

- VM_BIND_3(Arg1, Arg2, Arg3, Fn(&kr, trailer));
+ kr = Fn(&Arg1, &Arg2, &Arg3, trailer);
+ if (__improbable(kr != KERN_SUCCESS)) {
+     return replace_with_cleanup_func();
+ }

@@
identifier Fn;
expression Arg1, Arg2, kr;
expression list trailer;
@@

- VM_BIND_2(Arg1, Arg2, Fn(&kr, trailer));
+ kr = Fn(&Arg1, &Arg2, trailer);
+ if (__improbable(kr != KERN_SUCCESS)) {
+     return replace_with_cleanup_func();
+ }
