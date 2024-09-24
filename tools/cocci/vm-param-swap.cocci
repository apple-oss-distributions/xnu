@@
expression kr;
expression offset, vms_caller, addr, end, offset_u;
@@

- kr = vm_sanitize_offset(&offset, vms_caller, addr, end, offset_u);
+ kr = vm_sanitize_offset(offset_u, vms_caller, addr, end, &offset);

@@
expression kr;
expression mask, vms_caller, mask_u;
@@

- kr = vm_sanitize_mask(&mask, vms_caller, mask_u);
+ kr = vm_sanitize_mask(mask_u, vms_caller, &mask);

@@
expression kr;
expression size, vms_caller, flags, size_u;
@@

- kr = vm_sanitize_object_size(&size, vms_caller, flags, size_u);
+ kr = vm_sanitize_object_size(size_u, vms_caller, flags, &size);

@@
expression kr;
expression size, vms_caller, map, flags, offset_u, size_u;
@@

- kr = vm_sanitize_size(&size, vms_caller, map, flags, offset_u, size_u);
+ kr = vm_sanitize_size(offset_u, size_u, vms_caller, map, flags, &size);

@@
expression kr;
expression prot, vms_caller, map, prot_u, extra_mask;
@@

- kr = vm_sanitize_prot(&prot, vms_caller, map, prot_u, extra_mask);
+ kr = vm_sanitize_prot(prot_u, vms_caller, map, extra_mask, &prot);

@@
expression kr;
expression prot, vms_caller, map, prot_u;
@@

- kr = vm_sanitize_prot(&prot, vms_caller, map, prot_u);
+ kr = vm_sanitize_prot(prot_u, vms_caller, map, &prot);

@@
expression kr;
expression prot, vms_caller, prot_u;
@@

- kr = vm_sanitize_prot_bsd(&prot, vms_caller, prot_u);
+ kr = vm_sanitize_prot_bsd(prot_u, vms_caller, &prot);

@@
expression kr;
expression perm, vms_caller, perm_u, flags, extra_mask;
@@

- kr = vm_sanitize_memory_entry_perm(&perm, vms_caller, perm_u, flags, extra_mask);
+ kr = vm_sanitize_memory_entry_perm(perm_u, vms_caller, flags, extra_mask, &perm);

@@
expression kr;
expression inherit, vms_caller, inherit_u;
@@

- kr = vm_sanitize_inherit(&inherit, vms_caller, inherit_u);
+ kr = vm_sanitize_inherit(inherit_u, vms_caller, &inherit);

@@
expression kr;
expression addr, end, size, vms_caller, pgmask, flags, addr_u, size_u;
@@

- kr = vm_sanitize_addr_size(&addr, &end, &size, vms_caller, pgmask, flags, addr_u, size_u);
+ kr = vm_sanitize_addr_size(addr_u, size_u, vms_caller, pgmask, flags, &addr, &end, &size);

@@
expression kr;
expression start, end, size, vms_caller, map, flags, addr_u, end_u;
@@

- kr = vm_sanitize_addr_end(&start, &end, &size, vms_caller, map, flags, addr_u, end_u);
+ kr = vm_sanitize_addr_end(addr_u, end_u, vms_caller, map, flags, &start, &end, &size);

@@
expression kr;
expression cur_prot, max_prot, vms_caller, map, cur_prot_u, max_prot_u, extra_mask;
@@

- kr = vm_sanitize_prot_cur_max(&cur_prot, &max_prot, vms_caller, map, cur_prot_u, max_prot_u, extra_mask);
+ kr = vm_sanitize_prot_cur_max(cur_prot_u, max_prot_u, vms_caller, map, extra_mask, &cur_prot, &max_prot);

@@
expression kr;
expression cur_prot, max_prot, vms_caller, map, cur_prot_u, max_prot_u;
@@

- kr = vm_sanitize_prot_cur_max(&cur_prot, &max_prot, vms_caller, map, cur_prot_u, max_prot_u);
+ kr = vm_sanitize_prot_cur_max(cur_prot_u, max_prot_u, vms_caller, map, &cur_prot, &max_prot);

