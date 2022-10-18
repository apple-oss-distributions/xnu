#!/usr/sbin/dtrace -s

vminfo:::object_ownership_change
{
	old_owner = (task_t)arg1;
	if (old_owner == 0) {
		old_pid = -1;
		old_name = "(nil)";
	} else {
		old_proc = xlate <psinfo_t *>((proc_t)old_owner->t_tro->tro_proc);
		old_pid = old_proc->pr_pid;
		old_name = old_proc->pr_fname;
	}
	new_owner = (task_t)arg4;
	if (new_owner == 0) {
		new_pid = -1;
		new_name = "(nil)";
	} else {
		new_proc = xlate <psinfo_t *>((proc_t)new_owner->t_tro->tro_proc);
		new_pid = new_proc->pr_pid;
		new_name = new_proc->pr_fname;
	}

	printf("%d[%s] object 0x%p id 0x%x purgeable:%d owner:0x%p (%d[%s]) tag:%d nofootprint:%d -> owner:0x%p (%d[%s]) tag:%d nofootprint:%d",
	       pid, execname, arg0, arg7, ((vm_object_t)arg0)->purgable,
	       old_owner, old_pid, old_name,
	       arg2, arg3,
	       new_owner, new_pid, new_name,
	       arg5, arg6);
	stack();
	ustack();
}
