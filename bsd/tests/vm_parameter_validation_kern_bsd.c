#include <sys/cdefs.h>
#include <sys/proc_internal.h>
#include <sys/vnode_internal.h>
#include <sys/ubc_internal.h>
#include <sys/file_internal.h>
#include <sys/vnode.h>

// From vm_parameter_validation_kern.c
void testprintf(const char *format, ...);

struct file_control_return {
	void * control;
	struct fileproc * fp;
	struct vnode * vp;
	int fd;
};
struct file_control_return get_control_from_fd(int fd);

struct file_control_return
get_control_from_fd(int fd)
{
	struct fileproc                 *fp = NULL;
	struct vnode                    *vp = NULL;
	size_t                          file_size;
	off_t                           fs;
	memory_object_control_t         file_control = NULL;
	int                             error;
	struct file_control_return ret = {NULL, NULL, NULL, fd};


	proc_t p = current_proc();

	/* get file structure from file descriptor */
	error = fp_get_ftype(p, fd, DTYPE_VNODE, EINVAL, &fp);
	if (error) {
		testprintf("%s: [%d(%s)]: fp_get_ftype() failed, error %d\n",
		    __func__, proc_getpid(p), p->p_comm, error);
		return ret;
	}
	ret.fp = fp;

	/* We need at least read permission on the file */
	if (!(fp->fp_glob->fg_flag & FREAD)) {
		testprintf("%s: [%d(%s)]: not readable\n",
		    __func__, proc_getpid(p), p->p_comm);
		return ret;
	}

	/* Get the vnode from file structure */
	vp = (struct vnode *)fp_get_data(fp);
	error = vnode_getwithref(vp);
	if (error) {
		testprintf("%s: [%d(%s)]: failed to get vnode, error %d\n",
		    __func__, proc_getpid(p), p->p_comm, error);
		return ret;
	}
	ret.vp = vp;

	/* Make sure the vnode is a regular file */
	if (vp->v_type != VREG) {
		testprintf("%s: [%d(%s)]: vnode not VREG\n",
		    __func__, proc_getpid(p), p->p_comm);
		return ret;
	}

	/* get vnode size */
	error = vnode_size(vp, &fs, vfs_context_current());
	if (error) {
		return ret;
	}
	file_size = fs;

	/* get the file's memory object handle */
	file_control = ubc_getobject(vp, UBC_HOLDOBJECT);
	if (file_control == MEMORY_OBJECT_CONTROL_NULL) {
		testprintf("%s: [%d(%s)]: no memory object\n",
		    __func__, proc_getpid(p), p->p_comm);
		return ret;
	}
	ret.control = file_control;

	return ret;
}

void cleanup_control_related_data(struct file_control_return info);

void
cleanup_control_related_data(struct file_control_return info)
{
	if (info.fp != NULL) {
		/* release the file descriptor */
		fp_drop(current_proc(), info.fd, info.fp, 0);
	}
	if (info.vp != NULL) {
		(void)vnode_put(info.vp);
	}
}
