/*
 * Copyright (c) 1998-2011 Erez Zadok
 * Copyright (c) 2009	   Shrikar Archak
 * Copyright (c) 2003-2011 Stony Brook University
 * Copyright (c) 2003-2011 The Research Foundation of SUNY
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#include "wrapfs.h"
#define OPEN_WRITE_FLAGS (O_WRONLY | O_RDWR | O_APPEND)
#define MAX 100

static ssize_t wrapfs_read(struct file *file, char __user *buf,
			   size_t count, loff_t *ppos)
{
	int err;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;
	lower_file = wrapfs_lower_file(file);
	if (!lower_file)
		lower_file = wrapfs_lower_file_idx(file, 1);
	err = vfs_read(lower_file, buf, count, ppos);
	/* update our inode atime upon a successful lower read */
	if (err >= 0)
		fsstack_copy_attr_atime(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);

	return err;
}

static ssize_t wrapfs_write(struct file *file, const char __user *buf,
			    size_t count, loff_t *ppos)
{
	int err = 0;
	struct file *lower_file;
	struct dentry *dentry = file->f_path.dentry;

	lower_file = wrapfs_lower_file(file);
	err = vfs_write(lower_file, buf, count, ppos);
	/* update our inode times+sizes upon a successful lower write */
	if (err >= 0) {
		fsstack_copy_inode_size(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
		fsstack_copy_attr_times(dentry->d_inode,
					lower_file->f_path.dentry->d_inode);
	}

	return err;
}
struct wrapfs_getdents_callback {
	void *dirent;
	int entries_written;
	int filldir_size;
	filldir_t filldir;
	char **files;
	int index;
	int count;
	int leftcount;
};
char *get_whiteout(char *name, int len)
{
	char *buf;
	buf = kmalloc(len + 5, GFP_KERNEL);
	if (unlikely(!buf))
		return ERR_PTR(-ENOMEM);
	strcpy(buf, ".wh.");
	strlcat(buf, name, len + 6);
	return buf;
}
static int wrapfs_check_filename(char **files, char *name, int len, int count)
{
	int i = 0;
	int namelen = len + 6;
	char *whname = get_whiteout(name, len);
	for (i = 0; i < count; i++) {
		if (!strncmp(files[i], whname, namelen))
			return 1;
		if (!strncmp(files[i], name, len))
			return 1;
	}
return 0;
}
static int wrapfs_filldir(void *dirent, const char *oname, int namelen,
			loff_t offset, u64 ino, unsigned int d_type)
{
	struct wrapfs_getdents_callback *buf = dirent;
	int err = 0;
	int is_whiteout = false;
	char *name = (char *) oname;
	int count = buf->count;
	if (buf->index == 0) {
		buf->files[count] = kmalloc(namelen, GFP_KERNEL);
		buf->files[count] = name;
		buf->count++;
	}
	if (buf->index == 1 && buf->leftcount >= 1) {
		err = wrapfs_check_filename(buf->files, name, namelen,
							buf->leftcount);
		if (err)
			is_whiteout = true;
		err = 0;
	}
	if (buf->index == 0)
		if (!strncmp(name, ".wh.", 4))
			is_whiteout = true;
	if (!is_whiteout)
		err = buf->filldir(buf->dirent, name, namelen, offset,
			ino, d_type);
	return err;
}
static int wrapfs_readdir(struct file *file, void *dirent, filldir_t filldir)
{
	int err = 0, bindex = 0;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct wrapfs_getdents_callback buf;
	for (bindex = 0 ; bindex <= 1; ++bindex) {
		lower_file = wrapfs_lower_file_idx(file, bindex);
		if (!lower_file) {
			buf.files = NULL;
			buf.leftcount = 0;
			continue;
		}
	buf.dirent = dirent;
	buf.filldir = filldir;
	buf.index = bindex;
	buf.count = 0;
	if (bindex == 0)
		buf.files = kmalloc(MAX * sizeof(char *), GFP_KERNEL);
	err = vfs_readdir(lower_file, wrapfs_filldir, &buf);
	file->f_pos = lower_file->f_pos;
	if (bindex == 0)
		buf.leftcount = buf.count;
	else
	buf.leftcount = 0;
	if (err >= 0)
		fsstack_copy_attr_atime(dentry->d_inode,
				lower_file->f_path.dentry->d_inode);
	}
	return err;
}

static long wrapfs_unlocked_ioctl(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = wrapfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->unlocked_ioctl)
		err = lower_file->f_op->unlocked_ioctl(lower_file, cmd, arg);

out:
	return err;
}

#ifdef CONFIG_COMPAT
static long wrapfs_compat_ioctl(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	long err = -ENOTTY;
	struct file *lower_file;

	lower_file = wrapfs_lower_file(file);

	/* XXX: use vfs_ioctl if/when VFS exports it */
	if (!lower_file || !lower_file->f_op)
		goto out;
	if (lower_file->f_op->compat_ioctl)
		err = lower_file->f_op->compat_ioctl(lower_file, cmd, arg);

out:
	return err;
}
#endif

static int wrapfs_mmap(struct file *file, struct vm_area_struct *vma)
{
	int err = 0;
	bool willwrite;
	struct file *lower_file;
	const struct vm_operations_struct *saved_vm_ops = NULL;

	/* this might be deferred to mmap's writepage */
	willwrite = ((vma->vm_flags | VM_SHARED | VM_WRITE) == vma->vm_flags);

	/*
	 * File systems which do not implement ->writepage may use
	 * generic_file_readonly_mmap as their ->mmap op.  If you call
	 * generic_file_readonly_mmap with VM_WRITE, you'd get an -EINVAL.
	 * But we cannot call the lower ->mmap op, so we can't tell that
	 * writeable mappings won't work.  Therefore, our only choice is to
	 * check if the lower file system supports the ->writepage, and if
	 * not, return EINVAL (the same error that
	 * generic_file_readonly_mmap returns in that case).
	 */
	lower_file = wrapfs_lower_file(file);
	if (willwrite && !lower_file->f_mapping->a_ops->writepage) {
		err = -EINVAL;
		printk(KERN_ERR "wrapfs: lower file system does not "
		       "support writeable mmap\n");
		goto out;
	}

	/*
	 * find and save lower vm_ops.
	 *
	 * XXX: the VFS should have a cleaner way of finding the lower vm_ops
	 */
	if (!WRAPFS_F(file)->lower_vm_ops) {
		err = lower_file->f_op->mmap(lower_file, vma);
		if (err) {
			printk(KERN_ERR "wrapfs: lower mmap failed %d\n", err);
			goto out;
		}
		saved_vm_ops = vma->vm_ops; /* save: came from lower ->mmap */
		err = do_munmap(current->mm, vma->vm_start,
				vma->vm_end - vma->vm_start);
		if (err) {
			printk(KERN_ERR "wrapfs: do_munmap failed %d\n", err);
			goto out;
		}
	}

	/*
	 * Next 3 lines are all I need from generic_file_mmap.  I definitely
	 * don't want its test for ->readpage which returns -ENOEXEC.
	 */
	file_accessed(file);
	vma->vm_ops = &wrapfs_vm_ops;
	vma->vm_flags |= VM_CAN_NONLINEAR;

	file->f_mapping->a_ops = &wrapfs_aops; /* set our aops */
	if (!WRAPFS_F(file)->lower_vm_ops) /* save for our ->fault */
		WRAPFS_F(file)->lower_vm_ops = saved_vm_ops;

out:
	return err;
}
/*added by nafees*/
/* unionfs_open helper function: open a directory */
static int __open_dir(struct inode *inode, struct file *file,
		      struct dentry *parent)
{
	struct dentry *lower_dentry;
	struct file *lower_file;
	int bindex;
	struct vfsmount *lower_mnt;
	struct dentry *dentry = file->f_path.dentry;
	struct path path;

	for (bindex = 0; bindex <= 1; bindex++) {
		lower_dentry = wrapfs_lower_dentry_idx(dentry, bindex);
		if (!lower_dentry)
				continue;
		dget(lower_dentry);
		lower_mnt = wrapfs_lower_mnt_idx(dentry, bindex);
		if (!lower_mnt)
			lower_mnt = wrapfs_lower_mnt_idx(parent, bindex);
		path.dentry = lower_dentry;
		path.mnt = lower_mnt;
		if (!lower_dentry->d_inode)
			continue;
		else
			lower_file = dentry_open(lower_dentry, lower_mnt,
					 file->f_flags, current_cred());

		if (IS_ERR(lower_file))
			return PTR_ERR(lower_file);

		wrapfs_set_lower_file_idx(file, bindex, lower_file);
		if (!wrapfs_lower_mnt_idx(dentry, bindex))
			wrapfs_set_lower_mnt_idx(dentry, bindex, lower_mnt);

		/*
		 * The branchget goes after the open, because otherwise
		 * we would miss the reference on release.
		 */
		branchget(inode->i_sb, bindex);
	}
	return 0;
}

/* unionfs_open helper function: open a file */
static int __open_file(struct inode *inode, struct file *file,
		       struct dentry *parent)
{
	struct dentry *lower_dentry;
	struct file *lower_file;
	int lower_flags;
	int bindex;
	struct dentry *dentry = file->f_path.dentry;
	struct vfsmount *lower_mnt;
	struct path path;
	lower_flags = file->f_flags;
	for (bindex = 0; bindex <= 1; bindex++) {
		lower_dentry =
			wrapfs_lower_dentry_idx(dentry, bindex);
		if (!lower_dentry)
			continue;
		if (!lower_dentry->d_inode)
			continue;

	/*keep copy up code here */
	/*
	 * check for the permission for lower file.  If the error is
	 * COPYUP_ERR, copyup the file.
	 */
	if (lower_dentry->d_inode && (bindex == 1)) {
		/*
		 * if the open will change the file, copy it up otherwise
		 * defer it.
		 */
		if (lower_flags & O_TRUNC) {
			int size = 0;
			int err = -EROFS;
			/* copyup the file */
			err = copyup_file(parent->d_inode, file,
						  bindex, 0, size);
		if (!err)
					break;
			return err;
		} else {
			/*
			 * turn off writeable flags, to force delayed copyup
			 * by caller.
			 */
			lower_flags &= ~(OPEN_WRITE_FLAGS);
		}
	}
	/*end here*/
		dget(lower_dentry);
		lower_mnt = wrapfs_lower_mnt_idx(dentry, bindex);
		if (!lower_mnt)
			lower_mnt = wrapfs_lower_mnt_idx(parent, bindex);
		path.dentry = lower_dentry;
		path.mnt = lower_mnt;
		if (!lower_dentry->d_inode)
			continue;
		else
			lower_file = dentry_open(lower_dentry, lower_mnt,
						 file->f_flags, current_cred());
		/*path_put(&path);*/
		if (IS_ERR(lower_file))
			return PTR_ERR(lower_file);

		wrapfs_set_lower_file_idx(file, bindex, lower_file);
		if (!wrapfs_lower_mnt_idx(dentry, bindex))
			wrapfs_set_lower_mnt_idx(dentry, bindex, lower_mnt);

		/*
		 * The branchget goes after the open, because otherwise
		 * we would miss the reference on release.
		 */
		branchget(inode->i_sb, bindex);
		return 0;
	}
	UDBG;
	return 0;
}

int wrapfs_open(struct inode *inode, struct file *file)
{
	int err = 0;
	struct file *lower_file = NULL;
	struct dentry *dentry = file->f_path.dentry;
	struct dentry *parent;
	int bindex = 0;
	int size = 3;

	/* don't open unhashed/deleted files */
	if (d_unhashed(dentry)) {
		err = -ENOENT;
		goto out_nofree;
	}
	parent = dget_parent(dentry);
	file->private_data =
		kzalloc(sizeof(struct wrapfs_file_info), GFP_KERNEL);
	if (unlikely(!WRAPFS_F(file))) {
		err = -ENOMEM;
		goto out_nofree;
	}
	size = sizeof(struct file *) * size;
	WRAPFS_F(file)->lower_files = kzalloc(size, GFP_KERNEL);
	if (unlikely(!WRAPFS_F(file)->lower_files)) {
		err = -ENOMEM;
		goto out;
	}

	/*
	 * open all directories and make the unionfs file struct point to
	 * these lower file structs
	 */
	if (S_ISDIR(inode->i_mode))
		err = __open_dir(inode, file, parent); /* open a dir */
	else
		err = __open_file(inode, file, parent);	/* open a file */
	UDBG;
	/* freeing the allocated resources, and fput the opened files */
	if (err) {
		for (bindex = 0; bindex <= 1; bindex++) {
			lower_file = wrapfs_lower_file_idx(file, bindex);
			if (!lower_file)
				continue;

			branchput(dentry->d_sb, bindex);
			/* fput calls dput for lower_dentry */
			fput(lower_file);
		}
	}
out:
	UDBG;
	dput(parent);
	UDBG;
	if (err) {
		kfree(WRAPFS_F(file)->lower_files);
		kfree(WRAPFS_F(file));
	}
	UDBG;
out_nofree:
UDBG;
	return err;
}
static int wrapfs_flush(struct file *file, fl_owner_t id)
{
	int err = 0;
	struct file *lower_file = NULL;
	lower_file = wrapfs_lower_file(file);
	if (lower_file && lower_file->f_op && lower_file->f_op->flush)
		err = lower_file->f_op->flush(lower_file, id);
	UDBG;
	return err;
}

/* release all lower object references & free the file info structure */
static int wrapfs_file_release(struct inode *inode, struct file *file)
{
	struct file *lower_file;
	lower_file = wrapfs_lower_file(file);
	if (lower_file) {
		wrapfs_set_lower_file(file, NULL);
		fput(lower_file);
	}
	UDBG;
	kfree(WRAPFS_F(file));
	return 0;
}

static int wrapfs_fsync(struct file *file, loff_t start, loff_t end,
			int datasync)
{
	int err;
	struct file *lower_file;
	struct path lower_path;
	struct dentry *dentry = file->f_path.dentry;
	UDBG;
	err = generic_file_fsync(file, start, end, datasync);
	if (err)
		goto out;
	lower_file = wrapfs_lower_file(file);
	wrapfs_get_lower_path(dentry, &lower_path);
	err = vfs_fsync_range(lower_file, start, end, datasync);
	wrapfs_put_lower_path(dentry, &lower_path);
	UDBG;
out:
	return err;
}

static int wrapfs_fasync(int fd, struct file *file, int flag)
{
	int err = 0;
	struct file *lower_file = NULL;

	lower_file = wrapfs_lower_file(file);
	if (lower_file->f_op && lower_file->f_op->fasync)
		err = lower_file->f_op->fasync(fd, lower_file, flag);

	return err;
}

const struct file_operations wrapfs_main_fops = {
	.llseek		= generic_file_llseek,
	.read		= wrapfs_read,
	.write		= wrapfs_write,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.mmap		= wrapfs_mmap,
	.open		= wrapfs_open,
	.flush		= wrapfs_flush,
	.release	= wrapfs_file_release,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};

/* trimmed directory options */
const struct file_operations wrapfs_dir_fops = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= wrapfs_readdir,
	.unlocked_ioctl	= wrapfs_unlocked_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= wrapfs_compat_ioctl,
#endif
	.open		= wrapfs_open,
	.release	= wrapfs_file_release,
	.flush		= wrapfs_flush,
	.fsync		= wrapfs_fsync,
	.fasync		= wrapfs_fasync,
};
