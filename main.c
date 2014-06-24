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
#include <linux/module.h>

 /*
  * make sure the branch we just looked up (nd) makes sense:
  *
  * 1) we're not trying to stack unionfs on top of unionfs
  * 2) it exists
  * 3) is a directory
  */
int check_branch(const struct path *path)
{	/* XXX: remove in ODF code -- stacking unions allowed there */
	if (!strcmp(path->dentry->d_sb->s_type->name, WRAPFS_NAME))
		return -EINVAL;
	if (!path->dentry->d_inode)
		return -ENOENT;
	if (!S_ISDIR(path->dentry->d_inode->i_mode))
		return -ENOTDIR;
		return 0;
}
static void wrapfs_fill_inode(struct dentry *dentry, struct inode *inode)
{
	struct inode *lower_inode;
	struct dentry *lower_dentry;
	int bindex ;
	for (bindex = 0; bindex <= 1; bindex++) {
		lower_dentry = wrapfs_lower_dentry_idx(dentry, bindex);
		if (!lower_dentry) {
			wrapfs_set_lower_inode_idx(inode, bindex, NULL);
			continue;
		}
		/* Initialize the lower inode to the new lower inode. */
		if (!lower_dentry->d_inode)
			continue;
			wrapfs_set_lower_inode_idx(inode, bindex,
				igrab(lower_dentry->d_inode));
		}
	/* Use attributes from the first branch. */
	lower_inode = wrapfs_lower_inode(inode);
	/* Use different set of inode ops for symlinks & directories */
	if (S_ISLNK(lower_inode->i_mode))
		inode->i_op = &wrapfs_symlink_iops;
	else if (S_ISDIR(lower_inode->i_mode))
		inode->i_op = &wrapfs_dir_iops;
	/* Use different set of file ops for directories */
	if (S_ISDIR(lower_inode->i_mode))
		inode->i_fop = &wrapfs_dir_fops;
	/* properly initialize special inodes */
	if (S_ISBLK(lower_inode->i_mode) || S_ISCHR(lower_inode->i_mode) ||
		S_ISFIFO(lower_inode->i_mode) || S_ISSOCK(lower_inode->i_mode))
		init_special_inode(inode, lower_inode->i_mode,
		lower_inode->i_rdev);
	/* all well, copy inode attributes */
	fsstack_copy_attr_all(inode, lower_inode);
	fsstack_copy_inode_size(inode, lower_inode);
}
static int parse_dirs_option(struct super_block *sb, struct wrapfs_dentry_info
				*lower_root_info, char *options)
{
		struct path path;
		char *name;
		int err = 0;
		int branches = 2;
		int bindex = 0;
		int i = 0;
		/* allocate space for underlying pointers to lower dentry */
		WRAPFS_SB(sb)->data =
		kcalloc(branches, sizeof(struct wrapfs_data), GFP_KERNEL);
		if (unlikely(!WRAPFS_SB(sb)->data)) {
			err = -ENOMEM;
			goto out_return;
		}
	lower_root_info->lower_paths =
		kcalloc(branches, sizeof(struct path), GFP_KERNEL);
	if (unlikely(!lower_root_info->lower_paths)) {
		err = -ENOMEM;
		/* free the underlying pointer array */
		kfree(WRAPFS_SB(sb)->data);
		WRAPFS_SB(sb)->data = NULL;
		goto out_return;
	}
	/* now parsing a string */
	branches = 0;
	while ((name = strsep(&options, ",")) != NULL) {
		int perms;
		char *dir = strchr(name, '=');
		if (!name)
			continue;
		if (!*name) {   /* bad use of ','  */
			err = -EINVAL;
			goto out;
		}
	branches++;
		if (dir)
			*dir++ = '\0';
		if (bindex == 0)
			perms = MAY_READ | MAY_WRITE;
		else
			perms = MAY_READ;
		err = kern_path(dir, LOOKUP_FOLLOW, &path);
		if (err) {
			printk(KERN_ERR "u2fs: error accessing "
				"lower directory '%s' (error %d)\n", name, err);
			goto out;
		}
		err = check_branch(&path);
		if (err) {
			printk(KERN_ERR "u2fs: lower directory "
				"'%s' is not a valid branch\n", name);
			path_put(&path);
			goto out;
		}
		lower_root_info->lower_paths[bindex].dentry = path.dentry;
		lower_root_info->lower_paths[bindex].mnt = path.mnt;
		set_branchperms(sb, bindex, perms);
		set_branch_count(sb, bindex, 0);
		new_branch_id(sb, bindex);
		bindex++;
	}
	if (branches == 0) {
		printk(KERN_ERR "unionfs: no branches specified\n");
		err = -EINVAL;
		goto out;
	}
out:
	if (err) {
		for (i = 0; i < branches; i++)
			path_put(&lower_root_info->lower_paths[i]);
		kfree(lower_root_info->lower_paths);
		kfree(WRAPFS_SB(sb)->data);
		/*
		 * MUST clear the pointers to prevent potential double free if
		 * the caller dies later on
		 */
		lower_root_info->lower_paths = NULL;
		WRAPFS_SB(sb)->data = NULL;
	}
out_return:
	return err;
}

static struct wrapfs_dentry_info *wrapfs_parse_options(
					struct super_block *sb,
					char *options)
{
	struct wrapfs_dentry_info *lower_root_info;
	int err = 0;
	/* allocate private data area */
	err = -ENOMEM;
	lower_root_info =
		kzalloc(sizeof(struct wrapfs_dentry_info), GFP_KERNEL);
	if (unlikely(!lower_root_info))
		goto out_error;
	lower_root_info->bopaque = -1;
	err = parse_dirs_option(sb, lower_root_info, options);
	if (err)
		goto out_error;
	goto out;
out_error:
	kfree(lower_root_info->lower_paths);
	kfree(lower_root_info);
	kfree(WRAPFS_SB(sb)->data);
	WRAPFS_SB(sb)->data = NULL;
	lower_root_info = ERR_PTR(err);
out:
	return lower_root_info;
}

static int wrapfs_read_super(struct super_block *sb, void *raw_data, int silent)
{
	int err = 0;
	struct wrapfs_dentry_info *lower_root_info = NULL;
	int bindex;
	struct inode *inode = NULL;
	if (!raw_data) {
		printk(KERN_ERR
			"u2fs: read_super: missing data argument\n");
			err = -EINVAL;
			goto out;
	}
	sb->s_fs_info = kzalloc(sizeof(struct wrapfs_sb_info), GFP_KERNEL);
	if (unlikely(!WRAPFS_SB(sb))) {
		printk(KERN_CRIT "u2fs: read_super: out of memory\n");
		err = -ENOMEM;
		goto out;
	}
	lower_root_info = wrapfs_parse_options(sb, raw_data);
		if (IS_ERR(lower_root_info)) {
			printk(KERN_ERR
				"u2fs: read_super: error while parsing options "
				"(err = %ld)\n", PTR_ERR(lower_root_info));
		err = PTR_ERR(lower_root_info);
		lower_root_info = NULL;
		goto out_free;
	}
/* set the lower superblock field of upper superblock */
	for (bindex = 0; bindex <= 1; bindex++) {
		struct dentry *d = lower_root_info->lower_paths[bindex].dentry;
		wrapfs_set_lower_super_idx(sb, bindex, d->d_sb);
	}
	/* max Bytes is the maximum bytes from highest priority branch */
	sb->s_maxbytes = wrapfs_lower_super_idx(sb, 0)->s_maxbytes;
	/* get a new inode and allocate our root dentry */
	inode = wrapfs_iget_new(sb,
			lower_root_info->lower_paths[0].dentry->d_inode, 0);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		goto out_dput;
	}
	inode->i_mode = S_IFDIR | 0755;
	sb->s_root = d_alloc_root(inode);
	if (unlikely(!sb->s_root)) {
		err = -ENOMEM;
		goto out_iput;
	}
	d_set_d_op(sb->s_root, &wrapfs_dops);
	/* link the upper and lower dentries */
	sb->s_root->d_fsdata = NULL;
	err = new_dentry_private_data(sb->s_root);
	if (unlikely(err))
		goto out_freedpd;
	for (bindex = 0; bindex <= 1; bindex++) {
			struct dentry *d;
			struct vfsmount *m;
			d = lower_root_info->lower_paths[bindex].dentry;
			m = lower_root_info->lower_paths[bindex].mnt;
			wrapfs_set_lower_dentry_idx(sb->s_root, bindex, d);
			wrapfs_set_lower_mnt_idx(sb->s_root, bindex, m);
	 }
	wrapfs_fill_inode(sb->s_root, inode);
	d_rehash(sb->s_root);
	goto out;
out_freedpd:
	if (WRAPFS_D(sb->s_root)) {
		kfree(WRAPFS_D(sb->s_root)->lower_paths);
		free_dentry_private_data(sb->s_root);
	}
	dput(sb->s_root);
out_iput:
	iput(inode);
out_dput:
	if (lower_root_info && !IS_ERR(lower_root_info)) {
		kfree(lower_root_info->lower_paths);
		kfree(lower_root_info);
		lower_root_info = NULL;
	}
out_free:
	kfree(WRAPFS_SB(sb)->data);
	kfree(WRAPFS_SB(sb));
	sb->s_fs_info = NULL;
out:
	if (lower_root_info && !IS_ERR(lower_root_info)) {
		kfree(lower_root_info->lower_paths);
		kfree(lower_root_info);
	 }
	return err;
}

struct dentry *wrapfs_mount(struct file_system_type *fs_type, int flags,
			    const char *dev_name, void *raw_data)
{
	return mount_nodev(fs_type, flags, raw_data,
			   wrapfs_read_super);
}

static struct file_system_type wrapfs_fs_type = {
	.owner		= THIS_MODULE,
	.name		= WRAPFS_NAME,
	.mount		= wrapfs_mount,
	.kill_sb	= generic_shutdown_super,
	.fs_flags	= FS_REVAL_DOT,
};

static int __init init_wrapfs_fs(void)
{
	int err;

	err = wrapfs_init_inode_cache();
	if (err)
		goto out;
	err = wrapfs_init_dentry_cache();
	if (err)
		goto out;
	err = register_filesystem(&wrapfs_fs_type);
out:
	if (err) {
		wrapfs_destroy_inode_cache();
		wrapfs_destroy_dentry_cache();
	}
	return err;
}

static void __exit exit_wrapfs_fs(void)
{
	wrapfs_destroy_inode_cache();
	wrapfs_destroy_dentry_cache();
	unregister_filesystem(&wrapfs_fs_type);
	pr_info("Completed wrapfs module unload\n");
}

MODULE_AUTHOR("Erez Zadok, Filesystems and Storage Lab, Stony Brook University"
	      " (http://www.fsl.cs.sunysb.edu/)");
MODULE_DESCRIPTION("Wrapfs " WRAPFS_VERSION
		   " (http://wrapfs.filesystems.org/)");
MODULE_LICENSE("GPL");

module_init(init_wrapfs_fs);
module_exit(exit_wrapfs_fs);
