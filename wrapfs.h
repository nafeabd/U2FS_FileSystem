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

#ifndef _WRAPFS_H_
#define _WRAPFS_H_

#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/mm.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/seq_file.h>
#include <linux/statfs.h>
#include <linux/fs_stack.h>
#include <linux/magic.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/sched.h>

/* the file system name */
#define WRAPFS_NAME "u2fs"

/* wrapfs root inode number */
#define WRAPFS_ROOT_INO     1

/* useful for tracking code reachability */
#define UDBG printk(KERN_DEFAULT "DBG:%s:%s:%d\n", __FILE__, __func__, __LINE__)


/* dentry to private data */
#define WRAPFS_D(dent) ((struct wrapfs_dentry_info *)(dent)->d_fsdata)

/* superblock to private data */
#define WRAPFS_SB(super) ((struct wrapfs_sb_info *)(super)->s_fs_info)

/* file to private Data */
#define WRAPFS_F(file) ((struct wrapfs_file_info *)((file)->private_data))

/* Macros for locking a dentry. */
enum wrapfs_dentry_lock_class {
	WRAPFS_DMUTEX_NORMAL,
	WRAPFS_DMUTEX_ROOT,
	WRAPFS_DMUTEX_PARENT,
	WRAPFS_DMUTEX_CHILD,
	WRAPFS_DMUTEX_WHITEOUT,
	WRAPFS_DMUTEX_REVAL_PARENT, /* for file/dentry revalidate */
	WRAPFS_DMUTEX_REVAL_CHILD,   /* for file/dentry revalidate */
};
/* operations vectors defined in specific files */
extern const struct file_operations wrapfs_main_fops;
extern const struct file_operations wrapfs_dir_fops;
extern const struct inode_operations wrapfs_main_iops;
extern const struct inode_operations wrapfs_dir_iops;
extern const struct inode_operations wrapfs_symlink_iops;
extern const struct super_operations wrapfs_sops;
extern const struct dentry_operations wrapfs_dops;
extern const struct address_space_operations wrapfs_aops, wrapfs_dummy_aops;
extern const struct vm_operations_struct wrapfs_vm_ops;

extern int wrapfs_init_inode_cache(void);
extern void wrapfs_destroy_inode_cache(void);
extern int wrapfs_init_dentry_cache(void);
extern void wrapfs_destroy_dentry_cache(void);
extern int new_dentry_private_data(struct dentry *dentry);
extern void free_dentry_private_data(struct dentry *dentry);
extern struct dentry *wrapfs_lookup(struct inode *dir, struct dentry *dentry,
				    struct nameidata *nd);
extern struct inode *wrapfs_iget(struct super_block *sb,
				struct inode *lower_inode);
extern int wrapfs_interpose(struct dentry *dentry, struct super_block *sb,
			struct path *lower_path, int index);
extern struct inode *wrapfs_iget_new(struct super_block *sb,
				struct inode *lower_inode, int index);
/* copies a file from dbstart to newbindex branch */
extern int copyup_file(struct inode *dir, struct file *file, int bstart,
			int newbindex, loff_t size);
extern int copyup_named_file(struct inode *dir, struct file *file,
				char *name, int bstart, int new_bindex,
				loff_t len);
/* copies a dentry from dbstart to newbindex branch */
extern int copyup_dentry(struct inode *dir, struct dentry *dentry,
			int bstart, int new_bindex, const char *name,
			int namelen, struct file **copyup_file, loff_t len);
/* helper functions for post-copyup actions */
extern void wrapfs_postcopyup_setmnt(struct dentry *dentry);
extern void wrapfs_postcopyup_release(struct dentry *dentry);

struct wrapfs_file_info {
		const struct vm_operations_struct *lower_vm_ops;
		atomic_t generation;
		struct file **lower_files;
};

struct wrapfs_data {
	struct super_block *sb; /* lower super_block */
	atomic_t open_files;    /* number of open files on branch */
	int branchperms;
	int branch_id;          /* unique branch ID at re/mount time */
};

struct wrapfs_inode_info {
			atomic_t generation;
			struct inode **lower_inodes;
			struct inode vfs_inode;
};

struct wrapfs_dentry_info {
		spinlock_t lock;
		int bopaque;
		atomic_t generation;
		struct path *lower_paths;
};

struct wrapfs_sb_info {
	atomic_t generation;
	int high_branch_id;
	struct wrapfs_data *data;
};

/*
 * inode to private data
 *
 * Since we use containers and the struct inode is _inside_ the
 * wrapfs_inode_info structure, WRAPFS_I will always (given a non-NULL
 * inode pointer), return a valid non-NULL pointer.
 */
static inline struct wrapfs_inode_info *WRAPFS_I(const struct inode *inode)
{
	return container_of(inode, struct wrapfs_inode_info, vfs_inode);
}

static inline struct file *wrapfs_lower_file(const struct file *f)
{
	BUG_ON(!f);
	return WRAPFS_F(f)->lower_files[0];
}

static inline void wrapfs_set_lower_file_idx(struct file *f, int index,
						struct file *val)
{
	BUG_ON(!f || index < 0);
	WRAPFS_F(f)->lower_files[index] = val;
}

static inline void wrapfs_set_lower_file(struct file *f, struct file *val)
{
	wrapfs_set_lower_file_idx((f), 0, (val));
}


/* inode to lower inode. */
static inline struct inode *wrapfs_lower_inode(const struct inode *i)
{
	return WRAPFS_I(i)->lower_inodes[0];
}
static inline struct inode *wrapfs_lower_inode_idx(const struct inode *i,
							 int index)
{
	return WRAPFS_I(i)->lower_inodes[index];
}
static inline void wrapfs_set_lower_inode(struct inode *i, struct inode *val)
{
	WRAPFS_I(i)->lower_inodes[0] = val;
}

/* superblock to lower superblock */
static inline struct super_block *wrapfs_lower_super(
	const struct super_block *sb)
{
	return WRAPFS_SB(sb)->data[0].sb;
}
static inline void wrapfs_set_lower_super_idx(struct super_block *sb,
						int index,
						struct super_block *val)
{
	BUG_ON(!sb || index < 0);
	WRAPFS_SB(sb)->data[index].sb = val;
}
static inline struct super_block *wrapfs_lower_super_idx(
					const struct super_block *sb,
							int index)
{
	BUG_ON(!sb || index < 0);
	return WRAPFS_SB(sb)->data[index].sb;
}
static inline void wrapfs_set_lower_dentry_idx(struct dentry *dent, int index,
						struct dentry *val)
{
	BUG_ON(!dent || index < 0);
	WRAPFS_D(dent)->lower_paths[index].dentry = val;
}

static inline void wrapfs_set_lower_super(struct super_block *sb,
					  struct super_block *val)
{
	 WRAPFS_SB(sb)->data[0].sb = val;
}

/* path based (dentry/mnt) macros */
static inline void pathcpy(struct path *dst, const struct path *src)
{
	dst->dentry = src->dentry;
	dst->mnt = src->mnt;
}
/* Returns struct path.  Caller must path_put it. */
static inline void wrapfs_get_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&WRAPFS_D(dent)->lock);
	pathcpy(lower_path, &WRAPFS_D(dent)->lower_paths[0]);
	path_get(lower_path);
	spin_unlock(&WRAPFS_D(dent)->lock);
	return;
}
static inline struct dentry *lock_parent_wh(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	mutex_lock_nested(&dir->d_inode->i_mutex, WRAPFS_DMUTEX_WHITEOUT);
	return dir;
}
static inline void wrapfs_get_lower_path_idx(const struct dentry *dent,
					 struct path *lower_path, int index)
{
	spin_lock(&WRAPFS_D(dent)->lock);
	pathcpy(lower_path, &WRAPFS_D(dent)->lower_paths[index]);
	path_get(lower_path);
	spin_unlock(&WRAPFS_D(dent)->lock);
	return;
}
static inline void wrapfs_put_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	return;
}
static inline void branchget(struct super_block *sb, int index)
{
	BUG_ON(!sb || index < 0);
	atomic_inc(&WRAPFS_SB(sb)->data[index].open_files);
}

static inline void branchput(struct super_block *sb, int index)
{
	BUG_ON(!sb || index < 0);
	atomic_dec(&WRAPFS_SB(sb)->data[index].open_files);
}
static inline void wrapfs_set_lower_path(const struct dentry *dent,
					 struct path *lower_path)
{
	spin_lock(&WRAPFS_D(dent)->lock);
	pathcpy(&WRAPFS_D(dent)->lower_paths[0], lower_path);
	spin_unlock(&WRAPFS_D(dent)->lock);
	return;
}
static inline void wrapfs_set_lower_path_idx(const struct dentry *dent,
					 struct path *lower_path, int index)
{
	spin_lock(&WRAPFS_D(dent)->lock);
	pathcpy(&WRAPFS_D(dent)->lower_paths[index], lower_path);
	spin_unlock(&WRAPFS_D(dent)->lock);
	return;
}
static inline void wrapfs_reset_lower_path(const struct dentry *dent)
{
	spin_lock(&WRAPFS_D(dent)->lock);
	WRAPFS_D(dent)->lower_paths[0].dentry = NULL;
	WRAPFS_D(dent)->lower_paths[0].mnt = NULL;
		spin_unlock(&WRAPFS_D(dent)->lock);
	return;
}
static inline void wrapfs_put_reset_lower_path(const struct dentry *dent)
{
	struct path lower_path;
	spin_lock(&WRAPFS_D(dent)->lock);
	pathcpy(&lower_path, &WRAPFS_D(dent)->lower_paths[0]);
	WRAPFS_D(dent)->lower_paths[0].dentry = NULL;
	WRAPFS_D(dent)->lower_paths[0].mnt = NULL;
	spin_unlock(&WRAPFS_D(dent)->lock);
	path_put(&lower_path);
	return;
}
static inline void wrapfs_put_reset_lower_path_idx(const struct dentry *dent,
							int index)
{
	struct path lower_path;
	spin_lock(&WRAPFS_D(dent)->lock);
	pathcpy(&lower_path, &WRAPFS_D(dent)->lower_paths[index]);
	WRAPFS_D(dent)->lower_paths[index].dentry = NULL;
	WRAPFS_D(dent)->lower_paths[index].mnt = NULL;
	spin_unlock(&WRAPFS_D(dent)->lock);
	path_put(&lower_path);
	return;
}

/* locking helpers */
static inline struct dentry *lock_parent(struct dentry *dentry)
{
	struct dentry *dir = dget_parent(dentry);
	mutex_lock_nested(&dir->d_inode->i_mutex, I_MUTEX_PARENT);
	return dir;
}
static inline int set_branchperms(struct super_block *sb, int index, int perms)
{
	BUG_ON(index < 0);
	WRAPFS_SB(sb)->data[index].branchperms = perms;
	return perms;
}
static inline void set_branch_count(struct super_block *sb, int index, int val)
{
	BUG_ON(!sb || index < 0);
	atomic_set(&WRAPFS_SB(sb)->data[index].open_files, val);
}
static inline void wrapfs_set_lower_mnt_idx(struct dentry *dent, int index,
						struct vfsmount *mnt)
{
	BUG_ON(!dent || index < 0);
	WRAPFS_D(dent)->lower_paths[index].mnt = mnt;
}
static inline void set_branch_id(struct super_block *sb, int index, int val)
{
	BUG_ON(!sb || index < 0);
	WRAPFS_SB(sb)->data[index].branch_id = val;
}
static inline void new_branch_id(struct super_block *sb, int index)
{
	BUG_ON(!sb || index < 0);
	set_branch_id(sb, index, ++WRAPFS_SB(sb)->high_branch_id);
}
static inline void wrapfs_set_lower_inode_idx(struct inode *i, int index,
						struct inode *val)
{
	BUG_ON(!i || index < 0);
	WRAPFS_I(i)->lower_inodes[index] = val;
}
static inline struct dentry *wrapfs_lower_dentry_idx(
				const struct dentry *dent,
						int index)
{
	BUG_ON(!dent || index < 0);
	return WRAPFS_D(dent)->lower_paths[index].dentry;
}
static inline struct vfsmount *wrapfs_lower_mnt_idx(
					const struct dentry *dent,
					int index)
{
	BUG_ON(!dent || index < 0);
	return WRAPFS_D(dent)->lower_paths[index].mnt;
}
static inline struct file *wrapfs_lower_file_idx(const struct file *f,
						  int index)
{
	BUG_ON(!f || index < 0);
	return WRAPFS_F(f)->lower_files[index];
}
static inline void unlock_dir(struct dentry *dir)
{
	mutex_unlock(&dir->d_inode->i_mutex);
	dput(dir);
}
static inline struct dentry *lookup_lck_len(const char *name,
					struct dentry *base, int len)
{
	struct dentry *d;
	d = lookup_one_len(name, base, len);
	return d;
}

#endif	/* not _WRAPFS_H_ */
