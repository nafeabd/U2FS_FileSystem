
Author : Nafees Ahmed Abdul

Included:
file.c,inode.c,copyup.c,wrapfs.h,lookup.c,super.c,main.c,Makefile,dentry.c

Purpose:
u2fs is a stackable, fan-out, unification file system.
which takes two branches - left branch(LB) and right branch (RB)
and while mounting it combines these two branches and
presents them as a single branch to the user.

Here LB has higher priority than RB and LB had R/W permissions where as
RB had just READ permissions.

                u2fs
                 /\
                /  \
               /    \
             LB      RB

Here the files in LB and RB will physically be staying in the same underlying
location as they were before. The advantage of u2fs is that we can keep the
underlying directories separate, which is convenient for software management
as well as Live-CDs, but at the same time provide a convenient merged view
of the two directories to users.


Approach and Declarations:

u2fs was developed on top of wrapfs which is a stackable file system when
we have a single lower branch. I borrowed many functionalities from other 
stackable file system which is called unionfs.

I have used may components of unionfs while coding my project.

u2fs was coded by taking the existing wrapfs code and adding functionalities of u2fs
in an incremental way.

Inode numbers for the files in u2fs will be generated as in wrapfs , which generally
follows by assigning lower parent inodes to the created ones in wrapfs layer.
We can create/edit the files in filesystem by using any of the file manipulation commands
like touch, echo, vim etc
The new files created will be physically created in the LB (as RB has just Read permissions).

If we try to create a new file inside the directory of RB then the new file will be created
in the LB replacing the existing file in the RB in u2fs. This is called copyup operation.

And if we try to delete a file in the RB then the file will be marked as whiteout and it
will not be visible to the user in u2fs.

File manipulations in LB will work in a normal way as in any filesytem.

USAGE :
-------

Mounting:       
mount -t u2fs -o ldir=/tmp/left,rdir=/tmp/right null /mnt/u2fs

and by cd to respective /mnt/u2fs we can perform file operations
Umounting:      
umount /mnt/u2fs

where '/mnt/u2fs' is the mount point and 'ldir=/tmp/left,rdir=tmp/right'
are the two directories 'ldir' and 'rdir' which are to be combined and mounted
in new file system.

Here the device name will be 'null' and we pass the directories as options to
'mount' command which will parse the options and then pass the directories to
the file system.

All general commands of file system can be used directly here


Validations:
	Appropriate validations are done as in wrapfs and unionfs at right places.
	
Compiling and executing :
------------------------
Below are the basic steps:

'make' will compile and create the 'img' file for the files system which is a loadable module.
'insmod ./fs/wrapfs/wrapfs.ko' will insert this module.
And then we can mount the u2fs and use it.
'rmmod wrapfs' will remove the module.	


