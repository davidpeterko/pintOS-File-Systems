#ifndef FILESYS_FILESYS_H
#define FILESYS_FILESYS_H

#include <stdbool.h>
#include "filesys/off_t.h"

/* Sectors of system file inodes. */
#define FREE_MAP_SECTOR 0       /* Free map file inode sector. */
#define ROOT_DIR_SECTOR 1       /* Root directory file inode sector. */

struct dir;

/* Block device that contains the file system. */
struct block *fs_device;

void filesys_init (bool format);
void filesys_done (void);
bool filesys_create (const char *name, off_t initial_size);
bool filesys_create2 (const char *name, off_t initial_size, struct dir *dir);
struct file *filesys_open (const char *name);
struct file *filesys_open2 (const char *name, struct dir *dir);
bool filesys_remove (const char *name);
bool filesys_remove2 (const char *name, struct dir *dir);

#endif /* filesys/filesys.h */
