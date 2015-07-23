#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include <stdio.h>
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

/* Number of block types. Totals to
   126, where the remaining blocks
   are double indirect blocks */
#define DIRECT 98
#define INDIRECT 26

/* Max number of sectors that fit within
   inode's indirect blocks or the entire inode */
#define INDIRECT_MAX (INDIRECT*128 + DIRECT)
#define INODE_MAX (128*128 + INDIRECT_MAX)

/* Max number of sectors that may fit in an
   8 MB file system */
#define MAX_SECTORS 16000

/* inode_dist array contains 99 data blocks,
   26 indirect blocks, and 1 double indirect block */

/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk
  {
    block_sector_t sectors[125];        /* Array of sectors, indirect,
                                           and double indirect blocks */
    bool is_dir;
    off_t length;                       /* File size in bytes. */
    unsigned magic;                     /* Magic number. */
  };

struct indirect_block
  {
    block_sector_t sectors[128];        /* Array of sectors */
  };

struct double_indirect_block
  {
    block_sector_t sectors[128];        /* Array of indirect blocks */
  };

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t
bytes_to_sectors (off_t size)
{
  return DIV_ROUND_UP (size, BLOCK_SECTOR_SIZE);
}

/* In-memory inode. */
struct inode 
  {
    struct lock lock;
    struct list_elem elem;              /* Element in inode list. */
    block_sector_t sector;              /* Sector number of disk location. */
    int open_cnt;                       /* Number of openers. */
    bool removed;                       /* True if deleted, false otherwise. */
    int deny_write_cnt;                 /* 0: writes ok, >0: deny writes. */
    struct inode_disk data;             /* Inode content. */
  };

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t
byte_to_sector (const struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  off_t sec_num = pos / BLOCK_SECTOR_SIZE;
  block_sector_t ret;
  if (sec_num < DIRECT) {
    return inode->data.sectors[sec_num];
  } else if (sec_num < INDIRECT_MAX) {
    /* sector in indirect block */
    off_t indr_block_num = (sec_num - DIRECT) / 128;
    off_t indr_sec_num = (sec_num - DIRECT) % 128;
    block_sector_t indr_sector = inode->data.sectors[indr_block_num+DIRECT];
    struct indirect_block *indr;
    indr = calloc (1, sizeof *indr);
    block_read (fs_device, indr_sector, indr);
    ret = indr->sectors[indr_sec_num];
    free (indr);
    return ret;
  } else if (sec_num < INODE_MAX) {
    /* sector in double indirect block */
    return -1;
  } else {
    /* sector out of range */
    return -1;
  }

}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void
inode_init (void) 
{
  list_init (&open_inodes);
}

/* Allocate one sector from the free_map.
   Returns true if successful */
static bool
allocate_sector (block_sector_t *s)
{
  if (free_map_allocate (1, s))
    {
      static char zeros[BLOCK_SECTOR_SIZE];
      block_write (fs_device, *s, zeros);
      return true;
    }
  return false;
}

/* Allocate N sectors of an indirect block written
   to sector S */
static bool
allocate_indirect_block (block_sector_t *s, size_t n)
{
  ASSERT (n > 0);
  ASSERT (n <= 128);

  struct indirect_block *indr_blk = NULL;
  bool success = false;
  indr_blk = calloc (1, sizeof *indr_blk);
  if (indr_blk != NULL)
    {
      /* Allocate this indirect block */
      if (free_map_allocate (1, s))
        {
          /* Allocate the sectors of this block needed */
          size_t i;
          for (i = 0; i < 128; i++)
            indr_blk->sectors[i] = *s;
          success = true;
          for (i = 0; i < n; i++)
            {
              success = success && allocate_sector (&indr_blk->sectors[i]);
              if (!success)
                break;
            }
          block_write (fs_device, *s, indr_blk);
        }
    }
  free (indr_blk);

  return success;
}

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool
inode_create2 (block_sector_t sector, off_t length, bool dir)
{

  struct inode_disk *disk_inode = NULL;
  bool success = false;

  ASSERT (length >= 0);

  //printf ("inode_create, sector %u\n", sector);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT (sizeof *disk_inode == BLOCK_SECTOR_SIZE);
  ASSERT (sizeof (struct indirect_block) == BLOCK_SECTOR_SIZE);
  ASSERT (sizeof (struct double_indirect_block) == BLOCK_SECTOR_SIZE);

  disk_inode = calloc (1, sizeof *disk_inode);
  if (disk_inode != NULL)
    {
      size_t sectors = bytes_to_sectors (length);
      disk_inode->is_dir = dir;
      disk_inode->length = length;
      disk_inode->magic = INODE_MAGIC;

      /* Initialize all sector numbers to the disk_inode's
             such that any unused sector will retain that number */
      size_t i;
      for (i = 0; i < 125; i++)
        disk_inode->sectors[i] = sector;
         
      if (sectors > 0) 
        {
          size_t direct_sectors;
          if (sectors > DIRECT)
            direct_sectors = DIRECT;
          else
            direct_sectors = sectors;
          for (i = 0; i < direct_sectors; i++)
            {
              allocate_sector (&disk_inode->sectors[i]);
            }

          sectors -= direct_sectors;
          size_t indirect_sectors = (sectors > INDIRECT*128) ? INDIRECT*128 : sectors;
          size_t indirect_blocks;
          if (indirect_sectors % 128 == 0)
            indirect_blocks = indirect_sectors / 128;
          else
            indirect_blocks = (indirect_sectors / 128) + 1;
          for (i = 0; i < indirect_blocks; i++)
            {
              if (indirect_sectors >= 128) {
                allocate_indirect_block (&disk_inode->sectors[i+DIRECT], 128);
                indirect_sectors -= 128;
              } else {
                allocate_indirect_block (&disk_inode->sectors[i+DIRECT], indirect_sectors);
              }
            }
          sectors -= indirect_sectors;
        }

        block_write (fs_device, sector, disk_inode);

      /* do something similar for double_indirect_block */

      /* error handling needed; if any allocation returns false,
         release all allocated sectors */

      success = (sectors == 0);
      free (disk_inode);
    }
  return success;
}

bool
inode_create (block_sector_t sector, off_t length)
{
  return inode_create2 (sector, length, false);

}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode *
inode_open (block_sector_t sector)
{
  struct list_elem *e;
  struct inode *inode;

  /* Check whether this inode is already open. */
  for (e = list_begin (&open_inodes); e != list_end (&open_inodes);
       e = list_next (e)) 
    {
      inode = list_entry (e, struct inode, elem);
      if (inode->sector == sector) 
        {
          inode_reopen (inode);
          return inode; 
        }
    }

  /* Allocate memory. */
  inode = malloc (sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front (&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&inode->lock);
  block_read (fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode *
inode_reopen (struct inode *inode)
{
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t
inode_get_inumber (const struct inode *inode)
{
  return inode->sector;
}

/* Closes INODE and writes it to disk. (Does it?  Check code.)
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void
inode_close (struct inode *inode) 
{

  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  lock_acquire(&inode->lock);
  block_write (fs_device, inode->sector, &inode->data);

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0)
    {
      /* Remove from inode list and release lock. */
      list_remove (&inode->elem);
 
      /* Change this to free sectors one at a time based on
        the on the disk_inode's allocated blocks */
      /* Deallocate blocks if removed. */
      if (inode->removed) 
        {
          free_map_release (inode->sector, 1);
          off_t i, j;
          for (i = 0; i < DIRECT; i++) {
            if (inode->data.sectors[i] == inode->sector)
              break;
            free_map_release (inode->data.sectors[i], 1);
          }
          for (i = 0; i < INDIRECT; i++) {
            if (inode->data.sectors[i+DIRECT] == inode->sector)
              break;
            block_sector_t indr_sec = inode->data.sectors[i+DIRECT];
            struct indirect_block *indr;
            indr = calloc (1, sizeof *indr);
            block_read (fs_device, indr_sec, indr);
            for (j = 0; j < 128; j++) {
              if (indr->sectors[j] == indr_sec)
                break;
              free_map_release (indr->sectors[j], 1);
            }
            free (indr);
            free_map_release (inode->data.sectors[i+DIRECT], 1);
          }
        }
      lock_release(&inode->lock);
      free (inode); 
    } else {
      lock_release(&inode->lock);
    }

}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void
inode_remove (struct inode *inode) 
{
  ASSERT (inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t
inode_read_at (struct inode *inode, void *buffer_, off_t size, off_t offset) 
{
  ASSERT(inode != NULL);
  lock_acquire(&inode->lock);
  uint8_t *buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t *bounce = NULL;

  while (size > 0) 
    {
      /* Disk sector to read, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually copy out of this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Read full sector directly into caller's buffer. */
          block_read (fs_device, sector_idx, buffer + bytes_read);
        }
      else 
        {
          /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }
          block_read (fs_device, sector_idx, bounce);
          memcpy (buffer + bytes_read, bounce + sector_ofs, chunk_size);
        }
      
      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_read += chunk_size;
    }
  free (bounce);

  lock_release(&inode->lock);
  return bytes_read;
}

/* Grows the file if the identified sector has not
   been allocated */
static block_sector_t
byte_to_sector2 (struct inode *inode, off_t pos) 
{
  ASSERT (inode != NULL);
  off_t sec_num = pos / BLOCK_SECTOR_SIZE;
  block_sector_t ret;
  if (sec_num < DIRECT) {
    if (inode->data.sectors[sec_num] == inode->sector) {
      allocate_sector (&inode->data.sectors[sec_num]);
    }
    return inode->data.sectors[sec_num];
  } else if (sec_num < INDIRECT_MAX) {
    /* sector in indirect block */
    off_t indr_block_num = (sec_num - DIRECT) / 128;
    off_t indr_sec_num = (sec_num - DIRECT) % 128;
    if (inode->data.sectors[indr_block_num+DIRECT] == inode->sector) {
      allocate_indirect_block (&inode->data.sectors[indr_block_num+DIRECT], 1);
    }
    block_sector_t indr_sector = inode->data.sectors[indr_block_num+DIRECT];
    struct indirect_block *indr;
    indr = calloc (1, sizeof *indr);
    block_read (fs_device, indr_sector, indr);
    if (indr->sectors[indr_sec_num] == indr_sector) {
      allocate_sector (&indr->sectors[indr_sec_num]);
      block_write (fs_device, indr_sector, indr);
    }
    ret = indr->sectors[indr_sec_num];
    free (indr);
    return ret;
  } else if (sec_num < INODE_MAX) {
    /* sector in double indirect block */
    return -1;
  } else {
    /* sector out of range */
    return -1;
  }

}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t
inode_write_at (struct inode *inode, const void *buffer_, off_t size,
                off_t offset) 
{
  ASSERT(inode != NULL);
  lock_acquire(&inode->lock);
  const uint8_t *buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t *bounce = NULL;

  if (inode->deny_write_cnt) {
    lock_release(&inode->lock);
    return 0;
  }

  /* Fill space between EOF and start of this write
     with zeros */
  if (offset >= inode_length (inode)) {
    off_t i;
    for (i = inode_length(inode); i < offset; i+=BLOCK_SECTOR_SIZE) {
      byte_to_sector2 (inode, i);
    }
  }

  /* Update the inode's length if necessary */
  if (inode->data.length < (offset + size)) {
    inode->data.length = offset + size;
  }

  while (size > 0) 
    {
      /* Sector to write, starting byte offset within sector. */
      block_sector_t sector_idx = byte_to_sector2 (inode, offset);
      int sector_ofs = offset % BLOCK_SECTOR_SIZE;

      /* Bytes left in inode, bytes left in sector, lesser of the two. */
      off_t inode_left = inode_length (inode) - offset;
      int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
      int min_left = inode_left < sector_left ? inode_left : sector_left;

      /* Number of bytes to actually write into this sector. */
      int chunk_size = size < min_left ? size : min_left;
      if (chunk_size <= 0)
        break;

      if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE)
        {
          /* Write full sector directly to disk. */
          block_write (fs_device, sector_idx, buffer + bytes_written);
        }
      else 
        {
          /* We need a bounce buffer. */
          if (bounce == NULL) 
            {
              bounce = malloc (BLOCK_SECTOR_SIZE);
              if (bounce == NULL)
                break;
            }

          /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
          if (sector_ofs > 0 || chunk_size < sector_left) 
            block_read (fs_device, sector_idx, bounce);
          else
            memset (bounce, 0, BLOCK_SECTOR_SIZE);
          memcpy (bounce + sector_ofs, buffer + bytes_written, chunk_size);
          block_write (fs_device, sector_idx, bounce);
        }

      /* Advance. */
      size -= chunk_size;
      offset += chunk_size;
      bytes_written += chunk_size;
    }
  free (bounce);

  lock_release(&inode->lock);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void
inode_deny_write (struct inode *inode) 
{
  inode->deny_write_cnt++;
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void
inode_allow_write (struct inode *inode) 
{
  ASSERT (inode->deny_write_cnt > 0);
  ASSERT (inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t
inode_length (const struct inode *inode)
{
  return inode->data.length;
}

bool
inode_is_dir (const struct inode *inode)
{
  return (int) inode->data.is_dir;
}

int
inode_open_cnt (const struct inode *inode)
{
  return (int) inode->open_cnt;
}

int
inode_number (const struct inode *inode)
{
  return (int) inode->sector;
}
