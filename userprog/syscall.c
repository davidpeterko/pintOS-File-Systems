#include "userprog/syscall.h"
#include <stdio.h>
#include <string.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "filesys/free-map.h"
#include "filesys/filesys.h"
#include "filesys/directory.h"

#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "devices/shutdown.h"
#include "devices/input.h"


#define BUF_MAX 200

static void relative_to_absolute (const char *, char *);
static bool valid_mem_access (const void *);
static void syscall_handler (struct intr_frame *);
static void userprog_halt (void);
static void userprog_exit (int);
static pid_t userprog_exec (const char *);
static int userprog_wait (pid_t);
static bool userprog_create (const char *, unsigned);
static bool userprog_remove (const char *);
static int userprog_open (const char *);
static int userprog_filesize (int);
static int userprog_read (int, void *, unsigned);
static int userprog_write (int, const void *, unsigned);
static void userprog_seek (int, unsigned);
static unsigned userprog_tell (int);
static void userprog_close (int);
static bool userprog_chdir (const char *);
static bool userprog_mkdir (const char *);
static bool userprog_readdir (int, char *);
static bool userprog_isdir (int);
static int userprog_inumber (int);
static struct openfile * getFile (int);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
  lock_init (&filesys_lock);
}

static void
relative_to_absolute (const char *relative, char *buffer)
{
  printf("rtoa cur dir: %s\n", thread_current()->path);

  if (*relative == '/') {
    strlcpy (buffer, relative, strlen(relative)+1);
    return;
  }

  int i = 0;
  int j = 0;
  int k = 0;
  char *token, *save_ptr;
  char **rel_tokens = (char **)malloc(sizeof(char)*512);
  char **cur_tokens = (char **)malloc(sizeof(char)*512);

  char *rel_copy = (char *)malloc(sizeof(char)*512);
  char *cur_copy = (char *)malloc(sizeof(char)*512);

  /* Tokenize the relative path and process' current path */
  strlcpy (rel_copy, relative, strlen(relative)+1);
  for (token = strtok_r (rel_copy, "/", &save_ptr); token != NULL;
        token = strtok_r (NULL, "/", &save_ptr)) {
    rel_tokens[i] = token;
    i++;
  }

  strlcpy (cur_copy, thread_current()->path, strlen(thread_current()->path)+1);
  for (token = strtok_r (cur_copy, "/", &save_ptr); token != NULL;
        token = strtok_r (NULL, "/", &save_ptr)) {
    cur_tokens[j] = token;
    j++;
  }

  /* Change cur_tokens to hold the absolute path */
  for (k = 0; k < i; k++) {
    if (strcmp(rel_tokens[k], ".") == 0){
    } else if (strcmp(rel_tokens[k], "..") == 0) {
      if (j > 0) {
        cur_tokens[j-1] = NULL;
        j--;
      }
    } else {
      cur_tokens[j] = rel_tokens[k];
      j++;
    }
  }

  /* Copy the absolute path into BUFFER */
  if (j == 0) {
    strlcpy (buffer, "/", 2);
  } else {
    strlcpy (buffer, "", 1);
    for (k = 0; k < j; k++) {
      strlcat (buffer, "/", strlen(buffer)+2);
      strlcat (buffer, cur_tokens[k], strlen(buffer)+strlen(cur_tokens[k])+1);
    }
  }

  printf("rtoa cur dir2: %s\n", thread_current()->path);

  free (rel_tokens);
  free (cur_tokens);
  free (rel_copy);
  free (cur_copy);
}

/* Verify that the user pointer is valid */
static bool
valid_mem_access (const void *up)
{
	struct thread *t = thread_current ();

	if (up == NULL)
		return false;
  if (is_kernel_vaddr (up))
    return false;
  if (pagedir_get_page (t->pagedir, up) == NULL)
   	return false;
  
	return true;
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  void *esp = f->esp;
  uint32_t *eax = &f->eax;
  int syscall_num;

  if(!valid_mem_access ( ((int *) esp) ))
    userprog_exit (-1);
  if(!valid_mem_access ( ((int *) esp)+1 ))
    userprog_exit (-1);
  syscall_num = *((int *) esp);

  switch (syscall_num) {
  	case 0:
  	  userprog_halt ();
  	  break;
  	case 1:
  	{
  	  int status = *(((int *) esp) + 1);
  	  userprog_exit (status);
  	  break;
  	}
  	case 2:
  	{
  	  const char *cmd_line = *(((char **) esp) + 1);
  	  *eax = (uint32_t) userprog_exec (cmd_line);
  	  break;
  	}
  	case 3:
  	{
  	  pid_t pid = *(((pid_t *) esp) + 1);
  	  *eax = (uint32_t) userprog_wait (pid);
  	  break;
  	}
  	case 4:
  	{
  	  const char *file = *(((char **) esp) + 1);
  	  unsigned initial_size = *(((unsigned *) esp) + 2);
  	  *eax = (uint32_t) userprog_create (file, initial_size);
  	  break;
  	}
  	case 5:
  	{
  	  const char *file = *(((char **) esp) + 1);
  	  *eax = (uint32_t) userprog_remove (file);
  	  break;
  	}
  	case 6:
  	{
  	  const char *file = *(((char **) esp) + 1);
  	  *eax = (uint32_t) userprog_open (file);
  	  break;
  	}
  	case 7:
  	{
  	  int fd = *(((int *) esp) + 1);
  	  *eax = (uint32_t) userprog_filesize (fd);
  	  break;
  	}
  	case 8:
  	{
  	  int fd = *(((int *) esp) + 1);
  	  void *buffer = (void *) *(((int **) esp) + 2);
  	  unsigned size = *(((unsigned *) esp) + 3);
  	  *eax = (uint32_t) userprog_read (fd, buffer, size);
  	  break;
  	}
  	case 9:
  	{
  	  int fd = *(((int *) esp) + 1);
  	  const void *buffer = (void *) *(((int **) esp) + 2);
  	  unsigned size = *(((unsigned *) esp) + 3);
  	  *eax = (uint32_t) userprog_write (fd, buffer, size);
  	  break;
  	}
  	case 10:
  	{
  	  int fd = *(((int *) esp) + 1);
  	  unsigned position = *(((unsigned *) esp) + 2);
  	  userprog_seek (fd, position);
  	  break;
  	}
  	case 11:
  	{
  	  int fd = *(((int *) esp) + 1);
  	  *eax = (uint32_t) userprog_tell (fd);
  	  break;
  	}
  	case 12:
  	{
  	  int fd = *(((int *) esp) + 1);
  	  userprog_close (fd);
  	  break;
  	}
    case 13:
    {
      /* MMAP */
      break;
    }
    case 14:
    {
      /* MUNMAP */
      break;
    }
    case 15:
    {
      void *dir = (char *) *(((int **) esp) + 1);
      *eax = (uint32_t) userprog_chdir (dir);
      break;
    }
    case 16:
    {
      void *dir = (char *) *(((int **) esp) + 1);
      *eax = (uint32_t) userprog_mkdir (dir);
      break;
    }
    case 17:
    {
      int fd = *(((int *) esp) + 1);
      void *name = (char *) *(((int **) esp) + 2);
      *eax = (uint32_t) userprog_readdir (fd, name);
      break;
    }
    case 18:
    {
      int fd = *(((int *) esp) + 1);
      *eax = (uint32_t) userprog_isdir (fd);
      break;
    }
    case 19:
    {
      int fd = *(((int *) esp) + 1);
      *eax = (uint32_t) userprog_inumber (fd);
      break;
    }
  }
}

static void
userprog_halt ()
{
	shutdown_power_off ();
}

static void
userprog_exit (int status)
{
  struct thread *cur = thread_current ();
  cur->exit_status = status;
	thread_exit ();
}

static pid_t
userprog_exec (const char *cmd_line)
{
  tid_t child_tid = TID_ERROR;

  if(!valid_mem_access(cmd_line))
    userprog_exit (-1);

  child_tid = process_execute (cmd_line);

	return child_tid;
}

static int
userprog_wait (pid_t pid)
{
  return process_wait (pid);
}

static bool
userprog_create (const char *file, unsigned initial_size)
{
  if (!valid_mem_access(file))
    userprog_exit (-1);

  bool ret = true;
  int i, j;
  char *token, *save_ptr;
  struct dir *parent;
  struct inode *inode;
  char **tokens = (char **)malloc(sizeof(char)*512);
  char *absolute = (char *)malloc(sizeof(char)*512);
  relative_to_absolute (file, absolute);
  printf("Create: %s\n", absolute);
  printf("currentdir: %s\n", thread_current()->path);

  i = 0;
  for (token = strtok_r (absolute, "/", &save_ptr); token != NULL;
        token = strtok_r (NULL, "/", &save_ptr)) {
    tokens[i] = token;
    i++;
  }
  i--;

  if (tokens[i] == NULL) {
    /* Not a valid file name */
    free (tokens);  
    free (absolute);
    return false;
  }

  parent = dir_open_root ();
  for (j = 0; j < i; j++) {
    if(!dir_lookup (parent, tokens[j], &inode)) {
      ret = false;
      break;
    }
    dir_close (parent);
    parent = dir_open (inode);
  }
  if (ret) {
    lock_acquire (&filesys_lock);
    ret = filesys_create2 (tokens[i], initial_size, parent);
    lock_release (&filesys_lock);
  }

  dir_close (parent);

  free (tokens);  
  free (absolute);
  return ret;
}

static bool
userprog_remove (const char *file)
{
  printf("Remove\n");
  printf("currentdir: %s\n", thread_current()->path);
  if (!valid_mem_access(file))
    userprog_exit (-1);

  bool ret = true;
  int i, j;
  char *token, *save_ptr;
  struct dir *parent;
  struct inode *inode;
  char **tokens = (char **)malloc(sizeof(char)*512);
  char *absolute = (char *)malloc(sizeof(char)*512);
  relative_to_absolute (file, absolute);

  i = 0;
  for (token = strtok_r (absolute, "/", &save_ptr); token != NULL;
        token = strtok_r (NULL, "/", &save_ptr)) {
    tokens[i] = token;
    i++;
  }
  i--;

  if (tokens[i] == NULL) {
    /* Not a valid file name */
    free (tokens);  
    free (absolute);
    return false;
  }

  parent = dir_open_root ();
  for (j = 0; j < i; j++) {
    if(!dir_lookup (parent, tokens[j], &inode)) {
      ret = false;
      break;
    }
    dir_close (parent);
    parent = dir_open (inode);
  }
  if (ret) {
    lock_acquire (&filesys_lock);
    ret = filesys_remove2 (tokens[i], parent);
    lock_release (&filesys_lock);
  }

  dir_close (parent);

  free (tokens);  
  free (absolute);
  return ret;
}

static int
userprog_open (const char *file)
{
  if (!valid_mem_access(file))
    userprog_exit (-1);

  bool ret = true;
  int i, j;
  char *token, *save_ptr;
  struct dir *parent;
  struct inode *inode;
  char **tokens = (char **)malloc(sizeof(char)*512);
  char *absolute = (char *)malloc(sizeof(char)*512);
  printf("\tCurrent dir: %s\n", thread_current()->path);
  relative_to_absolute (file, absolute);
  printf("Open %s, %s\n", file, absolute);
  printf("\tCurrent dir: %s\n", thread_current()->path);

  i = 0;
  for (token = strtok_r (absolute, "/", &save_ptr); token != NULL;
        token = strtok_r (NULL, "/", &save_ptr)) {
    tokens[i] = token;
    i++;
  }
  i--;

  if (tokens[i] == NULL) {
    /* Root */
    struct openfile *new = palloc_get_page (0);
    new->fd = thread_current ()->next_fd;
    thread_current ()->next_fd++;
    new->file = (struct file *) dir_open_root ();
    if (new->file == NULL) {
      palloc_free_page (new);
      free (tokens);  
      free (absolute);
      return -1;
    }
    new->is_dir = file_is_dir (new->file);
    list_push_back(&thread_current ()->openfiles, &new->elem);
    free (tokens);  
    free (absolute);
    return new->fd;
  }

  parent = dir_open_root ();
  for (j = 0; j < i; j++) {
    if(!dir_lookup (parent, tokens[j], &inode)) {
      ret = false;
      break;
    }
    dir_close (parent);
    parent = dir_open (inode);
  }
  if (ret) {
    struct openfile *new = palloc_get_page (0);
    new->fd = thread_current ()->next_fd;
    thread_current ()->next_fd++;
    lock_acquire (&filesys_lock);
    new->file = filesys_open2(tokens[i], parent);
    lock_release (&filesys_lock);
    if (new->file == NULL) {
      palloc_free_page (new);
      dir_close (parent);
      free (tokens);  
      free (absolute);
      return -1;
    }
    new->is_dir = file_is_dir (new->file);
    list_push_back(&thread_current ()->openfiles, &new->elem);
    dir_close (parent);
    free (tokens);  
    free (absolute);
    return new->fd;
  }

  dir_close (parent);

  free (tokens);  
  free (absolute);
  return -1;
}

static int
userprog_filesize (int fd)
{
  int retval;
  struct openfile *of = NULL;
	of = getFile (fd);
  if (of == NULL)
    return 0;
  lock_acquire (&filesys_lock);
  retval = file_length (of->file);
  lock_release (&filesys_lock);
  return retval;
}

static int
userprog_read (int fd, void *buffer, unsigned size)
{
  int bytes_read = 0;
  char *bufChar = NULL;
  struct openfile *of = NULL;
	if (!valid_mem_access(buffer))
    userprog_exit (-1);
  bufChar = (char *)buffer;
	if(fd == 0) {
    while(size > 0) {
      input_getc();
      size--;
      bytes_read++;
    }
    return bytes_read;
  }
  else {
    of = getFile (fd);
    if (of == NULL)
      return -1;
    lock_acquire (&filesys_lock);
    bytes_read = file_read (of->file, buffer, size);
    lock_release (&filesys_lock);
    return bytes_read;
  }
}

static int
userprog_write (int fd, const void *buffer, unsigned size)
{
  int bytes_written = 0;
  char *bufChar = NULL;
  struct openfile *of = NULL;
	if (!valid_mem_access(buffer))
		userprog_exit (-1);
  bufChar = (char *)buffer;
  if(fd == 1) {
    /* break up large buffers */
    while(size > BUF_MAX) {
      putbuf(bufChar, BUF_MAX);
      bufChar += BUF_MAX;
      size -= BUF_MAX;
      bytes_written += BUF_MAX;
    }
    putbuf(bufChar, size);
    bytes_written += size;
    return bytes_written;
  }
  else {
    of = getFile (fd);
    if (of == NULL)
      return 0;
    if (of->is_dir) {
      return -1;
    }
    lock_acquire (&filesys_lock);
    bytes_written = file_write (of->file, buffer, size);
    lock_release (&filesys_lock);
    return bytes_written;
  }
}

static void
userprog_seek (int fd, unsigned position)
{
	struct openfile *of = NULL;
  of = getFile (fd);
  if (of == NULL)
    return;
  lock_acquire (&filesys_lock);
  file_seek (of->file, position);
  lock_release (&filesys_lock);
}

static unsigned
userprog_tell (int fd)
{
  unsigned retval;
	struct openfile *of = NULL;
  of = getFile (fd);
  if (of == NULL)
    return 0;
  lock_acquire (&filesys_lock);
  retval = file_tell (of->file);
  lock_release (&filesys_lock);
  return retval;
}

static void
userprog_close (int fd)
{
  printf("close\n");
  printf("close: urrent dir: %s\n", thread_current()->path);
	struct openfile *of = NULL;
  of = getFile (fd);
  if (of == NULL)
    return;
  if (of->is_dir) {
    dir_close ((struct dir*)of->file);
  } else {
    lock_acquire (&filesys_lock);
    file_close (of->file);
    lock_release (&filesys_lock);
  }
  list_remove (&of->elem);
  palloc_free_page (of);
  printf("close: urrent dir: %s\n", thread_current()->path);
}

static bool
userprog_chdir (const char *dir)
{
  if (!valid_mem_access(dir))
    return false;

  bool ret = true;
  int i, j;
  char *token, *save_ptr;
  struct dir *parent;
  struct inode *inode;
  struct thread *t = thread_current ();
  char **tokens = (char **)malloc(sizeof(char)*512);
  char *absolute = (char *)malloc(sizeof(char)*512);
  relative_to_absolute (dir, absolute);
  printf("chdir: %s -> %s\n", t->path, dir);

  i = 0;
  for (token = strtok_r (absolute, "/", &save_ptr); token != NULL;
        token = strtok_r (NULL, "/", &save_ptr)) {
    tokens[i] = token;
    i++;
  }

  if (tokens[i] == NULL) {
    /* Root */
    strlcpy (t->path, "/", 2);
    free (tokens);  
    free (absolute);
    printf ("Chdir: %s\n", t->path);
    return true;
  }

  /* Make sure the directory exists */
  parent = dir_open_root ();
  for (j = 0; j < i; j++) {
    if(!dir_lookup (parent, tokens[j], &inode)) {
      ret = false;
      break;
    }
    dir_close (parent);
    parent = dir_open (inode);
  }

  if (ret) {
    /* Update the process' path */
    strlcpy (t->path, "", 1);
    for (j = 0; j < i; j++) {
      strlcat (t->path, "/", strlen(t->path)+2);
      strlcat (t->path, tokens[j], strlen(t->path)+strlen(tokens[j])+1);
    }
  }

  printf ("Chdir: %s\n", t->path);

  dir_close (parent);

  free (tokens);  
  free (absolute);
  return ret;
}

static bool
userprog_mkdir (const char *dir)
{
  if (!valid_mem_access(dir))
    return false;

  bool ret = true;
  int i, j;
  block_sector_t s;
  char *token, *save_ptr;
  struct dir *parent;
  struct inode *inode;
  char **tokens = (char **)malloc(sizeof(char)*512);
  char *absolute = (char *)malloc(sizeof(char)*512);
  relative_to_absolute (dir, absolute);
  printf("Mkdir %s\n", absolute);
  printf("\tCurrent dir: %s\n", thread_current()->path);

  i = 0;
  for (token = strtok_r (absolute, "/", &save_ptr); token != NULL;
        token = strtok_r (NULL, "/", &save_ptr)) {
    tokens[i] = token;
    i++;
  }
  i--;

  if (tokens[i] == NULL) {
    free (tokens);  
    free (absolute);
    return false;
  }

  parent = dir_open_root ();
  for (j = 0; j < i; j++) {
    if(!dir_lookup (parent, tokens[j], &inode)) {
      ret = false;
      break;
    }
    dir_close (parent);
    parent = dir_open (inode);
  }
  if (ret && !dir_lookup (parent, tokens[i], &inode)) {
    if (free_map_allocate (1, &s)) {
      if (dir_create (s, 16)) {
        ret = dir_add (parent, tokens[i], s);
      } else {
        ret = false;
      }

    } else {
      ret = false;
    }
  } else {
    ret = false;
  }

  dir_close (parent);

  free (tokens);  
  free (absolute);
  return ret;
}

static bool
userprog_readdir (int fd, char *name)
{
  printf("readdir\n");
  if (!valid_mem_access(name))
    userprog_exit (-1);

  struct openfile *of = NULL;
  of = getFile (fd);
  if (of == NULL)
    return false;
  if (!of->is_dir)
    return false;

  return dir_readdir ((struct dir *)of->file, name);
}

static bool
userprog_isdir (int fd UNUSED)
{
  struct openfile *of = NULL;
  of = getFile (fd);
  if (of == NULL)
    return false;
  return file_is_dir(of->file);
}

static int
userprog_inumber (int fd)
{
  struct openfile *of = NULL;
  of = getFile (fd);
  if (of == NULL)
    return 0;
  return file_get_inumber(of->file);
}

/* Helper function for getting a thread's opened
   file by its file descriptor */
static struct openfile *
getFile (int fd)
{
  struct thread *t = thread_current ();
  struct list_elem *e;
  for (e = list_begin (&t->openfiles); e != list_end (&t->openfiles);
       e = list_next (e))
    {
      struct openfile *of = list_entry (e, struct openfile, elem);
      if(of->fd == fd)
        return of;
    }
  return NULL;
}
