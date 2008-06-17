/* system-config-audit-server

Copyright (C) 2007 Red Hat, Inc.  All rights reserved.
This copyrighted material is made available to anyone wishing to use, modify,
copy, or redistribute it subject to the terms and conditions of the GNU
General Public License v.2.  This program is distributed in the hope that it
will be useful, but WITHOUT ANY WARRANTY expressed or implied, including the
implied warranties of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU General Public License for more details.  You should have
received a copy of the GNU General Public License along with this program; if
not, write to the Free Software Foundation, Inc., 51 Franklin Street, Fifth
Floor, Boston, MA 02110-1301, USA.  Any Red Hat trademarks that are
incorporated in the source code or documentation are not subject to the GNU
General Public License and may only be used or replicated with the express
permission of Red Hat, Inc.

Red Hat Author: Miloslav Trmac <mitr@redhat.com> */
#include "config.h"

#include <assert.h>
#include <errno.h>
#include <error.h>
#include <fcntl.h>
#include <inttypes.h>
#include <libintl.h>
#include <locale.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <libaudit.h>

#include "server.h"

#define _(X) gettext(X)

#define SOCKET_FILENO STDIN_FILENO

 /* Generic utilities */

#define STR__(X) #X
#define STR(X) STR__(X)

/* Like read (), but avoid partial reads if possible. */
static ssize_t
full_read (int fd, void *buf, size_t size)
{
  ssize_t res, r;

  res = 0;
  while (size != 0 && (r = read (fd, buf, size)) != 0)
    {
      if (r < 0)
	return r;
      res += r;
      buf = (char *)buf + r;
      assert (size >= (size_t)r);
      size -= r;
    }
  return res;
}

/* Like write (), but handle partial writes. */
static ssize_t
full_write (int fd, const void *buf, size_t size)
{
  size_t left;

  left = size;
  while (left != 0)
    {
      ssize_t r;

      r = write (fd, buf, left);
      if (r < 0)
	return r;
      assert (r != 0);
      buf = (const char *)buf + r;
      assert (left >= (size_t)r);
      left -= r;
    }
  return size;
}

/* Like full_read (), but abort if the whole read could not be completed */
static void
read_or_fail (int fd, void *buf, size_t size)
{
  if ((size_t)full_read (fd, buf, size) != size)
    exit (EXIT_FAILURE);
}

/* Like full_write (), but abort if the whole write could not be completed */
static void
write_or_fail (int fd, const void *buf, size_t size)
{
  if ((size_t)full_write (fd, buf, size) != size)
    exit (EXIT_FAILURE);
}

/* Return a malloc() ed concatenation of s1 and s2, or NULL */
static char *
concat (const char *s1, const char *s2)
{
  size_t len1, size2;
  char *res;

  len1 = strlen (s1);
  size2 = strlen (s2) + 1;
  res = malloc (len1 + size2);
  if (res != NULL)
    {
      memcpy (res, s1, len1);
      memcpy (res + len1, s2, size2);
    }
  return res;
}

 /* The server */

/* Print the usage message. */
static void
usage (void)
{
  puts (_("This program is only for use by system-config-audit and it should "
	  "not be run\n"
	  "manually."));
}

/* Handle command-line arguments. */
static void
handle_args (int argc, char *argv[])
{
  if (argc > 1)
    {
      if (strcmp (argv[1], "--help") == 0)
	{
	  usage ();
	  printf (_("\n"
		    "Report bugs to %s.\n"), PACKAGE_BUGREPORT);
	  exit (EXIT_SUCCESS);
	}
      if (strcmp (argv[1], "--version") == 0)
	{
	  puts (PACKAGE_NAME " " PACKAGE_VERSION);
	  puts (_("Copyright (C) 2007 Red Hat, Inc.  All rights reserved.\n"
		  "This software is distributed under the GPL v.2.\n"
		  "\n"
		  "This program is provided with NO WARRANTY, to the extent "
		  "permitted by law."));
	  exit (EXIT_SUCCESS);
	}
      usage ();
      exit (EXIT_FAILURE);
    }
}

/* Read a file ID from the client and return the relevant path.  Abort if the
   ID is invalid. */
static const char *
get_file_path (void)
{
  uint32_t id;

  read_or_fail (SOCKET_FILENO, &id, sizeof (id));
  switch (id)
    {
    case FILE_AUDITD_CONF:
      return SYSCONFDIR "/audit/auditd.conf";
    case FILE_AUDIT_RULES:
      return SYSCONFDIR "/audit/audit.rules";
    default:
      exit (EXIT_FAILURE);
    }
}

/* Handle REQ_READ_FILE */
static void
req_read_file (void)
{
  const char *path;
  int fd;
  uint32_t err;
  struct stat st;
  void *data;
  ssize_t res;
  uint64_t data_len;

  path = get_file_path ();
  fd = open(path, O_RDONLY);
  if (fd == -1)
    {
      err = errno;
      goto err;
    }
  if (fstat (fd, &st) != 0)
    {
      err = errno;
      goto err_fd;
    }
  /* If sizeof (off_t) <= sizeof (size_t), (size_t)st.st_size cannot overflow
     and (off_t)SIZE_MAX is negative. */
  if (sizeof (off_t) > sizeof (size_t) && st.st_size > (off_t)SIZE_MAX)
    {
      err = EFBIG;
      goto err_fd;
    }
  data = malloc (st.st_size);
  if (data == NULL)
    {
      err = errno;
      goto err_fd;
    }
  res = full_read (fd, data, st.st_size);
  if (res < 0)
    {
      err = errno;
      goto err_data;
    }
  data_len = res;
  close (fd);
  err = 0;
  write_or_fail (SOCKET_FILENO, &err, sizeof (err));
  write_or_fail (SOCKET_FILENO, &data_len, sizeof (data_len));
  write_or_fail (SOCKET_FILENO, data, data_len);
  free (data);
  return;

 err_data:
  free (data);
 err_fd:
  close (fd);
 err:
  write_or_fail (SOCKET_FILENO, &err, sizeof (err));
}

/* Handle REQ_WRITE_FILE */
static void
req_write_file (void)
{
  const char *path;
  struct stat st_orig;
  uint32_t err;
  uint64_t data_left;
  char *tmp_path, *backup_path;
  int fd;

  path = get_file_path ();
  read_or_fail (SOCKET_FILENO, &data_left, sizeof (data_left));
  if (stat (path, &st_orig) != 0)
    {
      err = errno;
      goto err;
    }
  tmp_path = concat (path, "XXXXXX");
  if (tmp_path == NULL)
    {
      err = errno;
      goto err;
    }
  fd = mkstemp (tmp_path);
  if (fd == -1)
    {
      err = errno;
      goto err_tmp_path;
    }
  while (data_left != 0)
    {
      char buf[BUFSIZ];
      size_t run;

      run = data_left;
      if (run > sizeof (buf))
	run = sizeof (buf);
      read_or_fail (SOCKET_FILENO, buf, run);
      if ((size_t)full_write (fd, buf, run) != run)
	{
	  err = errno;
	  goto err_tmp_fd;
	}
      data_left -= run;
    }
  if (fchmod (fd, st_orig.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) != 0)
    {
      err = errno;
      goto err_tmp_fd;
    }
  if (close (fd) != 0)
    {
      err = errno;
      goto err_tmp_file;
    }
  backup_path = concat (path, "~");
  if (backup_path == NULL)
    {
      err = errno;
      goto err_tmp_file;
    }
  (void)unlink(backup_path);
  if (link (path, backup_path) != 0)
    {
      err = errno;
      free (backup_path);
      goto err_tmp_file;
    }
  free (backup_path);
  if (rename (tmp_path, path) != 0)
    {
      err = errno;
      goto err_tmp_file;
    }
  err = 0;
  goto err_tmp_path;

 err_tmp_fd:
  (void)close (fd);
 err_tmp_file:
  (void)unlink (tmp_path);
 err_tmp_path:
  free (tmp_path);
 err:
  while (data_left != 0)
    {
      char buf[BUFSIZ];
      size_t run;

      run = data_left;
      if (run > sizeof (buf))
	run = sizeof (buf);
      read_or_fail (SOCKET_FILENO, buf, run);
      data_left -= run;
    }
  write_or_fail (SOCKET_FILENO, &err, sizeof (err));
}

/* Handle REQ_APPLY */
static void
req_apply (void)
{
  int res;
  uint32_t err;

  assert (SOCKET_FILENO == STDIN_FILENO);
  /* system() uses "sh -c ...", so the "exec " avoids one fork (). */
  res = system ("exec /sbin/service auditd condrestart "
		STR(SOCKET_FILENO) "</dev/null");
  switch (res)
    {
    case 0:
      err = 0;
      break;
    case -1:
      err = errno;
      break;
    default:
      /* Discard the possible additional information. */
      err = EIO;
    }
  write_or_fail (SOCKET_FILENO, &err, sizeof (err));
}

/* Handle REQ_AUDIT_STATUS */
static void
req_audit_status (void)
{
  struct audit_reply reply;
  uint32_t err;
  int fd, res;

  fd = audit_open ();
  if (fd == -1)
    {
      err = errno;
      goto err;
    }
  res = audit_request_status (fd);
  if (res == 0)
    {
      err = EIO; /* Unknown */
      goto err_fd;
    }
  else if (res < 0)
    {
      err = -res;
      goto err_fd;
    }
 again:
  res = audit_get_reply (fd, &reply, GET_REPLY_BLOCKING, 0);
  if (res < 0)
    {
      err = -res;
      goto err_fd;
    }
  if (reply.type == NLMSG_ERROR)
    {
      if (res != NLMSG_LENGTH (sizeof (*reply.error)))
	{
	  err = EIO;
	  goto err_fd;
	}
      if (reply.error->error == 0)
	goto again;
      err = -reply.error->error;
      goto err_fd;
    }
  if (reply.type != AUDIT_GET
      || reply.len != NLMSG_LENGTH (sizeof (*reply.status)))
    {
      err = EIO;
      goto err_fd;
    }
  audit_close (fd);
  err = 0;
  write_or_fail (SOCKET_FILENO, &err, sizeof (err));
  write_or_fail (SOCKET_FILENO, reply.status, sizeof (*reply.status));
  return;

 err_fd:
  audit_close (fd);
 err:
  write_or_fail (SOCKET_FILENO, &err, sizeof (err));
}

/* Handle REQ_AUDIT_ENABLE */
static void
req_audit_enable (void)
{
  uint32_t enable, err;
  int fd, res;

  read_or_fail (SOCKET_FILENO, &enable, sizeof (enable));
  fd = audit_open ();
  if (fd == -1)
    {
      err = errno;
      goto err;
    }
  res = audit_set_enabled (fd, enable);
  if (res == 0)
    {
      err = EIO; /* Unknown */
      goto err_fd;
    }
  else if (res < 0)
    {
      err = -res;
      goto err_fd;
    }
  err = 0;
 err_fd:
  audit_close (fd);
 err:
  write_or_fail (SOCKET_FILENO, &err, sizeof (err));
}

int
main (int argc, char *argv[])
{
  struct stat st;
  uint32_t req;
  ssize_t len;

  setlocale (LC_ALL, "");
  bindtextdomain (PACKAGE_NAME, LOCALEDIR);
  textdomain (PACKAGE_NAME);
  handle_args(argc, argv);
  if (fstat (SOCKET_FILENO, &st) != 0)
    error (EXIT_FAILURE, errno, "fstat (SOCKET_FILENO)");
  if (!S_ISSOCK (st.st_mode))
    error (EXIT_FAILURE, 0, _("The control file is not a socket"));
  while ((len = full_read (SOCKET_FILENO, &req, sizeof (req))) == sizeof (req))
    {
      switch (req)
	{
	case REQ_READ_FILE:
	  req_read_file ();
	  break;

	case REQ_WRITE_FILE:
	  req_write_file ();
	  break;

	case REQ_APPLY:
	  req_apply ();
	  break;

	case REQ_AUDIT_STATUS:
	  req_audit_status ();
	  break;

	case REQ_AUDIT_ENABLE:
	  req_audit_enable ();
	  break;

	default:
	  error (EXIT_FAILURE, 0, _("Unknown server request %" PRIu32), req);
	}
    }
  if (len != 0)
    return EXIT_FAILURE;
  return EXIT_SUCCESS;
}
