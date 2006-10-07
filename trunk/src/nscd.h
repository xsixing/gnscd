/* This file is part of gnscd, a complete nscd replacement.
 * Copyright (C) 2006 Google. Licensed under the GPL version 2. */

/* gnscd is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 * 
 * gnscd is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 * 
 * You can download the GNU General Public License from the GNU website
 * at http://www.gnu.org/ or write to the Free Software Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA. */

#ifndef __NSCD_H
#define __NSCD_H

/* This file is based on glibc's nscd-client.h */

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/uio.h>


typedef int32_t nscd_ssize_t;


/* Version number of the daemon interface */
#define NSCD_VERSION 2

#define NSCD_MAXKEYLEN 1024

/* Path for the Unix domain socket.  */
#define NSCD_SOCKET "/var/run/nscd/socket"
#define NSCD_SOCKET_OLD "/var/run/.nscd_socket"


/* Available services.  */
typedef enum
{
  GETPWBYNAME,
  GETPWBYUID,
  GETGRBYNAME,
  GETGRBYGID,
  GETHOSTBYNAME,
  GETHOSTBYNAMEv6,
  GETHOSTBYADDR,
  GETHOSTBYADDRv6,
  LASTDBREQ = GETHOSTBYADDRv6,
  SHUTDOWN,		/* Shut the server down.  */
  GETSTAT,		/* Get the server statistic.  */
  INVALIDATE,           /* Invalidate one special cache.  */
  GETFDPW,
  GETFDGR,
  GETFDHST,
  GETAI,
  INITGROUPS,
  GETPWENT, /* should be above with other GETPW things */
  GETGRENT, /* should be above with other GETGR things */
  LASTREQ
} request_type;


/* Header common to all requests */
typedef struct
{
  int32_t version;	/* Version number of the daemon interface.  */
  request_type type;	/* Service requested.  */
  int32_t key_len;	/* Key length.  */
} request_header;


/* Structure sent in reply to password query.  Note that this struct is
   sent also if the service is disabled or there is no record found.  */
typedef struct
{
  int32_t version;
  int32_t found;
  nscd_ssize_t pw_name_len;
  nscd_ssize_t pw_passwd_len;
  uid_t pw_uid;
  gid_t pw_gid;
  nscd_ssize_t pw_gecos_len;
  nscd_ssize_t pw_dir_len;
  nscd_ssize_t pw_shell_len;
} pw_response_header;


/* Structure sent in reply to group query.  Note that this struct is
   sent also if the service is disabled or there is no record found.  */
typedef struct
{
  int32_t version;
  int32_t found;
  nscd_ssize_t gr_name_len;
  nscd_ssize_t gr_passwd_len;
  gid_t gr_gid;
  nscd_ssize_t gr_mem_cnt;
} gr_response_header;


/* Structure sent in reply to host query.  Note that this struct is
   sent also if the service is disabled or there is no record found.  */
typedef struct
{
  int32_t version;
  int32_t found;
  nscd_ssize_t h_name_len;
  nscd_ssize_t h_aliases_cnt;
  int32_t h_addrtype;
  int32_t h_length;
  nscd_ssize_t h_addr_list_cnt;
  int32_t error;
} hst_response_header;


/* Structure sent in reply to addrinfo query.  Note that this struct is
   sent also if the service is disabled or there is no record found.  */
typedef struct
{
  int32_t version;
  int32_t found;
  nscd_ssize_t naddrs;
  nscd_ssize_t addrslen;
  nscd_ssize_t canonlen;
  int32_t error;
} ai_response_header;

/* Structure filled in by __nscd_getai.  */
struct nscd_ai_result
{
  int naddrs;
  char *canon;
  uint8_t *family;
  char *addrs;
};

/* Structure sent in reply to initgroups query.  Note that this struct is
   sent also if the service is disabled or there is no record found.  */
typedef struct
{
  int32_t version;
  int32_t found;
  nscd_ssize_t ngrps;
} initgr_response_header;

#endif /* __NSCD_H */
