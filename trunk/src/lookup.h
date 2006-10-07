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

#ifndef __LOOKUP_H
#define __LOOKUP_H

#include <time.h>
#include <stdint.h>
#include <pthread.h>

#include "nscd.h"

extern pthread_mutex_t * pwent_query_mutex;
extern pthread_mutex_t * grent_query_mutex;

/* generate normal replies and disabled replies, respectively */
extern int generate_reply(request_header * req, void * key, uid_t uid, void ** reply, int32_t * reply_len, time_t * refresh_interval);
extern int generate_disabled_reply(request_type type, void ** reply, int32_t * reply_len);

/* request that a background thread fetch this GET*ENT request and add it to the cache */
extern int request_ent_cache(request_header * req, void * key, uid_t uid);

#endif /* __LOOKUP_H */
