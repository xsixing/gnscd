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

#ifndef __CACHE_H
#define __CACHE_H

#include <stdint.h>
#include <pthread.h>
#include <time.h>

#include "nscd.h"

/* All entries in the cache are stored using this structure. */
struct cache_entry {
	/* query information */
	request_type type;
	void * key;
	int32_t key_len;
	uint32_t key_hash;
	
	/* cached information */
	void * reply;
	int32_t reply_len;
	int close_socket;
	
	/* refresh information */
	time_t expire_time;
	time_t refresh_interval;
	int refreshes;
	
	/* chaining information */
	struct cache_entry ** point;
	struct cache_entry * chain;
};

/* All access to the cache is synchronized with this mutex. */
extern pthread_mutex_t cache_mutex;

/* Search the cache for an entry, and fill in the pointers if one is found. */
extern int cache_search(request_header * req, void * key, uid_t uid, struct cache_entry ** entry);

/* Add an entry to the cache with the specified parameters. */
extern int cache_add(request_header * req, void * key, uid_t uid, void * reply, int32_t reply_len, int close_socket, time_t refresh_interval);

/* Initialize the cache and start the cache maintenance thread. */
extern int cache_init(void);

#endif /* __CACHE_H */
