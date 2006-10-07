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

#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include "nscd.h"
#include "misc.h"
#include "lookup.h"
#include "cache.h"

/* All access to the cache is synchronized with this mutex. */
pthread_mutex_t cache_mutex = PTHREAD_MUTEX_INITIALIZER;

/* This hash is supposed to be good for short textual data. */
static uint32_t bernstein_hash(uint8_t * key, int32_t key_len, uint32_t level)
{
	uint32_t hash = level;
	while(key_len-- > 0)
		hash = 33 * hash + *(key++);
	return hash;
}

#define cache_hash(key, key_len, type) bernstein_hash(key, key_len, 0xDEADBEEF + type)

/* This hash table stores all cache entries. Note that 10007 is prime. */
#define HASH_SIZE 10007
static struct cache_entry * hash_table[HASH_SIZE] = {NULL};

/* MUST BE CALLED WITH THE LOCK HELD */
int cache_search(request_header * req, void * key, uid_t uid, struct cache_entry ** entry)
{
	uint32_t hash = cache_hash(key, req->key_len, req->type);
	struct cache_entry * scan = hash_table[hash % HASH_SIZE];
	for(scan = hash_table[hash % HASH_SIZE]; scan; scan = scan->chain)
		if(scan->key_hash == hash && scan->key_len == req->key_len
		   && scan->type == req->type && !memcmp(scan->key, key, req->key_len))
			break;
	if(!scan)
		return -1;
	/* don't return expired data, just leave it for cleanup */
	if(time(NULL) > scan->expire_time)
	{
		/* the newly added one will occur before this one in
		 * the hash chain, so this won't be touched again */
		if(debug)
			printf("Expired cache entry for [%s], refreshes %d\n", (char *) scan->key, scan->refreshes);
		scan->refreshes = 5;
		return -1;
	}
	*entry = scan;
	return 0;
}

/* MUST BE CALLED WITH THE LOCK HELD */
int cache_add(request_header * req, void * key, uid_t uid, void * reply, int32_t reply_len, int close_socket, time_t refresh_interval)
{
	struct cache_entry * entry = malloc(sizeof(*entry));
	uint32_t index;
	if(!entry)
		return -1;
	/* query information */
	entry->type = req->type;
	entry->key = malloc(req->key_len);
	if(!entry->key)
	{
		free(entry);
		return -1;
	}
	memcpy(entry->key, key, req->key_len);
	entry->key_len = req->key_len;
	entry->key_hash = cache_hash(key, req->key_len, req->type);
	
	/* cached information */
	entry->reply = reply;
	entry->reply_len = reply_len;
	entry->close_socket = close_socket;
	
	/* refresh information */
	entry->expire_time = time(NULL) + refresh_interval;
	entry->refresh_interval = refresh_interval;
	entry->refreshes = 0;
	
	/* chaining information */
	index = entry->key_hash % HASH_SIZE;
	entry->point = &hash_table[index];
	entry->chain = hash_table[index];
	if(entry->chain)
		entry->chain->point = &entry->chain;
	hash_table[index] = entry;
	
	if(debug)
		printf("Adding cache entry for [%s] hash 0x%08x at index %d\n", (char *) key, entry->key_hash, index);
	return 0;
}

static int cache_entry_destroy(struct cache_entry * entry)
{
	if(debug)
		printf("Removing cache entry for [%s], refreshes %d\n", (char *) entry->key, entry->refreshes);
	*entry->point = entry->chain;
	if(entry->chain)
		entry->chain->point = entry->point;
	free(entry->key);
	free(entry->reply);
	free(entry);
	return 0;
}

static void * cache_maintain(void * arg)
{
	/* This code runs as a thread and is responsible for maintaining the
	 * cache. Every 10 seconds it scans 1/6 of the cache, so that in a
	 * minute it will scan the entire cache. It attempts to refresh cache
	 * entries which have expired, but only up to 5 times if they have not
	 * been used in the interim. After that they are removed. */
	int entries = HASH_SIZE / 6;
	int position = 0;
	for(;;)
	{
		int i;
		time_t now;
		struct timespec delay;
		
		delay.tv_sec = 10;
		delay.tv_nsec = 0;
		while(nanosleep(&delay, &delay) < 0 && errno == EINTR)
			if(debug)
				printf("Resuming interrupted sleep!\n");
		
		pthread_mutex_lock(&cache_mutex);
		if(debug)
			printf("Look over 1/6 of cache...\n");
		now = time(NULL);
		for(i = 0; i < entries; i++)
		{
			/* Since we'll potentially be removing entries from the
			 * linked list, we keep a pointer to the previous
			 * element's link to us so that we can update it and use
			 * that to get to the next element if we remove one. */
			struct cache_entry ** point = &hash_table[position];
			struct cache_entry * scan;
			while((scan = *point))
			{
				/* GET*ENT entries do not get refreshed here */
				if(scan->refreshes == 5 || (now > scan->expire_time &&
				   (scan->type == GETPWENT || scan->type == GETGRENT)))
					/* kill it */
					cache_entry_destroy(scan);
				else if(now > scan->expire_time)
				{
					request_header req = {version: NSCD_VERSION, type: scan->type, key_len: scan->key_len};
					int r;
					void * reply;
					int32_t reply_len;
					time_t refresh_interval;
					
					/* refresh it */
					if(debug)
						printf("Refreshing cache entry for [%s], refreshes %d\n", (char *) scan->key, scan->refreshes);
					pthread_mutex_unlock(&cache_mutex);
					r = generate_reply(&req, scan->key, -1, &reply, &reply_len, &refresh_interval);
					pthread_mutex_lock(&cache_mutex);
					now = time(NULL);
					
					/* while we were refreshing it, it may have
					 * been marked stale and a new copy fetched */
					if(scan->refreshes == 5 || r < 0)
					{
						/* kill it */
						cache_entry_destroy(scan);
						if(r >= 0)
							free(reply);
					}
					else
					{
						free(scan->reply);
						scan->reply = reply;
						scan->reply_len = reply_len;
						scan->expire_time += refresh_interval;
						scan->refresh_interval = refresh_interval;
						scan->refreshes++;
						/* go to next entry */
						point = &scan->chain;
					}
				}
				else
					/* go to next entry */
					point = &scan->chain;
			}
			if(++position == HASH_SIZE)
				position = 0;
		}
		if(debug)
			printf("Done looking over 1/6 of cache.\n");
		pthread_mutex_unlock(&cache_mutex);
	}
	return NULL;
}

int cache_init(void)
{
	pthread_t thread;
	if(pthread_create(&thread, NULL, cache_maintain, NULL) < 0)
		return -1;
	pthread_detach(thread);
	return 0;
}
