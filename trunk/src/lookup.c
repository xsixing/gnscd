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

#include <pwd.h>
#include <grp.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netdb.h>
#include <pthread.h>
#include <arpa/nameser.h>

#include "nscd.h"
#include "misc.h"
#include "cache.h"
#include "lookup.h"

/* The functions in this file actually generate replies in response to queries.
 * Also the background thread that handles GET*ENT queries is in this file. */

/* This structure is used to communicate between the query threads and the
 * background GET*ENT thread(s). When a background thread is started, it begins
 * iterating through either users or groups and adding entries to the cache.
 * When it has fetched the one that the query was interested in, it wakes up the
 * query thread that originally started it so that the reply can be sent to the
 * client before the iteration is finished. Later, additional queries may arrive
 * and wait for other indices in the iteration, and they too will be woken up
 * when the desired index has been added to the cache. Only one such background
 * thread will exist at a time for each service (passwd, group). */
struct ent_info {
	request_type type;
	int thread_busy, wait_index;
	pthread_mutex_t query_mutex;
	pthread_mutex_t busy_mutex;
	pthread_cond_t wait_done;
};

static struct ent_info pwent_info = {
	GETPWENT, 0, -1,
	PTHREAD_MUTEX_INITIALIZER,
	PTHREAD_MUTEX_INITIALIZER,
	PTHREAD_COND_INITIALIZER};
static struct ent_info grent_info = {
	GETGRENT, 0, -1,
	PTHREAD_MUTEX_INITIALIZER,
	PTHREAD_MUTEX_INITIALIZER,
	PTHREAD_COND_INITIALIZER};

/* The query mutex is held by the sleeping query thread which is waiting for the
 * background iteration thread to get to the index it wants. This makes sure
 * there will only be one such query thread at a time. */
pthread_mutex_t * pwent_query_mutex = &pwent_info.query_mutex;
pthread_mutex_t * grent_query_mutex = &grent_info.query_mutex;

/* Marshall a passwd structure into the NSCD format. */
static int marshall_pwd(int error, struct passwd * pwd, void ** reply, int32_t * reply_len, time_t * refresh_interval)
{
	pw_response_header header;
	header.version = NSCD_VERSION;
	if(error < 0 || !pwd)
	{
		if(error && error != -ENOENT && error != -ESRCH)
			return -1;
		
		header.found = 0;
		header.pw_name_len = 0;
		header.pw_passwd_len = 0;
		header.pw_uid = -1;
		header.pw_gid = -1;
		header.pw_gecos_len = 0;
		header.pw_dir_len = 0;
		header.pw_shell_len = 0;
		
		*reply_len = sizeof(header);
		*reply = malloc(*reply_len);
		if(!*reply)
			return -1;
		memcpy(*reply, &header, sizeof(header));
		/* The refresh interval for the negative entry at the end of
		 * getpwent() iteration should be the same as a positive query,
		 * so that we don't expire it before the rest of the entries and
		 * have to redo the iteration only to find that there still
		 * aren't any more users. The "error" variable will be 0 only in
		 * this case - all other cases have an error code. */
		*refresh_interval = error ? 20 : 600;
	}
	else
	{
		size_t offset;
		
		header.found = 1;
		header.pw_name_len = strlen(pwd->pw_name) + 1;
		header.pw_passwd_len = strlen(pwd->pw_passwd) + 1;
		header.pw_uid = pwd->pw_uid;
		header.pw_gid = pwd->pw_gid;
		header.pw_gecos_len = strlen(pwd->pw_gecos) + 1;
		header.pw_dir_len = strlen(pwd->pw_dir) + 1;
		header.pw_shell_len = strlen(pwd->pw_shell) + 1;
		
		*reply_len = sizeof(header)
		             + header.pw_name_len
		             + header.pw_passwd_len
		             + header.pw_gecos_len
		             + header.pw_dir_len
		             + header.pw_shell_len;
		*reply = malloc(*reply_len);
		if(!*reply)
			return -1;
		memcpy(*reply, &header, sizeof(header));
		offset = sizeof(header);
		
		strcpy(*reply + offset, pwd->pw_name);
		offset += header.pw_name_len;
		
		strcpy(*reply + offset, pwd->pw_passwd);
		offset += header.pw_passwd_len;
		
		strcpy(*reply + offset, pwd->pw_gecos);
		offset += header.pw_gecos_len;
		
		strcpy(*reply + offset, pwd->pw_dir);
		offset += header.pw_dir_len;
		
		strcpy(*reply + offset, pwd->pw_shell);
		*refresh_interval = 600;
	}
	return 0;
}

/* Marshall a group structure into the NSCD format. */
static int marshall_grp(int error, struct group * grp, void ** reply, int32_t * reply_len, time_t * refresh_interval)
{
	gr_response_header header;
	header.version = NSCD_VERSION;
	if(error < 0 || !grp)
	{
		if(error && error != -ENOENT && error != -ESRCH)
			return -1;
		
		header.found = 0;
		header.gr_name_len = 0;
		header.gr_passwd_len = 0;
		header.gr_gid = -1;
		header.gr_mem_cnt = 0;
		
		*reply_len = sizeof(header);
		*reply = malloc(*reply_len);
		if(!*reply)
			return -1;
		memcpy(*reply, &header, sizeof(header));
		/* The refresh interval for the negative entry at the end of
		 * getgrent() iteration should be the same as a positive query,
		 * so that we don't expire it before the rest of the entries and
		 * have to redo the iteration only to find that there still
		 * aren't any more groups. The "error" variable will be 0 only
		 * in this case - all other cases have an error code. */
		*refresh_interval = error ? 60 : 3600;
	}
	else
	{
		size_t offset;
		int i, mem_size = 0;
		uint32_t * sizes;
		
		header.found = 1;
		header.gr_name_len = strlen(grp->gr_name) + 1;
		header.gr_passwd_len = strlen(grp->gr_passwd) + 1;
		header.gr_gid = grp->gr_gid;
		for(i = 0; grp->gr_mem[i]; i++)
			mem_size += strlen(grp->gr_mem[i]) + 1;
		header.gr_mem_cnt = i;
		
		*reply_len = sizeof(header)
		             + header.gr_mem_cnt * sizeof(uint32_t)
		             + header.gr_name_len
		             + header.gr_passwd_len
		             + mem_size;
		*reply = malloc(*reply_len);
		if(!*reply)
			return -1;
		memcpy(*reply, &header, sizeof(header));
		offset = sizeof(header);
		
		sizes = (uint32_t *) (*reply + offset);
		for(i = 0; i < header.gr_mem_cnt; i++)
			sizes[i] = strlen(grp->gr_mem[i]) + 1;
		offset += header.gr_mem_cnt * sizeof(uint32_t);
		
		strcpy(*reply + offset, grp->gr_name);
		offset += header.gr_name_len;
		
		strcpy(*reply + offset, grp->gr_passwd);
		offset += header.gr_passwd_len;
		
		for(i = 0; i < header.gr_mem_cnt; i++)
		{
			strcpy(*reply + offset, grp->gr_mem[i]);
			offset += sizes[i];
		}
		*refresh_interval = 3600;
	}
	return 0;
}

/* Marshall a host structure into the NSCD format. */
static int marshall_hst(int error, struct hostent * hst, void ** reply, int32_t * reply_len, time_t * refresh_interval)
{
	hst_response_header header;
	header.version = NSCD_VERSION;
	if(!hst)
	{
		if(error != NETDB_SUCCESS && error != HOST_NOT_FOUND && error != TRY_AGAIN)
			return -1;
		
		header.found = 0;
		header.h_name_len = 0;
		header.h_aliases_cnt = 0;
		header.h_addrtype = -1;
		header.h_length = -1;
		header.h_addr_list_cnt = 0;
		header.error = HOST_NOT_FOUND;
		
		*reply_len = sizeof(header);
		*reply = malloc(*reply_len);
		if(!*reply)
			return -1;
		memcpy(*reply, &header, sizeof(header));
		/* The original nscd seems to treat TRY_AGAIN differently. So,
		 * we do as well. I'm not sure what the rationale is. */
		*refresh_interval = (error == TRY_AGAIN) ? 60 : 20;
	}
	else
	{
		size_t offset;
		int i, mem_size = 0;
		uint32_t * sizes;
		
		header.found = 1;
		header.h_name_len = strlen(hst->h_name) + 1;
		for(i = 0; hst->h_aliases[i]; i++)
			mem_size += strlen(hst->h_aliases[i]) + 1;
		header.h_aliases_cnt = i;
		header.h_addrtype = hst->h_addrtype;
		header.h_length = hst->h_length;
		for(i = 0; hst->h_addr_list[i]; i++);
		header.h_addr_list_cnt = i;
		header.error = NETDB_SUCCESS;
		
		*reply_len = sizeof(header)
		             + header.h_name_len
		             + header.h_aliases_cnt * sizeof(uint32_t)
		             + header.h_addr_list_cnt * header.h_length
		             + mem_size;
		*reply = malloc(*reply_len);
		if(!*reply)
			return -1;
		memcpy(*reply, &header, sizeof(header));
		offset = sizeof(header);
		
		strcpy(*reply + offset, hst->h_name);
		offset += header.h_name_len;
		
		sizes = (uint32_t *) (*reply + offset);
		for(i = 0; i < header.h_aliases_cnt; i++)
			sizes[i] = strlen(hst->h_aliases[i]) + 1;
		offset += header.h_aliases_cnt * sizeof(uint32_t);
		
		for(i = 0; i < header.h_addr_list_cnt; i++)
		{
			memcpy(*reply + offset, hst->h_addr_list[i], hst->h_length);
			offset += hst->h_length;
		}
		
		for(i = 0; i < header.h_aliases_cnt; i++)
		{
			strcpy(*reply + offset, hst->h_aliases[i]);
			offset += sizes[i];
		}
		*refresh_interval = 600;
	}
	return 0;
}

static int marshall_ai(int error, struct addrinfo * ai, void ** reply, int32_t * reply_len, time_t * refresh_interval)
{
	/* This function would marshall the addrinfo structure. Since Google
	 * doesn't use the host cache anyway, it is not implemented yet. */
	return -1;
}

/* Marshall a getgrouplist() result into the NSCD format. */
static int marshall_igr(int group_count, gid_t * groups, void ** reply, int32_t * reply_len, time_t * refresh_interval)
{
	initgr_response_header header;
	int32_t * gids;
	int i;
	
	header.version = NSCD_VERSION;
	header.found = group_count > 1;
	header.ngrps = group_count - 1;
	
	*reply_len = sizeof(header) + header.ngrps * sizeof(int32_t);
	*reply = malloc(*reply_len);
	if(!*reply)
		return -1;
	memcpy(*reply, &header, sizeof(header));
	
	gids = (int32_t *) (*reply + sizeof(header));
	for(i = 0; i < group_count; i++)
		/* ignore the -1 that we put there in generate_igr_reply() */
		if(groups[i] != -1)
			*gids++ = groups[i];
	
	*refresh_interval = 600;
	
	return 0;
}

static int generate_pwd_reply(request_header * req, void * key, uid_t uid, void ** reply, int32_t * reply_len, time_t * refresh_interval)
{
	struct passwd * pwd = NULL;
	char stack_buffer[512];
	char * buffer = stack_buffer;
	size_t buffer_size = sizeof(stack_buffer);
	long uid_value = -1;
	int error;
	
	if(req->type == GETPWBYUID)
	{
		char * end;
		uid_value = strtol(key, &end, 10);
		if(*end || end != key + req->key_len - 1)
			return -1;
	}
	
	/* We keep trying to get the reply with larger and larger buffers, until
	 * either we fail to allocate a buffer or we succeed. The first try uses
	 * a small buffer on the stack. */
	for(;;)
	{
		if(req->type == GETPWBYUID)
			error = getpwuid_r(uid_value,
			                   (struct passwd *) buffer,
			                   buffer + sizeof(struct passwd),
			                   buffer_size - sizeof(struct passwd),
			                   &pwd);
		else
			error = getpwnam_r(key,
			                   (struct passwd *) buffer,
			                   buffer + sizeof(struct passwd),
			                   buffer_size - sizeof(struct passwd),
			                   &pwd);
		if(error > 0)
			error = -error;
		if(error != -ERANGE)
			break;
		if(buffer != stack_buffer)
			free(buffer);
		/* The buffer size must be able to grow arbitrarily large
		 * (system memory permitting) to accomodate arbitrarily large
		 * data structures. They're all coming from trusted databases
		 * though, so this can't be used to consume all the RAM. */
		buffer_size *= 2;
		buffer = malloc(buffer_size);
		if(!buffer)
			return -1;
	}
	
	if(!pwd && !error)
		error = -ENOENT;
	error = marshall_pwd(error, pwd, reply, reply_len, refresh_interval);
	if(buffer != stack_buffer)
		free(buffer);
	return error;
}

static int generate_grp_reply(request_header * req, void * key, uid_t uid, void ** reply, int32_t * reply_len, time_t * refresh_interval)
{
	struct group * grp = NULL;
	char stack_buffer[1024];
	char * buffer = stack_buffer;
	size_t buffer_size = sizeof(stack_buffer);
	long gid_value = -1;
	int error;
	
	if(req->type == GETGRBYGID)
	{
		char * end;
		gid_value = strtol(key, &end, 10);
		if(*end || end != key + req->key_len - 1)
			return -1;
	}
	
	/* We keep trying to get the reply with larger and larger buffers, until
	 * either we fail to allocate a buffer or we succeed. The first try uses
	 * a small buffer on the stack. */
	for(;;)
	{
		if(req->type == GETGRBYGID)
			error = getgrgid_r(gid_value,
			                   (struct group *) buffer,
			                   buffer + sizeof(struct group),
			                   buffer_size - sizeof(struct group),
			                   &grp);
		else
			error = getgrnam_r(key,
			                   (struct group *) buffer,
			                   buffer + sizeof(struct group),
			                   buffer_size - sizeof(struct group),
			                   &grp);
		if(error > 0)
			error = -error;
		if(error != -ERANGE)
			break;
		if(buffer != stack_buffer)
			free(buffer);
		/* The buffer size must be able to grow arbitrarily large
		 * (system memory permitting) to accomodate arbitrarily large
		 * data structures. They're all coming from trusted databases
		 * though, so this can't be used to consume all the RAM. */
		buffer_size *= 2;
		buffer = malloc(buffer_size);
		if(!buffer)
			return -1;
	}
	
	if(!grp && !error)
		error = -ENOENT;
	error = marshall_grp(error, grp, reply, reply_len, refresh_interval);
	if(buffer != stack_buffer)
		free(buffer);
	return error;
}

static int generate_hst_reply(request_header * req, void * key, uid_t uid, void ** reply, int32_t * reply_len, time_t * refresh_interval)
{
	struct hostent * hst = NULL;
	char stack_buffer[512];
	char * buffer = stack_buffer;
	size_t buffer_size = sizeof(stack_buffer);
	int error, h_error = 0;
	
	if(req->type == GETHOSTBYADDR && req->key_len != NS_INADDRSZ)
		return -1;
	if(req->type == GETHOSTBYADDRv6 && req->key_len != NS_IN6ADDRSZ)
		return -1;
	
	/* We keep trying to get the reply with larger and larger buffers, until
	 * either we fail to allocate a buffer or we succeed. The first try uses
	 * a small buffer on the stack. */
	for(;;)
	{
		if(req->type == GETHOSTBYNAME)
			error = gethostbyname2_r(key, AF_INET,
			                         (struct hostent *) buffer,
			                         buffer + sizeof(struct hostent),
			                         buffer_size - sizeof(struct hostent),
			                         &hst, &h_error);
		else if(req->type == GETHOSTBYNAMEv6)
			error = gethostbyname2_r(key, AF_INET6,
			                         (struct hostent *) buffer,
			                         buffer + sizeof(struct hostent),
			                         buffer_size - sizeof(struct hostent),
			                         &hst, &h_error);
		else if(req->type == GETHOSTBYADDR)
			error = gethostbyaddr_r(key, NS_INADDRSZ, AF_INET,
			                        (struct hostent *) buffer,
			                        buffer + sizeof(struct hostent),
			                        buffer_size - sizeof(struct hostent),
			                        &hst, &h_error);
		else
			error = gethostbyaddr_r(key, NS_IN6ADDRSZ, AF_INET6,
			                        (struct hostent *) buffer,
			                        buffer + sizeof(struct hostent),
			                        buffer_size - sizeof(struct hostent),
			                        &hst, &h_error);
		if(error > 0)
			error = -error;
		if(error != -ERANGE)
			break;
		if(buffer != stack_buffer)
			free(buffer);
		/* The buffer size must be able to grow arbitrarily large
		 * (system memory permitting) to accomodate arbitrarily large
		 * data structures. They're all coming from trusted databases
		 * though, so this can't be used to consume all the RAM. */
		buffer_size *= 2;
		buffer = malloc(buffer_size);
		if(!buffer)
			return -1;
	}
	
	error = marshall_hst(h_error, hst, reply, reply_len, refresh_interval);
	if(buffer != stack_buffer)
		free(buffer);
	return error;
}

static int generate_ai_reply(request_header * req, void * key, uid_t uid, void ** reply, int32_t * reply_len, time_t * refresh_interval)
{
	/* This function would generate the getaddrinfo reply. Since Google
	 * doesn't use the host cache anyway, it is not implemented yet. */
	(void) &marshall_ai;
	return -1;
}

static int generate_igr_reply(request_header * req, void * key, uid_t uid, void ** reply, int32_t * reply_len, time_t * refresh_interval)
{
	gid_t stack_groups[32];
	gid_t * groups = stack_groups;
	int group_count = sizeof(stack_groups) / sizeof(stack_groups[0]);
	int error;
	
	/* we use -1 as "not a real group" */
	error = getgrouplist((char *) key, -1, groups, &group_count);
	if(error < 0)
	{
		groups = malloc(group_count * sizeof(*groups));
		if(!groups)
			return -1;
		error = getgrouplist((char *) key, -1, groups, &group_count);
		if(error < 0)
		{
			free(groups);
			return -1;
		}
	}
	
	error = marshall_igr(group_count, groups, reply, reply_len, refresh_interval);
	if(groups != stack_groups)
		free(groups);
	return error;
}

/* This is the background GET*ENT iteration thread. */
static void * ent_thread(void * arg)
{
	struct ent_info * info = (struct ent_info *) arg;
	request_header req = {version: NSCD_VERSION, type: info->type};
	uid_t uid = -1;
	char key[16];
	int index = 0;
	
	if(debug)
		printf("ent_thread() starting\n");
	if(info->type == GETPWENT)
		setpwent();
	else
		setgrent();
	for(;;)
	{
		int r;
		void * reply;
		int32_t reply_len;
		time_t refresh_interval;
		union {
			struct passwd * pwd;
			struct group * grp;
			void * data;
		} data;
		if(info->type == GETPWENT)
		{
			data.pwd = getpwent();
			r = marshall_pwd(0, data.pwd, &reply, &reply_len, &refresh_interval);
		}
		else
		{
			data.grp = getgrent();
			r = marshall_grp(0, data.grp, &reply, &reply_len, &refresh_interval);
		}
		
		/* must lock cache_mutex first */
		pthread_mutex_lock(&cache_mutex);
		pthread_mutex_lock(&info->busy_mutex);
		
		if(r >= 0)
		{
			struct cache_entry * entry;
			snprintf(key, sizeof(key), "%d%n", -index - 1, &req.key_len);
			req.key_len++;
			
			if(cache_search(&req, key, uid, &entry) < 0)
			{
				/* it's not in the cache, so add it */
				if(cache_add(&req, key, uid, reply, reply_len, 0, refresh_interval) < 0)
					free(reply);
			}
			else
			{
				if(debug)
					printf("Refreshing index %d (key %s, length %d)\n", index, key, req.key_len);
				/* It's already in the cache, so just update the
				 * reply and the expiration time. */
				free(entry->reply);
				entry->reply = reply;
				entry->reply_len = reply_len;
				entry->expire_time = time(NULL) + refresh_interval;
				entry->refresh_interval = refresh_interval;
				entry->refreshes++;
			}
		}
		if(info->wait_index == index++)
		{
			if(debug)
				printf("Notifying waiter for index %d\n", info->wait_index);
			/* there should only be one waiter, but broadcast anyway */
			pthread_cond_broadcast(&info->wait_done);
		}
		
		pthread_mutex_unlock(&info->busy_mutex);
		pthread_mutex_unlock(&cache_mutex);
		
		if(!data.data)
			break;
	}
	if(info->type == GETPWENT)
		endpwent();
	else
		endgrent();
	
	pthread_mutex_lock(&info->busy_mutex);
	info->thread_busy = 0;
	/* somebody might be waiting on a larger index than there actually is */
	pthread_cond_broadcast(&info->wait_done);
	pthread_mutex_unlock(&info->busy_mutex);
	if(debug)
		printf("ent_thread() terminating\n");
	
	return NULL;
}

/* This function is protected in thread.c by one of pwent_query_mutex or grent_query_mutex. */
int request_ent_cache(request_header * req, void * key, uid_t uid)
{
	struct ent_info * info;
	
	char * end;
	long index = strtol(key, &end, 10);
	if(*end || end != key + req->key_len - 1)
		return -1;
	index = -index - 1;
	if(index < 0)
		return -1;
	
	/* returns when the request has been fulfilled */
	if(req->type == GETPWENT)
		info = &pwent_info;
	else if(req->type == GETGRENT)
		info = &grent_info;
	else
		return -1;
	
	pthread_mutex_lock(&info->busy_mutex);
	pthread_mutex_unlock(&cache_mutex);
	info->wait_index = index;
	if(!info->thread_busy)
	{
		pthread_t thread;
		int r;
		info->thread_busy = 1;
		if(debug)
			printf("Starting iteration thread\n");
		r = pthread_create(&thread, NULL, ent_thread, info);
		if(r < 0)
		{ 
			info->thread_busy = 0;
			pthread_mutex_unlock(&info->busy_mutex);
			pthread_mutex_lock(&cache_mutex);
			return -1;
		}
		pthread_detach(thread);
	}
	/* wait for a signal */
	while(pthread_cond_wait(&info->wait_done, &info->busy_mutex) < 0);
	pthread_mutex_unlock(&info->busy_mutex);
	pthread_mutex_lock(&cache_mutex);
	
	return 0;
}

/* Return values:
 * Negative on error
 * 0 on success with a reusable socket
 * 1 on success with a non-reusable socket */
int generate_reply(request_header * req, void * key, uid_t uid, void ** reply, int32_t * reply_len, time_t * refresh_interval)
{
	switch(req->type)
	{
		case GETPWBYNAME:
		case GETPWBYUID:
			return generate_pwd_reply(req, key, uid, reply, reply_len, refresh_interval);
		case GETGRBYNAME:
		case GETGRBYGID:
			return generate_grp_reply(req, key, uid, reply, reply_len, refresh_interval);
		case GETHOSTBYNAME:
		case GETHOSTBYNAMEv6:
		case GETHOSTBYADDR:
		case GETHOSTBYADDRv6:
			return generate_hst_reply(req, key, uid, reply, reply_len, refresh_interval);
		case GETAI:
			return generate_ai_reply(req, key, uid, reply, reply_len, refresh_interval);
		case INITGROUPS:
			return generate_igr_reply(req, key, uid, reply, reply_len, refresh_interval);
		default:
			return -1;
	}
	return -1;
}

/* These are the replies that are sent when service types are disabled. */
static pw_response_header pw_disabled = {version: NSCD_VERSION, found: -1, pw_name_len: 0, pw_passwd_len: 0, pw_uid: -1, pw_gid: -1, pw_gecos_len: 0, pw_dir_len: 0, pw_shell_len: 0};
static gr_response_header gr_disabled = {version: NSCD_VERSION, found: -1, gr_name_len: 0, gr_passwd_len: 0, gr_gid: -1, gr_mem_cnt: 0};
static hst_response_header hst_disabled = {version: NSCD_VERSION, found: -1, h_name_len: 0, h_aliases_cnt: 0, h_addrtype: -1, h_length: -1, h_addr_list_cnt: 0, error: NETDB_INTERNAL};
static ai_response_header ai_disabled = {version: NSCD_VERSION, found: -1, naddrs: 0, addrslen: -1, canonlen: -1, error: -1};

int generate_disabled_reply(request_type type, void ** reply, int32_t * reply_len)
{
	switch(type)
	{
		case GETPWBYNAME:
		case GETPWBYUID:
		case GETPWENT:
			*reply = &pw_disabled;
			*reply_len = sizeof(pw_disabled);
			return 0;
		case GETGRBYNAME:
		case GETGRBYGID:
		case GETGRENT:
		case INITGROUPS:
			*reply = &gr_disabled;
			*reply_len = sizeof(gr_disabled);
			return 0;
		case GETHOSTBYNAME:
		case GETHOSTBYNAMEv6:
		case GETHOSTBYADDR:
		case GETHOSTBYADDRv6:
			*reply = &hst_disabled;
			*reply_len = sizeof(hst_disabled);
			return 0;
		case GETAI:
			/* The glibc version of nscd actually sends a
			 * hst_response_header for disabled host service,
			 * because it doesn't differentiate between
			 * GETHOST* and GETAI. We do better, because
			 * it helps with reusable sockets. */
			*reply = &ai_disabled;
			*reply_len = sizeof(ai_disabled);
			return 0;
		default:
			return -1;
	}
	return -1;
}
