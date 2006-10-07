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
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/poll.h>
#include <sys/un.h>
#include <sys/uio.h>

#include "nscd.h"
#include "misc.h"
#include "cache.h"
#include "lookup.h"

/* like read(), but times out if no data can be read */
static int read_timeout(int fd, void * buf, size_t len, int timeout, int is_nonblock)
{
	int r;
	struct pollfd pfd;
	
	if(is_nonblock)
	{
		r = read(fd, buf, len);
		if(r > 0)
			return r;
	}
	
	pfd.fd = fd;
	pfd.events = POLLIN;
	r = poll(&pfd, 1, timeout);
	if(r < 0)
		return r;
	if(!r)
	{
		errno = ETIMEDOUT;
		return -1;
	}
	
	return read(fd, buf, len);
}

/* like write(), but keep retrying unless we fail for a timeout period */
static int write_all(int fd, const void * buf, size_t len, int timeout)
{
	size_t n = len;
	ssize_t ret;
	do {
		ret = write(fd, buf, n);
		if(ret <= 0)
		{
			if(errno == EINTR)
				continue;
			if(errno == EAGAIN)
			{
				struct pollfd pfd;
				pfd.fd = fd;
				pfd.events = POLLOUT;
				if(poll(&pfd, 1, timeout) == 1)
					continue;
			}
			break;
		}
		buf += ret;
		n -= ret;
	} while(n > 0);
	if(debug && ret <= 0 && errno == EPIPE)
		printf("Client %d closed connection on us! (wrote %d bytes)\n", fd, len - n);
	return (len == n) ? ret : len - n;
}

/* return 1 if the service is disabled, 0 otherwise */
static int is_disabled(request_type type)
{
	switch(type)
	{
		case GETPWBYNAME:
		case GETPWBYUID:
			return 0;
		case GETGRBYNAME:
		case GETGRBYGID:
		case INITGROUPS:
			return 0;
		case GETHOSTBYNAME:
		case GETHOSTBYNAMEv6:
		case GETHOSTBYADDR:
		case GETHOSTBYADDRv6:
			return 1;
		case GETPWENT:
		case GETGRENT:
			return 0;
		case GETAI:
			/* NOT IMPLEMENTED */
			return 1;
		default:
			return -1;
	}
}

/* Return values:
 * Negative on error
 * 0 on success with a reusable socket
 * 1 on success with a non-reusable socket */
static int process_request(int client, uid_t uid, request_header * req, void * key)
{
	struct cache_entry * entry;
	void * reply;
	int32_t reply_len;
	time_t refresh_interval;
	pthread_mutex_t * extra_mutex = NULL;
	int r;
	
	if(debug)
		printf("Got request type %d (key = [%s]) from UID %d on FD %d\n", req->type, (char *) key, uid, client);
	if(req->type > LASTDBREQ && req->type != GETPWENT && req->type != GETGRENT && req->type != GETAI && req->type != INITGROUPS)
	{
		if(req->type == SHUTDOWN)
			exit(0);
		if(req->type == GETSTAT)
		{
			/* to aid the use of -g in figuring out whether
			 * gnscd is answering queries correctly, grab
			 * the cache mutex and release it */
			pthread_mutex_lock(&cache_mutex);
			pthread_mutex_unlock(&cache_mutex);
			send_stats(client, uid);
		}
		if(req->type == INVALIDATE)
		{
			/* key is "passwd" "group" or "hosts" */
			/* use memcmp not strcmp for security */
			/* if it's hosts, call res_init() */
			/* NOT IMPLEMENTED */
		}
		return 1;
	}
	
	if(is_disabled(req->type))
	{
		if(debug)
			printf("Service type %d disabled\n", req->type);
		r = generate_disabled_reply(req->type, &reply, &reply_len);
		if(r < 0)
			return -1;
		if(write_all(client, reply, reply_len, 200) != reply_len)
			return -1;
		return r;
	}
	
	/* if it is a GET*ENT query, grab the extra mutex */
	if(req->type == GETPWENT)
		extra_mutex = pwent_query_mutex;
	else if(req->type == GETGRENT)
		extra_mutex = grent_query_mutex;
	if(extra_mutex)
		pthread_mutex_lock(extra_mutex);
	
	pthread_mutex_lock(&cache_mutex);
	r = cache_search(req, key, uid, &entry);
	if(r < 0 && extra_mutex)
	{
		if(debug)
			printf("Not in the cache, requesting iteration.\n");
		/* request it */
		r = request_ent_cache(req, key, uid);
		if(r >= 0)
			r = cache_search(req, key, uid, &entry);
	}
	if(r >= 0)
	{
		if(debug)
			printf("Found it in the cache!\n");
		r = entry->close_socket;
		/* reset the refresh count */
		entry->refreshes = 0;
		if(write_all(client, entry->reply, entry->reply_len, 200) != entry->reply_len)
			r = -1;
		pthread_mutex_unlock(&cache_mutex);
		if(extra_mutex)
			pthread_mutex_unlock(extra_mutex);
		return r;
	}
	pthread_mutex_unlock(&cache_mutex);
	
	if(debug)
		printf("Not in the cache.\n");
	
	if(!extra_mutex)
		/* find it */
		r = generate_reply(req, key, uid, &reply, &reply_len, &refresh_interval);
	else
		r = -1;
	
	if(r >= 0)
	{
		int close_socket = r;
		int add_result = -1;
		
		if(write_all(client, reply, reply_len, 200) != reply_len)
		{
			if(debug)
				printf("Failed to write to client %d\n", client);
			r = -1;
		}
		
		pthread_mutex_lock(&cache_mutex);
		/* don't add duplicate entries */
		if(cache_search(req, key, uid, &entry) < 0)
			add_result = cache_add(req, key, uid, reply, reply_len, close_socket, refresh_interval);
		if(add_result < 0)
			/* either it was already in the cache or adding it failed */
			free(reply);
		pthread_mutex_unlock(&cache_mutex);
	}
	
	/* if it was a GET*ENT query, release the extra mutex */
	if(extra_mutex)
		pthread_mutex_unlock(extra_mutex);
	
	return r;
}

/* Return values:
 * Negative on error
 * 0 on success with a reusable socket
 * 1 on success with a non-reusable socket */
static int handle_request(int client, uid_t uid)
{
	request_header req;
	int got;
	char buffer[NSCD_MAXKEYLEN];
	
	/* read the request header, but time out after a short while */
	got = read_timeout(client, &req, sizeof(req), 5000, 1);
	if(debug)
	{
		if(got < 0)
		{
			if(errno == ETIMEDOUT)
				printf("Client %d timed out\n", client);
			else if(errno == ECONNRESET)
				printf("Client %d closed by peer\n", client);
			else
				printf("Client %d error (%s)\n", client, strerror(errno));
		}
		else if(!got)
			printf("Client %d completed\n", client);
	}
	if(got != sizeof(req) || req.version != NSCD_VERSION)
		return -1;
	
	/* glibc nscd limits the key to 1024 bytes, so we will too */
	if(req.key_len < 0 || req.key_len > NSCD_MAXKEYLEN)
		return -1;
	
	if(req.key_len)
	{
		/* read the key, but again time out after a (shorter) while */
		got = read_timeout(client, buffer, req.key_len, 200, 1);
		if(got != req.key_len)
			return -1;
		/* the last character of the key should be null */
		if(buffer[req.key_len - 1])
			return -1;
	}
	else
		buffer[0] = 0;
	
	return process_request(client, uid, &req, buffer);
}

/* this code runs as a thread and handles a single client until it is done */
static void * handle_client_thread(void * arg)
{
	int r, client = (int) arg;
	uid_t uid = -1;
	
	if(fcntl(client, F_SETFL, fcntl(client, F_GETFL) | O_NONBLOCK) < 0)
	{
		close(client);
		return NULL;
	}

#ifdef SO_PEERCRED
	struct ucred caller;
	socklen_t optlen = sizeof(caller);
	if(getsockopt(client, SOL_SOCKET, SO_PEERCRED, &caller, &optlen) < 0)
	{
		close(client);
		return NULL;
	}
	uid = caller.uid;
#else
#warning Not using SO_PEERCRED
#endif
	
	if(debug)
		printf("New client on FD %d\n", client);
	/* continue serving requests until handle_request returns nonzero */
	do {
		r = handle_request(client, uid);
	} while(!r);
	if(debug)
		printf("Closing client on FD %d\n", client);
	
	close(client);
	return NULL;
}

/* start a new thread to handle this client until it is done */
int dispatch_client(int client)
{
	/* FIXME eventually keep a pool of idle threads around */
	pthread_t thread;
	if(pthread_create(&thread, NULL, handle_client_thread, (void *) client) < 0)
		return -1;
	pthread_detach(thread);
	return 0;
}
