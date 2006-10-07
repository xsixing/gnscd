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
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <sys/un.h>

#include "nscd.h"
#include "cache.h"
#include "misc.h"

#define NSCD_PIDFILE "/var/run/gnscd.pid"

int debug = 0;

/* This internal glibc function is called to disable trying to contact nscd. We
 * are nscd, so we need to be able to do the lookups and not try to recurse. */
void __nss_disable_nscd(void);

static int wrote_pidfile = 0;

static void signal_handler(int signal)
{
	if(wrote_pidfile)
		unlink(NSCD_PIDFILE);
	unlink(NSCD_SOCKET_OLD);
	unlink(NSCD_SOCKET);
	exit(0);
}

static int write_pid(void)
{
	FILE * pid = fopen(NSCD_PIDFILE, "w");
	if(!pid)
		return -1;
	fprintf(pid, "%d\n", getpid());
	fclose(pid);
	wrote_pidfile = 1;
	return 0;
}

#define FAIL_OPEN(string) do { perror(string); close(sock); return -1; } while(0)

/* open a listening nscd server socket */
static int open_socket(const char * name)
{
	struct sockaddr_un sun;
	int sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if(sock < 0)
		FAIL_OPEN("socket()");
	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, name);
	unlink(name);
	if(bind(sock, (struct sockaddr *) &sun, sizeof(sun)) < 0)
		FAIL_OPEN("bind()");
	if(fcntl(sock, F_SETFL, fcntl(sock, F_GETFL) | O_NONBLOCK) < 0)
		FAIL_OPEN("fcntl()");
	if(chmod(name, 0666) < 0)
		FAIL_OPEN("chmod()");
	if(listen(sock, 32) < 0)
		FAIL_OPEN("listen()");
	return sock;
}

int main(int argc, char * argv[])
{
	struct pollfd pfd[2];
	
	if(argc > 1 && !strcmp(argv[1], "-g"))
	{
		get_stats();
		exit(0);
	}
	
	/* register cleanup hooks */
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	
	pfd[0].fd = open_socket(NSCD_SOCKET);
	if(pfd[0].fd < 0)
		return 1;
	pfd[1].fd = open_socket(NSCD_SOCKET_OLD);
	if(pfd[1].fd < 0)
	{
		close(pfd[0].fd);
		return 1;
	}
	
	pfd[0].events = POLLIN;
	pfd[1].events = POLLIN;
	
	/* In debug mode, we don't daemonize. We also print debugging
	 * information about what is going on inside gnscd. */
	if(argc < 2 || strcmp(argv[1], "-d"))
	{
		/* become a daemon */
		daemon(0, 0);
		setsid();
		write_pid();
		
		/* ignore job control signals */
		signal(SIGTTOU, SIG_IGN);
		signal(SIGTTIN, SIG_IGN);
		signal(SIGTSTP, SIG_IGN);
	}
	else
		debug = 1;
	
	/* don't die if a client closes a socket on us */
	signal(SIGPIPE, SIG_IGN);
	
	/* make sure we don't get recursive calls */
	__nss_disable_nscd();
	
	if(cache_init() < 0)
		exit(1);
	
	/* listen for clients and dispatch them to threads */
	for(;;)
	{
		int i;
		
		if(poll(pfd, 2, -1) < 0)
			if(errno != EINTR)
				exit(1);
		
		for(i = 0; i < 2; i++)
		{
			int client;
			if(!pfd[i].revents)
				continue;
			client = accept(pfd[i].fd, NULL, NULL);
			if(client < 0)
				/* FIXME: WTF? */
				continue;
			if(dispatch_client(client) < 0)
				close(client);
		}
	}	
	
	return 0;
}
