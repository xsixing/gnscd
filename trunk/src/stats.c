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

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include "nscd.h"

/* This function is run when a client connects and requests stats. */
void send_stats(int client, uid_t uid)
{
	char * stats = "Compiled on " __DATE__ " at "__TIME__ "\n";
	/* FIXME send some real stats */
	write(client, stats, strlen(stats) + 1);
}

/* This function is run when gnscd is run with -g, and contacts the running
 * instance of gnscd to get the stats. */
void get_stats(void)
{
	request_header req = {version: NSCD_VERSION, type: GETSTAT, key_len: 0};
	char buffer[1024];
	int got;
	
	struct sockaddr_un sun;
	int sock = socket(PF_UNIX, SOCK_STREAM, 0);
	if(sock < 0)
	{
		perror("socket");
		return;
	}
	
	sun.sun_family = AF_UNIX;
	strcpy(sun.sun_path, NSCD_SOCKET);
	if(connect(sock, (struct sockaddr *) &sun, sizeof(sun)) < 0 && errno != EINPROGRESS)
	{
		perror(NSCD_SOCKET);
		close(sock);
		return;
	}
	
	/* write the request */
	write(sock, &req, sizeof(req));
	
	/* get the reply and send it to standard output */
	got = read(sock, buffer, sizeof(buffer));
	while(got > 0 || errno == EINTR)
	{
		if(got > 0)
			write(1, buffer, got);
		got = read(sock, buffer, sizeof(buffer));
	}
	
	close(sock);
}
