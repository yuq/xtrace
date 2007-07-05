/*  This file is part of "xtrace"
 *  Copyright (C) 2005 Bernhard R. Link
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <config.h>

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netdb.h>

#include "xtrace.h"

int connectToServer(const char *displayname,int family,const char *hostname,int display) {
	const char *msg;
	int fd;

	fd = socket(family,SOCK_STREAM,0);
	if( fd < 0 )  {
		int e = errno;
		fprintf(stderr,"Error opening socket for '%s': %d=%s\n",displayname,e,strerror(e));
		return fd;
	}
	if( family == AF_INET ) {
		struct sockaddr_in addr;
		struct addrinfo hints;
		struct addrinfo *res;
		int tmp=1;
		int r;

		memset(&hints,0,sizeof(struct addrinfo));
		hints.ai_family = family;
		hints.ai_socktype = SOCK_STREAM;
		r = getaddrinfo(hostname, NULL, &hints, &res);
		if( r != 0 ) {
			close(fd);
			fprintf(stderr,"Error resolving hostname '%s' taken from '%s'\nError was: %s\n",hostname,displayname,gai_strerror(r));
			return -1;
		}
		assert( res->ai_addrlen == sizeof(addr));
		memcpy(&addr,res->ai_addr,sizeof(addr));
		freeaddrinfo(res);
		addr.sin_port = calculateTCPport(display);
		setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,(char *)&tmp,sizeof(tmp));
		if( connect(fd,(struct sockaddr*)&addr,sizeof(addr)) < 0 ) {
			int e = errno;
			close(fd);
			fprintf(stderr,"Error connecting to '%s' (resolved to '%s') for '%s': %d=%s\n",hostname,inet_ntoa(addr.sin_addr),displayname,e,strerror(e));
			return -1;
		}
	} else {
		struct sockaddr_un addr;

		msg = generateSocketName(&addr,display);
		if( msg != NULL )  {
			close(fd);
			fprintf(stderr,"Error calculating socket name for '%s': %s\n",displayname,msg);
			return -1;
		}

		if( connect(fd,(struct sockaddr*)&addr,sizeof(addr)) < 0 ) {
			int e = errno;
			close(fd);
			fprintf(stderr,"Error connecting to unix socket '%s' for '%s': %d=%s\n",addr.sun_path,displayname,e,strerror(e));
			return -1;
		}
	}
	return fd;
}
