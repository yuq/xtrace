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

#define GNU_SOURCE 1
#include <assert.h>
#include <errno.h>
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
		int tmp=1;

		addr.sin_family = AF_INET;
		addr.sin_port = calculateTCPport(display);
		if( isdigit(hostname[0]) )
			addr.sin_addr.s_addr = inet_addr(hostname);
		else {
			struct hostent *h =
				gethostbyname2(hostname,family);
			if( h == NULL ) {
				close(fd);
				fprintf(stderr,"Error resolving hostname '%s' taken from '%s'\n",hostname,displayname);
				return -1;
			}
			assert( h->h_length == sizeof(addr.sin_addr));
			memcpy(&addr.sin_addr,h->h_addr_list[0],sizeof(addr.sin_addr));
		}
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
