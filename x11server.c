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
#include <stdarg.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <sys/un.h>
#include <netdb.h>

#include "xtrace.h"

int listenForClients(const char *displayname,int family,int display) {
	int fd;
	const char *msg;
	struct sockaddr_in inaddr;
	struct sockaddr_un unaddr;
	struct sockaddr *address;
	size_t addresslen;

	fd = socket(family,SOCK_STREAM,0);
	if( fd < 0 )  {
		int e = errno;
		fprintf(stderr,"Error opening socket for '%s': %d=%s\n",displayname,e,strerror(e));
		return -1;
	}
	if( family == AF_INET ) {
		int tmp=1;

		inaddr.sin_family = family;
		inaddr.sin_port = calculateTCPport(display);
		inaddr.sin_addr.s_addr = htonl(INADDR_ANY);
		setsockopt(fd,SOL_SOCKET,SO_KEEPALIVE,(char *)&tmp,sizeof(tmp));
		address = (struct sockaddr*)&inaddr;
		addresslen = sizeof(inaddr);
	} else {
		msg = generateSocketName(&unaddr,display);
		if( msg != NULL )  {
			close(fd);
			fprintf(stderr,"Error calculating socket name for '%s': %s\n",displayname,msg);
			return -1;
		}
		unlink(unaddr.sun_path);
		address = (struct sockaddr*)&unaddr;
		addresslen = sizeof(unaddr);
	}
	if( bind(fd,address,addresslen) < 0 ) {
		int e = errno;
		close(fd);
		fprintf(stderr,"Error binding socket for '%s': %d=%s\n",displayname,e,strerror(e));
		return -1;
	}
	if( listen(fd,20) < 0 ) {
		int e = errno;
		close(fd);
		fprintf(stderr,"Error listening for '%s': %d=%s\n",displayname,e,strerror(e));
		return -1;
	}
	return fd;
}

#ifndef HAVE_ASPRINTF
#warning using asprint replacement
static int asprintf(char **r, const char *fmt, ...) {
	va_list ap;
	/* that's ugly, but we will not need longer values here... */
	char buffer[100];
	int len;

	va_start(ap, fmt);
	len = vsnprintf(buffer, 99, fmt, ap);
	buffer[99] = '\0';
	*r = strdup(buffer);
	if( *r == NULL )
		return -1;
	return len;
}
#endif

int acceptClient(int family,int listener, char **from) {
	int fd;
	socklen_t len;

	if( family == AF_INET ) {
		struct sockaddr_in inaddr;

		len = sizeof(inaddr);
		fd = accept(listener, (struct sockaddr*)&inaddr, &len);
		if( asprintf(from,"%s:%d",inet_ntoa(inaddr.sin_addr),ntohs(inaddr.sin_port)) < 0 || *from == NULL ) {
			close(fd);
			return -1;
		}

	} else if( family == AF_UNIX ) {
		struct sockaddr_un unaddr;

		len = sizeof(unaddr);
		fd = accept(listener, (struct sockaddr*)&unaddr, &len);
		if( len > sizeof(sa_family_t) ) {
			*from = strndup(unaddr.sun_path,len-sizeof(sa_family_t));
		} else
			*from = strdup("unknown(local)");
		if( *from == NULL ) {
			close(fd);
			return -1;
		}
	} else
		return -1;

	return fd;
}
