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
#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/un.h>

#include "xtrace.h"

#define X_TCP_PORT 6000

const char *parseDisplay(const char *displayname,
		char **protocol, char **hostname,
		int *display, int *screen, int *family ) {
	const char *p = displayname;
	const char *q;

/* Xlib reads display names as
 *            [protocol/] [hostname] : displaynumber [.screennumber]
 */

	/* find the protocol */
	while( *p != '\0' && *p != ':' && *p != '/' )
		p++;
	if( *p == '/' ) {
		if( p != displayname ) {
			*protocol = strndup(displayname,p-displayname);
			if( *protocol == NULL )
				return "Out of Memory";
		} else
			*protocol = NULL;
		p++;
		q = p;
		while( *p != '\0' && *p != ':' )
			p++;
	} else {
		*protocol = NULL;
		q = displayname;
	}
	if( *p == '\0' ) {
		free(*protocol);
		*protocol = NULL;
		return "No colon (':') found";
	}
	if( p != q && !(p-q == 4 && strncmp(q,"unix",4) == 0)) {
		*hostname = strndup(q,p-q);
		if( *hostname == NULL )
			return "Out of Memory";
		if( *protocol == NULL )
			*protocol = strdup("tcp");
	} else {
		*hostname = NULL;
		free(*protocol);
		*protocol = strdup("local");
	}
	if( *protocol == NULL ) {
		free(*hostname);
		*hostname = NULL;
		return "Out of Memory";
	}
	assert( *p == ':' );
	/* TODO: make sure we are in C locale, otherwise this can go wrong */
	p++;
	*display = strtol(p,(char**)&q,10);
	if( *q == '.' ) {
		p = q + 1;
		*screen = strtol(p,(char**)&q,10);
	}
	if( *q != '\0' ) {
		free(*protocol);
		*protocol = NULL;
		free(*hostname);
		*hostname = NULL;
		return "Garbage after first colon, only digits and a single dot allowed";
	}
	if( strcasecmp(*protocol,"inet")==0||strcasecmp(*protocol,"tcp")==0 ) {
		*family = AF_INET;
	} else if( strcasecmp(*protocol,"unix")==0||strcasecmp(*protocol,"local")==0 ) {
		*family = AF_UNIX;
	} else {
		free(*protocol);
		free(*hostname);
		*protocol = NULL;
		*hostname = NULL;
		return "Unknown protocol";
	}
	return NULL;
}

const char *generateSocketName(struct sockaddr_un *addr,int display) {
	addr->sun_family = AF_UNIX;
	/* TODO: length-check ? */
	snprintf(addr->sun_path,sizeof(addr->sun_path),"/tmp/.X11-unix/X%d",display);
	return NULL;
}

uint16_t calculateTCPport(int display) {
	return htons(X_TCP_PORT+display);
}
