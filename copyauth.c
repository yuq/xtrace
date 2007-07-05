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

#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/select.h>
#include <unistd.h>
#include <fcntl.h>

#include "xtrace.h"

/* This file is responsible for getting the autorisation tokens of the
 * device we are connecting to and saving them for the fake device we
 * are creating. This is done by calling xauth. (This allows to
 * to set PATH to an alternative utility to do even more funny things,
 * and is simpler than reimplementing xauth by using libXau) */

static inline ssize_t readtoend(int fd, char *buffer, size_t len) {
	size_t bytesgottotal = 0;
	ssize_t bytesgotlast;

	do {
		bytesgotlast = read(fd,buffer+bytesgottotal,len-bytesgottotal);
		if( bytesgotlast < 0 ) {
			int e = errno;
			fprintf(stderr,"Error reading from xauth pipe: %d=%s\n",e,strerror(e));
			return bytesgotlast;
		} else if( bytesgotlast > 0 ) {
			bytesgottotal += bytesgotlast;
			if( bytesgottotal >= len ) {
				fprintf(stderr,"Too much data from xauth command: more than %u\n",(unsigned int)len);
				return -1;
			}
		}
	} while( bytesgotlast != 0 );
	return bytesgottotal;
}
static inline bool parseauthdata(char *buffer,const char **name,const char **data) {
	char *p;
	bool foundsomething = false;
	char *thisname;
	char *thisdata;

	p = buffer;
	do {
		while( *p != '\0' && *p != '\n' && *p != ' ' && *p != '\t')
			p++;
		while( *p != '\0' && *p != '\n' && (*p == ' ' || *p == '\t') )
			p++;
		thisname = p;
		while( *p != '\0' && *p != '\n' && *p != ' ' && *p != '\t' )
			p++;
		if( *p != '\0' && *p != '\n' ) {
			*p = '\0';
			p++;
		}
		while( *p != '\0' && *p != '\n' && (*p == ' ' || *p == '\t') )
			p++;
		thisdata = p;
		while( *p != '\0' && *p != '\n' && *p != ' ' && *p != '\t' )
			p++;
		if( *p != '\0' && *p != '\n' ) {
			*p = '\0';
			p++;
		}
		while( *p != '\0' && *p != '\n' && (*p == ' ' || *p == '\t') )
			p++;
		if( *p == '\n' ) {
			*p = '\0';
		} else if( *p != '\0' ) {
			fprintf(stderr,"Error parsing xauth list data: more than three things in a line!\n");
			return false;
		}
		if( thisname[0] == '\0' || thisdata[0] == '\0' ) {
			fprintf(stderr,"Error parsing xauth list data: less than three things in a line!\n");
			return false;
		}
		if( strcmp(thisname,"MIT-MAGIC-COOKIE-1") == 0) {
			*name = thisname;
			*data = thisdata;
			foundsomething = true;
		}
	} while( *p != '\0' );
	return foundsomething;
}

bool copy_authentication(const char *fakedisplay,const char *display, const char *infile, const char *outfile) {
	int pipe_fds[2];
	int r,e;
	pid_t pid,waitresult;
	/* if this is not enough, copy manually */
	char buffer[4096];
	ssize_t bytesgot;
#ifdef STUPIDCC
	const char *name = NULL, *data = NULL;
#else
	const char *name,*data;
#endif
	int status;

	if( strncmp(display,"localhost:",10) == 0 ) {
		/* copy with remote X DISPLAYs */
		display += 9;
	}

	pid = fork();
	if( pid < 0 ) {
		e = errno;
		fprintf(stderr,"Error forking: %d=%s\n",e,strerror(e));
		return false;
	}
	if( pid == 0 ) {
		int fd = open("/dev/null",O_RDONLY);
		if( fd >= 0 ) {
			(void)dup2(fd,0);
			(void)dup2(fd,1);
			if( fd > 2 )
				(void)close(fd);
		}
		if( outfile != NULL )
			r = execlp("xauth","xauth","-f",outfile,"remove",fakedisplay,(char*)NULL);
		else
			r = execlp("xauth","xauth","remove",fakedisplay,(char*)NULL);
		exit(EXIT_FAILURE);
	}
	do {
		waitresult = waitpid(pid,&status,0);
	} while( waitresult < 0 && errno == EINTR );
	if( waitresult < 0 ) {
		e = errno;
		fprintf(stderr,"Error waiting for xauth remove: %d=%s\n",e,strerror(e));
		return false;
	}
	if( !WIFEXITED(status) ) {
		fprintf(stderr,"Abnormal termination of xauth remove!\n");
		return false;
	}
	if( WEXITSTATUS(status) != 0 ) {
		fprintf(stderr,"xauth remove terminated with exit code %d!\n",(int)(WEXITSTATUS(status)));
		return false;
	}
	r = pipe(pipe_fds);
	if( r != 0 ) {
		e = errno;
		fprintf(stderr,"Error creating pipe: %d=%s\n",e,strerror(e));
		return false;
	}
	pid = fork();
	if( pid < 0 ) {
		e = errno;
		fprintf(stderr,"Error forking: %d=%s\n",e,strerror(e));
		return false;
	}
	if( pid == 0 ) {
		int fd = open("/dev/null",O_RDONLY);
		if( fd >= 0 ) {
			(void)dup2(fd,0);
			if( fd > 2 )
				(void)close(fd);
		}
		(void)close(pipe_fds[0]);
		r = dup2(pipe_fds[1],1);
		if( r < 0 ) {
			e = errno;
			fprintf(stderr,"Error connecting pipe to stdin in child process: %d=%s\n",e,strerror(e));
			exit(EXIT_FAILURE);
		}
		(void)close(pipe_fds[1]);
		if( infile != NULL )
			r = execlp("xauth","xauth","-f",infile,"list",display,(char*)NULL);
		else
			r = execlp("xauth","xauth","list",display,(char*)NULL);
		exit(EXIT_FAILURE);
	}
	(void)close(pipe_fds[1]);
	bytesgot = readtoend(pipe_fds[0],buffer,sizeof(buffer)-1);
	if( bytesgot < 0 ) {
		return false;
	}
	r = close(pipe_fds[0]);
	if( r != 0 ) {
		e = errno;
		fprintf(stderr,"Error reading from pipe from xauth: %d=%s\n",e,strerror(e));
		return false;
	}
	buffer[bytesgot-1] = '\0';
	do {
		waitresult = waitpid(pid,&status,0);
	} while( waitresult < 0 && errno == EINTR );
	if( waitresult < 0 ) {
		e = errno;
		fprintf(stderr,"Error waiting for xauth list: %d=%s\n",e,strerror(e));
		return false;
	}
	if( !WIFEXITED(status) ) {
		fprintf(stderr,"Abnormal termination of xauth list!\n");
		return false;
	}
	if( WEXITSTATUS(status) != 0 ) {
		fprintf(stderr,"xauth list terminated with exit code %d!\n",(int)(WEXITSTATUS(status)));
		return false;
	}
	if( !parseauthdata(buffer,&name,&data) ) {
		return false;
	}
	pid = fork();
	if( pid < 0 ) {
		e = errno;
		fprintf(stderr,"Error forking: %d=%s\n",e,strerror(e));
		return false;
	}
	if( pid == 0 ) {
		int fd = open("/dev/null",O_RDONLY);
		if( fd >= 0 ) {
			(void)dup2(fd,0);
			(void)dup2(fd,1);
			if( fd > 2 )
				(void)close(fd);
		}
		if( outfile != NULL )
			r = execlp("xauth","xauth","-f",outfile,"add",fakedisplay,name,data,(char*)NULL);
		else
			r = execlp("xauth","xauth","add",fakedisplay,name,data,(char*)NULL);
		exit(EXIT_FAILURE);
	}
	do {
		waitresult = waitpid(pid,&status,0);
	} while( waitresult < 0 && errno == EINTR );
	if( waitresult < 0 ) {
		e = errno;
		fprintf(stderr,"Error waiting for xauth add: %d=%s\n",e,strerror(e));
		return false;
	}
	if( !WIFEXITED(status) ) {
		fprintf(stderr,"Abnormal termination of xauth add!\n");
		return false;
	}
	if( WEXITSTATUS(status) != 0 ) {
		fprintf(stderr,"xauth add terminated with exit code %d!\n",(int)(WEXITSTATUS(status)));
		return false;
	}
	return true;
}
