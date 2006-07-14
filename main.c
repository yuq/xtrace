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
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02111-1301  USA
 */
#include <config.h>

#include <errno.h>
#include <assert.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/select.h>
#include <unistd.h>
#include <getopt.h>

#include "xtrace.h"

bool readwritedebug = false;
bool copyauth = true;
bool stopwhennone = true;
bool denyallextensions = false;
bool interactive = false;
size_t maxshownlistlen = SIZE_MAX;

const char *out_displayname = NULL;
char *out_protocol,*out_hostname;
int out_family,out_display,out_screen;
const char *in_displayname = NULL;
char *in_protocol,*in_hostname;
int in_family,in_display,in_screen;

struct connection *connections = NULL ;

static void acceptConnection(int listener) {
	struct connection *c;
	static int id = 0;

	c = calloc(1,sizeof(struct connection));
	if( c == NULL ) {
		fprintf(stderr,"Out of memory!\n");
		exit(EXIT_FAILURE);
	}
	c->next = connections;
	c->client_fd = acceptClient(in_family,listener, &c->from);
	if( c->client_fd < 0 ) {
		free(c);
		return;
	}
	fprintf(stderr,"Got connection from %s\n",c->from);
	c->server_fd = connectToServer(out_displayname,out_family,out_hostname,out_display);
	if( c->server_fd < 0 ) {
		close(c->client_fd);
		free(c->from);
		free(c);
		fprintf(stderr,"Error connecting to server %s\n",out_displayname);
		return;
	}
	c->id = id++;
	connections = c;
}


static int mainqueue(int listener) {
	int n,r;
	fd_set readfds,writefds,exceptfds;
	struct connection *c;
	unsigned int allowsent = 1;

	while( 1 ) {
		n =  listener+1;
		FD_ZERO(&readfds);
		FD_ZERO(&writefds);
		FD_ZERO(&exceptfds);
		FD_SET(listener,&readfds);

		c = connections;
		while( c != NULL ) {
			if( c->client_fd != -1 && c->server_fd == -1 && c->servercount == 0 ) {
				close(c->client_fd);
				c->client_fd = -1;
				if( readwritedebug )
					printf("%03d:>:sent EOF\n",c->id);
			}
			if( c->client_fd != -1 ) {
				if( sizeof(c->clientbuffer) > c->clientcount )
					FD_SET(c->client_fd,&readfds);
				FD_SET(c->client_fd,&exceptfds);
				if( c->client_fd >= n )
					n = c->client_fd+1;
				if(c->serverignore > 0 && c->servercount > 0 )
					FD_SET(c->client_fd,&writefds);
			} else if( c->server_fd != -1 && c->clientcount == 0 ) {
				close(c->server_fd);
				c->server_fd = -1;
				if( readwritedebug )
					printf("%03d:<:sent EOF\n",c->id);
			}
			if( c->server_fd != -1 ) {
				if( sizeof(c->serverbuffer) > c->servercount )
					FD_SET(c->server_fd,&readfds);
				FD_SET(c->server_fd,&exceptfds);
				if( c->server_fd >= n )
					n = c->server_fd+1;
				if(c->clientignore > 0 && c->clientcount > 0
						&& allowsent > 0)
					FD_SET(c->server_fd,&writefds);

			}
			if( c->client_fd == -1 && c->server_fd == -1 ) {
				if( c == connections ) {
					free_usedextensions(c->usedextensions);
					free(c->from);
					connections = c->next;
					free(c);
					c = connections;
					if( connections == NULL && stopwhennone )
						return EXIT_SUCCESS;
					continue;
				}
			}
			c = c->next;
		}
		if( interactive ) {
			FD_SET(0,&readfds);
		}

		r = select(n,&readfds,&writefds,&exceptfds,NULL);
		for( c = connections ; c != NULL ; c = c->next ) {
			if( interactive && FD_ISSET(0,&readfds) ) {
				char buffer[201];
				ssize_t isread;
				isread = read(0,buffer,200);
				if( isread == 0 )
					exit(EXIT_SUCCESS);
				if( isread > 0 ) {
					buffer[isread]='\0';
					int number = atoi(buffer);
					if( number <= 0 )
						number = 1;
					allowsent += number;
				}
			}
			if( c->client_fd != -1 ) {
				if( FD_ISSET(c->client_fd,&exceptfds) ) {
					close(c->client_fd);
					c->client_fd = -1;
					printf("%03d: exception in communication with client\n",c->id);
					continue;
				}
				if( FD_ISSET(c->client_fd,&writefds) ) {
					size_t towrite = c->servercount;
					ssize_t written;

					if( c->serverignore < towrite )
						towrite = c->serverignore;
					written = write(c->client_fd,c->serverbuffer,towrite);
					if( written >= 0 ) {
						if( readwritedebug )
							printf("%03d:>:wrote %u bytes\n",c->id,(unsigned int)written);
						if( (size_t)written < c->servercount )
							memmove(c->serverbuffer,c->serverbuffer+written,c->servercount-written);
						c->servercount -= written;
						c->serverignore -= written;
						if( c->servercount == 0 ) {
							if( c->server_fd == -1 ) {
								close(c->client_fd);
								c->client_fd = -1;
								if( readwritedebug )
									printf("%03d:>:send EOF\n",c->id);
								continue;
							}
						} else if( c->serverignore == 0 ) {
							parse_server(c);
						}
					} else {
						int e = errno;
						close(c->client_fd);
						c->client_fd = -1;
						if( readwritedebug )
							printf("%03d: error writing to client: %d=%s\n",c->id,e,strerror(e));
						continue;
					}
				}
				if( FD_ISSET(c->client_fd,&readfds) ) {
					size_t toread = sizeof(c->clientbuffer)-c->clientcount;
					ssize_t wasread = read(c->client_fd,c->clientbuffer+c->clientcount,toread);
					assert( toread > 0 );
					if( wasread > 0 ) {
						if( readwritedebug )
							printf("%03d:<:received %u bytes\n",c->id,(unsigned int)wasread);
						c->clientcount += wasread;
					} else {
						if( readwritedebug )
							printf("%03d:<:got EOF\n",c->id);
						close(c->client_fd);
						c->client_fd = -1;
						continue;
					}
					if( c->clientignore == 0 && c->clientcount > 0) {
						parse_client(c);
					}
				}
			} else if( c->servercount > 0 && c->serverignore > 0 ) {
				unsigned int min;
				/* discard additional events */
				min = c->servercount;
				if( min > c->serverignore )
					min = c->serverignore;
				printf("%03d:s->?: discarded last answer of %u bytes\n",c->id,min);
				if( min < c->servercount )
					memmove(c->serverbuffer,c->serverbuffer+min,c->servercount-min);
				c->servercount -= min;
				c->serverignore -= min;
				if( c->serverignore == 0 && c->servercount > 0 ) {
					parse_server(c);
				}
			}
			if( c->server_fd != -1 ) {
				if( FD_ISSET(c->server_fd,&exceptfds) ) {
					close(c->server_fd);
					c->server_fd = -1;
					printf("%03d: exception in communication with server\n",c->id);
					continue;
				}
				if( FD_ISSET(c->server_fd,&writefds) ) {
					size_t towrite = c->clientcount;
					ssize_t written;

					if( c->clientignore < towrite )
						towrite = c->clientignore;
					written = write(c->server_fd,c->clientbuffer,towrite);
					if( interactive && allowsent > 0 )
						allowsent--;
					if( written >= 0 ) {
						if( readwritedebug )
							printf("%03d:<:wrote %u bytes\n",c->id,(unsigned int)written);
						if( (size_t)written < c->clientcount )
							memmove(c->clientbuffer,c->clientbuffer+written,c->clientcount-written);
						c->clientcount -= written;
						c->clientignore -= written;
						if( c->clientcount != 0 &&
						    c->clientignore == 0 ) {
							parse_client(c);
						}
					} else {
						int e = errno;
						close(c->server_fd);
						c->server_fd = -1;
						if( readwritedebug )
							printf("%03d: error writing to server: %d=%s\n",c->id,e,strerror(e));
						continue;
					}
				}
				if( FD_ISSET(c->server_fd,&readfds) ) {
					size_t toread = sizeof(c->serverbuffer)-c->servercount;
					ssize_t wasread = read(c->server_fd,c->serverbuffer+c->servercount,toread);
					assert( toread > 0 );
					if( wasread > 0 ) {
						if( readwritedebug )
							printf("%03d:>:received %u bytes\n",c->id,(unsigned int)wasread);
						c->servercount += wasread;
					} else {
						if( readwritedebug )
							printf("%03d:>:got EOF\n",c->id);
						close(c->server_fd);
						c->server_fd = -1;
					}
					if( c->serverignore == 0 && c->servercount > 0 ) {
						parse_server(c);
					}
				}
			} else if( c->clientcount > 0 && c->clientignore > 0 ) {
				unsigned int min;
				/* discard additional events */
				min = c->clientcount;
				if( min > c->clientignore )
					min = c->clientignore;
				printf("%03d:<: discarding last request of %u bytes\n",c->id,min);
				if( min < c->clientcount )
					memmove(c->clientbuffer,c->clientbuffer+min,c->clientcount-min);
				c->clientcount -= min;
				c->clientignore -= min;
				if( c->clientignore == 0 && c->clientcount > 0 ) {
					parse_client(c);
				}
			}
		}
		if( FD_ISSET(listener,&readfds) ) {
			acceptConnection(listener);
		}

	}
	
	return EXIT_SUCCESS;
}

#ifndef HAVE_STRNDUP
/* That's not the best possible strndup implementation, but it suffices for what
 * it is used here */
char *strndup(const char *str,size_t n) {
	char *r = malloc(n+1);
	if( r == NULL )
		return r;
	memcpy(r,str,n);
	r[n] = '\0';
	return r;
}
#endif

static const struct option longoptions[] = {
	{"display",	required_argument,	NULL,	'd'},
	{"fakedisplay",	required_argument,	NULL,	'D'},
	{"authfile",	required_argument,	NULL,	'f'},
	{"newauthfile",	required_argument,	NULL,	'F'},
	{"copyauthentication",	no_argument,	NULL,	'c'},
	{"nocopyauthentication",no_argument,	NULL,	'n'},
	{"stopwhendone",	no_argument,	NULL,	's'},
	{"keeprunning",		no_argument,	NULL,	'k'},
	{"denyextensions",	no_argument,	NULL,	'e'},
	{"readwritedebug",	no_argument,	NULL,	'w'},
	{"maxlistlength",required_argument,	NULL,	'm'},
	{"interactive",		no_argument,	NULL,	'i'},
	{"help",		no_argument,	NULL,	'h'},
	{NULL,		0,			NULL,	0}
};

int main(int argc, char *argv[]) {
	int listener,r;
	const char *msg;
	int c;
	const char *out_authfile=NULL, *in_authfile = NULL;

	while( (c=getopt_long(argc,argv,"d:D:f:F:cnskiewm:",longoptions,NULL)) != -1 ) {
		switch( c ) {
		 case 'd':
			 out_displayname = optarg;
			 break;
		 case 'D':
			 in_displayname = optarg;
			 break;
		 case 'f':
			 out_authfile = optarg;
			 break;
		 case 'F':
			 in_authfile = optarg;
			 break;
		 case 'c':
			 copyauth = true;
			 break;
		 case 'n':
			 copyauth = false;
			 break;
		 case 's':
			 stopwhennone = true;
			 break;
		 case 'k':
			 stopwhennone = false;
			 break;
		 case 'e':
			 denyallextensions = true;
			 break;
		 case 'w':
			 readwritedebug = true;
			 break;
		 case 'm':
			 maxshownlistlen = strtoll(optarg,NULL,0);
			 break;
		 case 'i':
			 interactive = true;
			 break;
	         case 'h':
			 printf(
"%s: Dump all X protocol data being tunneled from a fake X display to a real one.\n"
"--display, -d <display to connect to>\n"
"--fakedisplay, -D <display to fake>\n"
"--copyauthentication, -c	Copy credentials\n"
"--nocopyauthentication, -n	Do not copy credentials\n"
"--authfile, -f <file instead of ~/.Xauthority to get credentials from>\n"
"--newauthfile, -F <file instead of ~/.Xauthority to put credentials in>\n"
"--stopwhendone, -s		Return when last client disconnects\n"
"--keeprunning, -k		Keep running\n"
"--denyextensions, -e		Fake unavailability of all extensions\n"
"--readwritedebug, -w		Print amounts of data read/sent\n"
"--maxlistlength, -m <maximum number of entries in each list shown>\n",
argv[0]);
			 exit(EXIT_SUCCESS);

		 case ':':
		 case '?':
		 default:
			 exit(EXIT_FAILURE);
		}

	}
	if( optind < argc && strcmp(argv[optind],"--") != 0 ) {
		fprintf(stderr,"Unexpected argument: '%s'\n",argv[optind+1]);
		exit(EXIT_FAILURE);
	}

	signal(SIGPIPE,SIG_IGN);
	if( out_displayname == NULL ) {
		out_displayname = getenv("DISPLAY");
		if( out_displayname == NULL ) {
			fprintf(stderr,"No X server display to connect to specified\n");
			exit(EXIT_FAILURE);
		}
	}
	if( in_displayname == NULL ) {
		in_displayname = getenv("INDISPLAY");
		if( in_displayname == NULL ) {
			fprintf(stderr,"No display name to create specified, trying :9\n");
			in_displayname = ":9";
		}
	}
	msg = parseDisplay(in_displayname,&in_protocol,&in_hostname,&in_display,&in_screen,&in_family);
	if( msg != NULL ) {
		fprintf(stderr,"Parsing '%s' failed: %s\n",in_displayname,msg);
		return -1;
	}
	msg = parseDisplay(out_displayname,&out_protocol,&out_hostname,&out_display,&out_screen,&out_family);
	if( msg != NULL ) {
		fprintf(stderr,"Parsing '%s' failed: %s\n",out_displayname,msg);
		return -1;
	}
//	generateAuthorisation(out_displayname);
	if( copyauth ) {
		/* TODO: normalize them? or keep them so the user has more
		 * control? */
		if( !copy_authentication(in_displayname,out_displayname,in_authfile,out_authfile) )
			return -1;
	}
	listener = listenForClients(in_displayname,in_family,in_display);
	if( listener < 0 ) {
		exit(EXIT_FAILURE);
	}
	r = mainqueue(listener);
	close(listener);
	return r;
}
