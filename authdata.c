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

#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <X11/X.h>
#include <X11/Xlib.h>
#include <X11/extensions/security.h>

#include "xtrace.h"

char *authdata = NULL;
size_t authdata_len = 0;
char *authname = "MIT-MAGIC-COOKIE-1";
size_t authname_len = strlen("MIT-MAGIC-COOKIE-1");

/* The following code is heavily based on code from xauth's process.c
 * with the following notice and diclaimer:
 *
 * * Copyright 1989, 1998  The Open Group
 * *
 * * Permission to use, copy, modify, distribute, and sell this software and its
 * * documentation for any purpose is hereby granted without fee, provided that
 * * the above copyright notice appear in all copies and that both that
 * * copyright notice and this permission notice appear in supporting
 * * documentation.
 * *
 * * The above copyright notice and this permission notice shall be included
 * * in all copies or substantial portions of the Software.
 * *
 * * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * * IN NO EVENT SHALL THE OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * * OTHER DEALINGS IN THE SOFTWARE.
 * *
 * * Except as contained in this notice, the name of The Open Group shall
 * * not be used in advertising or otherwise to promote the sale, use or
 * * other dealings in this Software without prior written authorization
 * * from The Open Group.
 */

static int x_protocol_error;
static int
catch_x_protocol_error(Display *dpy, XErrorEvent *errevent)
{
    char buf[80];
    XGetErrorText(dpy, errevent->error_code, buf, sizeof (buf));
    fprintf(stderr, "%s\n", buf);
    x_protocol_error = errevent->error_code;
    return 1;
}

bool generateAuthorisation(const char *displayname) {
	Display *dpy;
	int major_version, minor_version;
	XSecurityAuthorization id_return;
	XSecurityAuthorizationAttributes attributes;
	Xauth *auth_in, *auth_return;
	int status;
	bool successfull = true;

	dpy = XOpenDisplay (displayname);
	if (!dpy) {
		fprintf (stderr, "unable to open display \"%s\".\n", displayname);
		return false;
	}

	status = XSecurityQueryExtension(dpy, &major_version, &minor_version);
	if (!status)
	{
		fprintf (stderr, "couldn't query Security extension on display \"%s\"\n",
				displayname);
		return false;
	}
	/* TODO: make them configurable */
	attributes.trust_level = XSecurityClientUntrusted;
	attributes.timeout = 1200;
	auth_in = XSecurityAllocXauth();
	if( auth_in == NULL ) {
		XCloseDisplay(dpy);
		return false;
	}
	auth_in->name = authname;
	auth_in->name_length = authname_len;
	auth_in->data = NULL;
	auth_in->data_length = 0;
	x_protocol_error = 0;
	XSetErrorHandler(catch_x_protocol_error);
	auth_return = XSecurityGenerateAuthorization(dpy, auth_in,
			XSecurityTimeout|XSecurityTrustLevel,
			&attributes, &id_return);
	if( auth_return != NULL ) {
		authdata_len = auth_return->data_length;
		authdata = malloc(authdata_len+1);
		if( authdata == NULL )
			successfull = false;
		else {
			memcpy(authdata,auth_return->data,authdata_len);
			authdata[authdata_len] = '\0';
		}
		XSecurityFreeXauth(auth_return);
	} else
		successfull = false;
	XSecurityFreeXauth(auth_in);
	XCloseDisplay(dpy);
	return successfull;
}
