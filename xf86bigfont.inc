/*  This file is part of "xtrace"
 *  Copyright (C) 2007 Bernhard R. Link
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
/* This file is based on /usr/include/X11/extensions/xf86bigf{ont,str}.h, which is:
Copyright (c) 1999-2000  Bruno Haible
Copyright (c) 1999-2000  The XFree86 Project, Inc.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
XFREE86 PROJECT BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of the XFree86 Project shall not
be used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization from the XFree86 Project.
*/

#define EOC {-1, NULL}
static const struct constant c_xf86bigfont_capabilities[] = {
	{1,	"LocalShm"},
	EOC
};
#define ft_xf86bigfont_capabilities ft_BITMASK32, c_xf86bigfont_capabilities
static const struct constant c_xf86bigfont_flags[] = {
	{1,	"Shm"},
	EOC
};
#define ft_xf86bigfont_flags ft_BITMASK32, c_xf86bigfont_flags
#undef EOC
#define EOP {0,NULL,0,NULL}
#define LC(len) {len,NULL,0,NULL}

static const struct parameter parameterXF86BigfontQueryVersion[] = {
	EOP
};
static const struct parameter returnXF86BigfontQueryVersion[] = {
	{ 	 8,	"major-version",	ft_UINT16,	NULL},
	{	10,	"minor-version",	ft_UINT16,	NULL},
	{	 1,	"capabilities",		ft_xf86bigfont_capabilities},
	{	12,	"uid",			ft_UINT32,	NULL},
	{	16,	"gid",			ft_UINT32,	NULL},
	{	20,	"signature",		ft_UINT32,	NULL},
	EOP
};

static const struct parameter parameterXF86BigfontQueryFont[] = {
	{	 4,	"id",			ft_UINT32,	NULL},
	{	 8,	"flags",		ft_xf86bigfont_flags},
	EOP
};

static const struct parameter returnXF86BigfontQueryFont[] = {
	{	 8,	"min-bounds",		ft_CHARINFO},
	{	24,	"max-bounds",		ft_CHARINFO},
	{	40,	"min-char-or-byte2",	ft_CARD16,	NULL},
	{	42,	"max-char-or-byte2",	ft_CARD16,	NULL},
	{	44,	"default-char",		ft_CARD16,	NULL},
	{	48,	"draw-direction",	ft_ENUM8,       c_direction},
	{	49,	"min-byte1",		ft_CARD8,	NULL},
	{	50,	"max-byte1",		ft_CARD8,	NULL},
	{	51,	"all-chars-exists",	ft_BOOL},
	{	52,	"font-ascent",		ft_INT16,	NULL},
	{	54,	"font-descent",		ft_INT16,	NULL},
	{	64,	"shmid",		ft_COUNT32,	NULL},
	{	68,	"shmsegoffset",		ft_COUNT32,	NULL},

	{	46,	"nFontProps",		ft_COUNT16,	NULL},
	{	72,	"properties",		ft_LISTofFONTPROP},
	{	60,	"nUniqCharInfos",	ft_COUNT32,	NULL},
	{OFS_LATER,	"uniq-char-infos",	ft_LISTofCHARINFO},
	{	56,	"nCharInfos",		ft_COUNT32,	NULL},
	{OFS_LATER,	"char-info-offsets",	ft_LISTofCARD16, NULL},
	EOP
};

#undef EOV
#undef EOP
#define ra(a) { #a , parameter ## a , NULL,NULL,NULL}
#define rb(a) { #a , parameter ## a , return ## a ,NULL,NULL}
#define rc(a) { #a , NULL, NULL,NULL,NULL}
static const struct request extensionXF86Bigfont[] = {
	rb(XF86BigfontQueryVersion),
	rb(XF86BigfontQueryFont),
};
#undef ra
#undef rb
#undef rc

static const struct event eventsXF86Bigfont[] = {};
static const char *errorsXF86Bigfont[] = {};

