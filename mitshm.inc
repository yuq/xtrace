/*  This file is part of "xtrace"
 *  Copyright (C) 2006 Bernhard R. Link
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
/* This file is based on /usr/include/X11/extensions/shmstr.h which states:
Copyright 1989, 1998  The Open Group

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that
copyright notice and this permission notice appear in supporting
documentation.

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
OPEN GROUP BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of The Open Group shall not be
used in advertising or otherwise to promote the sale, use or other dealings
in this Software without prior written authorization from The Open Group.
*/

#define EOP {0,NULL,0,NULL}

#define ft_ShmSeg	ft_CARD32, NULL
#define ft_Drawable	ft_CARD32, NULL
#define ft_Visualid	ft_CARD32, NULL
#define ft_GContext	ft_CARD32, NULL
#define ft_Pixmap	ft_CARD32, NULL
#define ft_format	ft_CARD8, c_bitmap_format

static const struct parameter parameterShmQueryVersion[] = {
	EOP
};
static const struct parameter returnShmQueryVersion[] = {
	{	 8,	"major-version",	ft_UINT16,	NULL},
	{	10,	"minor-version",	ft_UINT16,	NULL},
	{	12,	"uid",			ft_UINT16,	NULL},
	{	14,	"gid",			ft_UINT16,	NULL},
	{	16,	"pixmap-format",	ft_format},
	EOP
};

static const struct parameter parameterShmAttach[] = {
	{	 4,	"shmseg",		ft_ShmSeg},
	{	 8,	"shmid",		ft_CARD32,	NULL},
	{	12,	"readonly",		ft_BOOL},
	EOP
};
static const struct parameter parameterShmDetach[] = {
	{	 4,	"shmseg",		ft_ShmSeg},
	EOP
};
static const struct parameter parameterShmPutImage[] = {
	{	 4,	"drawable",		ft_Drawable},
	{	 8,	"gc",			ft_GContext},
	{	12,	"total-width",		ft_UINT16,	NULL},
	{	14,	"total-height",		ft_UINT16,	NULL},
	{	16,	"src-x",		ft_UINT16,	NULL},
	{	18,	"src-y",		ft_UINT16,	NULL},
	{	20,	"src-width",		ft_UINT16,	NULL},
	{	22,	"src-height",		ft_UINT16,	NULL},
	{	24,	"dst-x",		ft_INT16,	NULL},
	{	26,	"dst-y",		ft_INT16,	NULL},
	{	28,	"depth",		ft_UINT8,	NULL},
	{	29,	"format",		ft_format},
	{	30,	"send-event",		ft_BOOL},
	{	32,	"shmseg",		ft_ShmSeg},
	{	36,	"offset",		ft_CARD32,	NULL},
	EOP
};
static const struct parameter parameterShmGetImage[] = {
	{	 4,	"drawable",		ft_Drawable},
	{	 8,	"x",			ft_INT16,	NULL},
	{	10,	"y",			ft_INT16,	NULL},
	{	12,	"width",		ft_UINT16,	NULL},
	{	14,	"height",		ft_UINT16,	NULL},
	{	16,	"planeMask",		ft_UINT32,	NULL},
	{	20,	"format",		ft_format},
	{	24,	"shmseg",		ft_ShmSeg},
	{	28,	"offset",		ft_CARD32,	NULL},
	EOP
};
static const struct parameter returnShmGetImage[] = {
	{	 8,	"visual",		ft_VisualID,	NULL},
	{	12,	"size",			ft_UINT32,	NULL},
	EOP
};
static const struct parameter parameterShmCreatePixmap[] = {
	{	 4,	"pid",			ft_Pixmap},
	{	 8,	"drawable",		ft_Drawable},
	{	12,	"width",		ft_UINT16,	NULL},
	{	14,	"height",		ft_UINT16,	NULL},
	{	16,	"depth",		ft_UINT8,	NULL},
	{	20,	"shmseg",		ft_ShmSeg},
	{	24,	"offset",		ft_CARD32,	NULL},
	EOP
};

#define ra(a) { #a , parameter ## a , NULL,NULL,NULL}
#define rb(a) { #a , parameter ## a , return ## a ,NULL,NULL}
#define rc(a) { #a , NULL, NULL,NULL,NULL}
static const struct request extensionMITSHM[] = {
	rb(ShmQueryVersion),
	ra(ShmAttach),
	ra(ShmDetach),
	ra(ShmPutImage),
	rb(ShmGetImage),
	ra(ShmCreatePixmap),
};
#undef ra
#undef rb
#undef rc

static const struct parameter eparamShmCompletion[] = {
	{	 4,	"drawable",		ft_Drawable},
	{	12,	"shmseg",		ft_ShmSeg},
	{	16,	"offset",		ft_CARD32,	NULL},
	EOP
};

#define ev(name) { #name , eparam ## name }
static const struct event eventsMITSHM[] = {
	ev(ShmCompletion),
};
#undef ev

static const char *errorsMITSHM[] = { "BadShmSeg" };

#undef EOP
#undef ft_ShmSeg
#undef ft_Drawable
#undef ft_Visualid
#undef ft_GContext
#undef ft_Pixmap
