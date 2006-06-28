/*  This file is part of "xtrace"
 *  Copyright (C) 2006 Bernhard R. Link
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
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
/* This file is based on /usr/include/X11/extensions/randr{,proto}.h which state:
* Copyright © 2000 Compaq Computer Corporation
* Copyright © 2002 Hewlett-Packard Company
* and
* Copyright © 2000, Compaq Computer Corporation,
* Copyright © 2002, Hewlett Packard, Inc.
*
* Permission to use, copy, modify, distribute, and sell this software and its
* documentation for any purpose is hereby granted without fee, provided that
* the above copyright notice appear in all copies and that both that
* copyright notice and this permission notice appear in supporting
* documentation, and that the name of Compaq or HP not be used in advertising
* or publicity pertaining to distribution of the software without specific,
* written prior permission.  Compaq and HP makes no representations about the
* suitability of this software for any purpose.  It is provided "as is"
* without express or implied warranty.
*
* HP DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL COMPAQ
* BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
* WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
* OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN 
* CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*
* Author:  Jim Gettys, HP Labs, Hewlett-Packard, Inc.
*/

#define EOV {0, NULL, -1, NULL}
#define EOC {-1, NULL}

static const struct constant c_randr_notify[] = {
	{0,	"ScreenChangeNotify"},
	EOC
};
#define ft_RANDR_NOTIFY ft_ENUM8,c_randr_notify
static const struct constant c_randr_notify_mask[] = {
	{(1L << 0),	"ScreenChangeNotifyMask"},
	EOC
};
#define ft_RANDR_NOTIFY_MASK ft_BITMASK8,c_randr_notify_mask
static const struct constant c_randr_rr[] = {
	{1,	"Rotate_0"},
	{2,	"Rotate_90"},
	{4,	"Rotate_180"},
	{8,	"Rotate_270"},
	{16,	"Reflect_X"},
	{32,	"Reflect_Y"},
	EOC
};
#define ft_RANDR_RR ft_BITMASK16,c_randr_rr
static const struct constant c_subpixelorder[] = {
	{0,	"Unknown"},
	{1,	"HorizontalRGB"},
	{2,	"HorizontalBGR"},
	{3,	"VerticalRGB"},
	{4,	"VerticalBGR"},
	{5,	"None"},
	EOC
};
#define ft_SUBPIXELORDER	ft_CARD16,	c_subpixelorder
static const struct constant c_randr_status[] = {
	{0,	"Success"},
	{1,	"InvalidConfigTime"},
	{2,	"InvalidTime"},
	{3,	"Failed"},
	EOC
};
static const struct constant c_appropriate[] = {
	{0,	"appropriate"},
	EOC
};
#undef EOC
#define EOP {0,NULL,0,NULL}
#define LC(len) {len,NULL,0,NULL}

static const struct parameter parameterRandrQueryVersion[] = {
	{	4,	"major-version",	ft_UINT32,	NULL},
	{	8,	"minor-version",	ft_UINT32,	NULL},
	EOP
};
static const struct parameter returnRandrQueryVersion[] = {
	{ 	 8,	"major-version",	ft_UINT32,	NULL},
	{	12,	"minor-version",	ft_UINT32,	NULL},
	EOP
};
#define ft_Window	ft_CARD32, NULL
static const struct parameter parameterRandrGetScreenInfo[] = {
	{	4,	"window",		ft_Window},
	EOP
};

static const struct parameter listScreenSizes[] = {
	LC(8),
	{	 0,	"width[pixels]",	ft_UINT16,	NULL},
	{	 2,	"height[pixels]",	ft_UINT16,	NULL},
	{	 4,	"width[mm]",		ft_UINT16,	NULL},
	{	 6,	"height[mm]",		ft_UINT16,	NULL},
	EOP
};
#define ft_ScreenSizes	ft_LISTofStruct,(void*)listScreenSizes

static const struct parameter listRates[] = {
	LC(2),
	{	 0,	"count",		ft_COUNT16,	NULL},
	{	 2,	"r",		ft_LISTofUINT16, NULL},
	EOP
};
#define ft_Rates	ft_LISTofVarStruct,(void*)listRates

static const struct parameter returnRandrGetScreenInfo[] = {
	{	 1,	"rotations",		ft_RANDR_RR},
	{	 8,	"root",			ft_Window},
	{	12,	"timestamp",		ft_TIMESTAMP,	NULL},
	{	16,	"config-timestamp",	ft_TIMESTAMP,	NULL},
	{	20,	"nSizes",		ft_COUNT16,	NULL},
	{	22,	"sizeID",		ft_CARD16,	NULL},
	{	24,	"rotation",		ft_RANDR_RR},
	{	32,	"sizes",		ft_ScreenSizes},
	{	28,	"nrateEnts",		ft_COUNT16,	NULL},
	{	26,	"rate",			ft_UINT16,	NULL},
	{OFS_LATER,	"rates",		ft_Rates},
	EOP
};

static const struct parameter parameterRandrSetScreenConfig[] = {
	{	 4,	"drawable",		ft_CARD32,	NULL},
	{	 8,	"timestamp",		ft_TIMESTAMP,	c_curtime},
	{	12,	"config-timestamp",	ft_TIMESTAMP,	NULL},
	{	16,	"size-id",		ft_CARD16,	NULL},
	{	18,	"rotation",		ft_RANDR_RR,},
	{	20,	"rate",			ft_UINT16,	c_appropriate},
	EOP
};


static const struct parameter returnRandrSetScreenConfig[] = {
	{	 1,	"status",		ft_ENUM8,	c_randr_status},
	{	 8,	"timestamp",		ft_TIMESTAMP,	NULL},
	{	12,	"config-timestamp",	ft_TIMESTAMP,	NULL},
	{	16,	"root",			ft_Window},
	{	20,	"subpixelOrder",	ft_SUBPIXELORDER},
	EOP
};

static const struct parameter parameterRandrSelectInput[] = {
	{	 4,	"window",		ft_Window},
	{	 8,	"enable",		ft_RANDR_NOTIFY_MASK},
	EOP
};

#undef EOV
#define ra(a) { #a , parameter ## a , NULL,NULL,NULL}
#define rb(a) { #a , parameter ## a , return ## a ,NULL,NULL}
#define rc(a) { #a , NULL, NULL,NULL,NULL}
static const struct request extensionRANDR[] = {
	rb(RandrQueryVersion),
	rc(RandrOldGetScreenInfo),
	rb(RandrSetScreenConfig),
	rc(RandrOldScreenChangeSelectInput),
	ra(RandrSelectInput),
	rb(RandrGetScreenInfo)
};
#undef ra
#undef rb
#undef rc

static const struct parameter eparamRandrScreenChangeNotify[] = {
	{	 1,	"rotation",		ft_RANDR_RR},
	{	 4,	"timestamp",		ft_TIMESTAMP,	NULL},
	{	 8,	"configTimestamp",	ft_TIMESTAMP,	NULL},
	{	12,	"root",			ft_Window},
	{	16,	"window",		ft_Window},
	{	20,	"size-id",		ft_CARD16,	NULL},
	{	22,	"subpixelOrder",	ft_SUBPIXELORDER},
	{	24,	"width[pixels]",	ft_UINT16,	NULL},
	{	26,	"height[pixels]",	ft_UINT16,	NULL},
	{	28,	"width[mm]",		ft_UINT16,	NULL},
	{	30,	"height[mm]",		ft_UINT16,	NULL},
	EOP
};

#define ev(name) { #name , eparam ## name }
static const struct event eventsRANDR[] = {
	ev(RandrScreenChangeNotify),
};
#undef ev

static const char *errorsRANDR[] = { };

#undef EOP
