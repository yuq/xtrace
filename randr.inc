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
*
* modified for Xrandr1.2 using /usr/share/doc/x11proto-randr-dev/randrproto.txt.gz:
               The X Resize, Rotate and Reflect Extension
                              Version 1.2
                               2006-4-13

                              Jim Gettys
                           Jim.Gettys@hp.com
                     Cambridge Research Laboratory
                                HP Labs
                        Hewlett Packard Company

                             Keith Packard
                        keith.packard@intel.com
                     Open Source Technology Center
                           Intel Corporation

* from x11proto-randr-dev which states:
Copyright © 2000 Compaq Computer Corporation
Copyright © 2002 Hewlett-Packard Company
Copyright © 2006 Intel Corporation

Permission to use, copy, modify, distribute, and sell this software and its
documentation for any purpose is hereby granted without fee, provided that
the above copyright notice appear in all copies and that both that copyright
notice and this permission notice appear in supporting documentation, and
that the name of the copyright holders not be used in advertising or
publicity pertaining to distribution of the software without specific,
written prior permission.  The copyright holders make no representations
about the suitability of this software for any purpose.  It is provided "as
is" without express or implied warranty.

THE COPYRIGHT HOLDERS DISCLAIM ALL WARRANTIES WITH REGARD TO THIS SOFTWARE,
INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO
EVENT SHALL THE COPYRIGHT HOLDERS BE LIABLE FOR ANY SPECIAL, INDIRECT OR
CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE,
DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE
OF THIS SOFTWARE.
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
	{(1L << 2),	"OutputChangeNotifyMask"},
	{(1L << 3),	"OutputPropertyNotifyMask"},
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
#define ft_RRCONFIGSTATUS	ft_ENUM8,	c_randr_status
static const struct constant c_appropriate[] = {
	{0,	"appropriate"},
	EOC
};
static const struct constant c_randr_connection[] = {
	{0,	"Connected"},
	{1,     "Disconnected"},
	{2,     "UnknownConnection"},
	EOC
};
#define ft_CONNECTION	ft_CARD8,	c_randr_connection
static const struct constant c_randr_modeflags[] = {
	{0x00000001,	"HSyncPositive"},
	{0x00000002,	"HSyncNegative"},
	{0x00000004,	"VSyncPositive"},
	{0x00000008,	"VSyncNegative"},
	{0x00000010,	"Interlace"},
	{0x00000020,	"DoubleScan"},
	{0x00000040,	"CSync"},
	{0x00000080,	"CSyncPositive"},
	{0x00000100,	"CSyncNegative"},
	{0x00000200,	"HSkewPresent"},
	{0x00000400,	"BCast"},
	{0x00000800,	"PixelMultiplex"},
	{0x00001000,	"DoubleClock"},
	{0x00002000,	"ClockDivideBy2"},
	EOC
};
#define ft_SETofMODEFLAG  ft_BITMASK32, c_randr_modeflags

static const struct constant c_randr_changemode[] = {
	{0,	"Replace"},
	{1,	"Prepend"},
	{2,	"Append"},
	EOC
};

static const struct constant c_randr_changenotifystate[] = {
	{0,	"NewValue"},
	{1,	"Deleted"},
	EOC
};

#undef EOC
#define EOP {0,NULL,0,NULL}
#define LC(len) {len,NULL,0,NULL}

#define ft_OUTPUT	ft_CARD32, NULL
#define ft_LISTofOUTPUT	ft_LISTofCARD32, NULL
#define ft_CRTC		ft_CARD32, NULL
#define ft_LISTofCRTC	ft_LISTofCARD32, NULL
#define ft_MODE		ft_CARD32, NULL
#define ft_LISTofMODE	ft_LISTofCARD32, NULL

#define ft_LISTofMODEINFO ft_LISTofStruct, (void*)randrModeInfo
#define ft_MODEINFO	  ft_Struct, (void*)randrModeInfo
static const struct parameter randrModeInfo[] = {
	LC(32),
	{	 0,	"id",			ft_CARD32,	NULL},
	{	 4,	"width[pixels]",	ft_UINT16,	NULL},
	{	 6,	"height[pixels]",	ft_UINT16,	NULL},
	{	 8,	"dot_clock",		ft_UINT32,	NULL},
	{	 12,	"h_sync_start",		ft_UINT16,	NULL},
	{	 14,	"h_sync_end",		ft_UINT16,	NULL},
	{	 16,	"h_total",		ft_UINT16,	NULL},
	{	 18,	"h_skew",		ft_UINT16,	NULL},
	{	 20,	"v_sync_start",		ft_UINT16,	NULL},
	{	 22,	"v_sync_end",		ft_UINT16,	NULL},
	{	 24,	"v_total",		ft_UINT16,	NULL},
	{	 26,	"name_length",		ft_UINT16,	NULL},
	{	 28,	"mode_flags",		ft_SETofMODEFLAG},
	EOP
};

#define ft_TRANSFORM	ft_Struct,	(void*)randr_transform
static const struct parameter randr_transform[] = {
	LC(36),
	{	0,	"matrix",		ft_LISTofFIXED,	NULL},
	EOP
};

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
	{	 4,	"window",		ft_CARD32,	NULL},
	{	 8,	"timestamp",		ft_TIMESTAMP,	c_curtime},
	{	12,	"config-timestamp",	ft_TIMESTAMP,	NULL},
	{	16,	"sizei index",		ft_CARD16,	NULL},
	{	18,	"rotation",		ft_RANDR_RR,},
	{	20,	"rate",			ft_UINT16,	c_appropriate},
	EOP
};


static const struct parameter returnRandrSetScreenConfig[] = {
	{	 1,	"status",		ft_RRCONFIGSTATUS},
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

static const struct parameter parameterRandrGetScreenSizeRange[] = {
	{	 4,	"window",	ft_WINDOW,	NULL},
	EOP
};
static const struct parameter returnRandrGetScreenSizeRange[] = {
	{	  8,	"minWidth",	ft_UINT16,	NULL},
	{	 10,	"minHeight",	ft_UINT16,	NULL},
	{	 12,	"maxWidth",	ft_UINT16,	NULL},
	{	 14,	"maxHeight",	ft_UINT16,	NULL},
	EOP
};
static const struct parameter parameterRandrSetScreenSize[] = {
	{	  4,	"window",	ft_WINDOW,	NULL},
	{	  8,	"width",	ft_UINT16,	NULL},
	{	 10,	"height",	ft_UINT16,	NULL},
	{	 12,	"width[mm]",	ft_UINT32,	NULL},
	{	 16,	"height[mm]",	ft_UINT32,	NULL},
	EOP
};

#define parameterRandrGetScreenResourcesCurrent parameterRandrGetScreenResources
#define returnRandrGetScreenResourcesCurrent returnRandrGetScreenResources
static const struct parameter parameterRandrGetScreenResources[] = {
	{	 4,	"window",	ft_WINDOW,	NULL},
	EOP
};
static const struct parameter returnRandrGetScreenResources[] = {
	{	  8,	"timestamp",	ft_TIMESTAMP,	NULL},
	{	 12,	"config-timestamp",	ft_TIMESTAMP,	NULL},
	{	 16,	"#CRTCs",	ft_COUNT16,	NULL},
	{	 32,	"crtcs",	ft_LISTofCRTC},
	{	 18,	"#outputs",	ft_COUNT16,	NULL},
	{ OFS_LATER,	"outputs",	ft_LISTofOUTPUT},
	{	 20,	"#modeinfos",	ft_COUNT16,	NULL},
	{ OFS_LATER,	"modeinfos",	ft_LISTofMODEINFO},
	{	 22,	"total bytes in mode names",	ft_COUNT16,	NULL},
	/* a way to seperate them would be nice: */
	{ OFS_LATER,	"mode names",	ft_STRING8,	NULL},
	EOP
};
static const struct parameter parameterRandrGetOutputInfo[] = {
	{	 4,	"output",		ft_OUTPUT},
	{	 8,	"config-timestamp",	ft_TIMESTAMP,	NULL},
	EOP
};
static const struct parameter returnRandrGetOutputInfo[] = {
	{	 8,	"timestamp",	ft_TIMESTAMP,	NULL},
	{	12,	"current connected crtc",	ft_CRTC},
	{	16,	"width[mm]",	ft_UINT32,	NULL},
	{	20,	"height[mm]",	ft_UINT32,	NULL},
	{	24,	"connection",	ft_CONNECTION},
	{	25,	"subpixel-order",	ft_SUBPIXELORDER},
	{	26,	"#CRTCs",	ft_COUNT16,	NULL},
	{	36,	"crtcs",	ft_LISTofCRTC},
	{	28,	"#modes",	ft_COUNT16,	NULL},
	{OFS_LATER,	"modes",	ft_LISTofMODE},
	{	30,	"preferred modes",ft_UINT16,	NULL},
	{	32,	"clonecount",	ft_COUNT16,	NULL},
	{OFS_LATER,	"clones",	ft_LISTofOUTPUT},
	{	34,	"length of name",	ft_COUNT16,	NULL},
	{OFS_LATER,	"name",		ft_STRING8,	NULL},
	EOP
};
static const struct parameter parameterRandrListOutputProperties[] = {
	{	 4,	"output",	ft_OUTPUT},
	EOP
};
static const struct parameter returnRandrListOutputProperties[] = {
	{	 8,	"#atoms",	ft_COUNT16,	NULL},
	{	32,	"atoms",	ft_LISTofATOM,	NULL},
	EOP
};
static const struct parameter parameterRandrQueryOutputProperty[] = {
	{	 4,	"output",	ft_OUTPUT},
	{	 8,	"property",	ft_ATOM,	NULL},
	EOP
};
static const struct parameter returnRandrQueryOutputProperty[] = {
	{	 8,	"pending",	ft_BOOL},
	{	 9,	"range",	ft_BOOL},
	{	10,	"immutable",	ft_BOOL},
	{	32,	"valid values",	ft_LISTofUINT32,	NULL},
	EOP
};
static const struct parameter parameterRandrConfigureOutputProperty[] = {
	{	 4,	"output",	ft_OUTPUT},
	{	 8,	"property",	ft_ATOM,	 NULL},
	{	12,	"pending",	ft_BOOL},
	{	13,	"range",	ft_BOOL},
	{	16,	"valid values",	ft_LISTofUINT32, NULL},
	EOP
};
static const struct parameter parameterRandrChangeOutputProperty[] = {
	{	 4,	"output",	ft_OUTPUT},
	{	 8,	"property",	ft_ATOM,	NULL},
	{	12,	"type",		ft_ATOM,	NULL},
	{	16,	"format",	ft_FORMAT8,	NULL},
	{	17,	"mode",		ft_ENUM8,	c_randr_changemode},
	{	20,	"length",	ft_COUNT32,	NULL},
	{	24,	"data",		ft_LISTofFormat,	NULL},
	EOP
};
static const struct parameter parameterRandrDeleteOutputProperty[] = {
	{	 4,	"output",	ft_OUTPUT},
	{	 8,	"property",	ft_ATOM,	NULL},
	EOP
};
static const struct parameter parameterRandrGetOutputProperty[] = {
	{	 4,	"output",	ft_OUTPUT},
	{	 8,	"property",	ft_ATOM,	NULL},
	{	12,	"type",		ft_ATOM,	c_any},
	{	16,	"offset",	ft_CARD32,	NULL},
	{	20,	"length",	ft_CARD32,	NULL},
	{	24,	"delete",	ft_BOOL},
	{	25,	"pending",	ft_BOOL},
	EOP
};
static const struct parameter returnRandrGetOutputProperty[] = {
	{	 1,	"format",	ft_FORMAT8,	NULL},
	{	 8,	"type",		ft_ATOM,	c_none},
	{	12,	"bytes-after",	ft_CARD32,	NULL},
	{	16,	"length",	ft_COUNT32,	NULL},
	{	32,	"value",	ft_LISTofFormat, NULL},
	EOP
};
static const struct parameter parameterRandrCreateMode[] = {
	{	 4,	"window",	ft_WINDOW,	NULL},
	{	 8,	"mode",		ft_MODEINFO},
	{	40,	"mode name",	ft_STRING8,	NULL},
	EOP
};
static const struct parameter returnRandrCreateMode[] = {
	{	 8,	"mode",		ft_MODE},
	EOP
};
static const struct parameter parameterRandrDestroyMode[] = {
	{	 4,	"mode",		ft_MODE},
	EOP
};
static const struct parameter parameterRandrAddOutputMode[] = {
	{	 4,	"output",	ft_OUTPUT},
	{	 8,	"mode",		ft_MODE},
	EOP
};
#define parameterRandrDeleteOutputMode parameterRandrAddOutputMode
static const struct parameter parameterRandrGetCrtcInfo[] = {
	{	 4,	"crtc",			ft_CRTC},
	{	 8,	"config-timestamp",	ft_TIMESTAMP, NULL},
	EOP
};
static const struct parameter returnRandrGetCrtcInfo[] = {
	{	 1,	"status",	ft_RRCONFIGSTATUS},
	{	 8,	"timestamp",	ft_TIMESTAMP, NULL},
	{	12,	"x",		ft_INT16,	NULL},
	{	14,	"y",		ft_INT16,	NULL},
	{	16,	"width",	ft_UINT16,	NULL},
	{	18,	"height",	ft_UINT16,	NULL},
	{	20,	"mode",		ft_MODE},
	{	24,	"current rr",	ft_RANDR_RR},
	{	26,	"possible rr",	ft_RANDR_RR},
	{	28,	"#outputs",	ft_COUNT16,	NULL},
	{	32,	"outputs",	ft_LISTofOUTPUT},
	{	30,	"#possible outputs",ft_COUNT16,	NULL},
	{OFS_LATER,	"possible outputs", ft_LISTofOUTPUT},
	EOP
};
static const struct parameter parameterRandrSetCrtcConfig[] = {
	{	 4,	"crtc",			ft_CRTC},
	{	 8,	"timestamp",		ft_TIMESTAMP,	NULL},
	{	12,	"config timestamp",	ft_TIMESTAMP,	NULL},
	{	16,	"x",			ft_INT16,	NULL},
	{	18,	"y",			ft_INT16,	NULL},
	{	20,	"mode",			ft_MODE},
	{	24,	"rr",			ft_RANDR_RR},
	{	28,	"outputs",		ft_LISTofOUTPUT},
	EOP
};
static const struct parameter returnRandrSetCrtcConfig[] = {
	{	 1,	"status",	ft_RRCONFIGSTATUS},
	EOP
};
static const struct parameter parameterRandrGetCrtcGammaSize[] = {
	{	 4,	"crtc",		ft_CRTC},
	EOP
};
static const struct parameter returnRandrGetCrtcGammaSize[] = {
	{	 8,	"size",		ft_CARD16,	NULL},
	EOP
};
#define parameterRandrGetCrtcGamma parameterRandrGetCrtcGammaSize
static const struct parameter returnRandrGetCrtcGamma[] = {
	{	 8,	"size",	ft_COUNT16,	NULL},
	/* is this really 22?? */
	{	22,	"red",	ft_LISTofCARD16,	NULL},
	{	 8,	"size",	ft_COUNT16,	NULL},
	{OFS_LATER,	"green",ft_LISTofCARD16,	NULL},
	{	 8,	"size",	ft_COUNT16,	NULL},
	{OFS_LATER,	"blue",	ft_LISTofCARD16,	NULL},
	EOP
};
static const struct parameter parameterRandrSetCrtcGamma[] = {
	{	 4,	"crtc",	ft_CRTC},
	{	 8,	"size",	ft_COUNT16,	NULL},
	{	12,	"red",	ft_LISTofCARD16,	NULL},
	{	 8,	"size",	ft_COUNT16,	NULL},
	{OFS_LATER,	"green",ft_LISTofCARD16,	NULL},
	{	 8,	"size",	ft_COUNT16,	NULL},
	{OFS_LATER,	"blue",	ft_LISTofCARD16,	NULL},
	EOP
};
static const struct parameter parameterRandrSetCrtcTransform[] = {
	{	 4,	"crtc",			ft_CRTC},
	{	 8,	"transform",		ft_TRANSFORM},
	{	44,	"filter length",	ft_COUNT16,	NULL},
	{	48,	"filter name",		ft_STRING8,	NULL},
	ROUND,
	{OFS_LATER,	"filter params",	ft_LISTofFIXED,	NULL},
	EOP
};
static const struct parameter parameterRandrGetCrtcTransform[] = {
	{	 4,	"crtc",		ft_CRTC},
	EOP
};
static const struct parameter returnRandrGetCrtcTransform[] = {
	{	 8,	"pending transform",		ft_TRANSFORM},
	{	44,	"has transforms",		ft_BOOL},
	{	48,	"current transform",		ft_TRANSFORM},
	{	88,	"pending filter name length",	ft_COUNT16,	NULL},
	{	96,	"pending filter name",		ft_STRING8,	NULL},
	ROUND,
	{	90,	"pending filter num params",	ft_COUNT16,	NULL},
	{OFS_LATER,	"pending filter params",	ft_LISTofFIXED,	NULL},
	{	92,	"current filter name length",	ft_COUNT16,	NULL},
	{OFS_LATER,	"current filter name",		ft_STRING8,	NULL},
	ROUND,
	{	94,	"current filter num params",	ft_COUNT16,	NULL},
	{OFS_LATER,	"current filter params",	ft_LISTofFIXED,	NULL},
	EOP
};
static const struct parameter parameterRandrGetPanning[] = {
	{	4,	"crtc",		ft_CRTC},
	EOP
};
static const struct parameter returnRandrGetPanning[] = {
	{	 1,	"status",	ft_RRCONFIGSTATUS},
	{	 8,	"timestamp",	ft_TIMESTAMP,	NULL},
	{	12,	"left",		ft_UINT16,	NULL},
	{	14,	"top",		ft_UINT16,	NULL},
	{	16,	"width",	ft_UINT16,	NULL},
	{	18,	"height",	ft_UINT16,	NULL},
	{	20,	"track_left",	ft_UINT16,	NULL},
	{	22,	"track_top",	ft_UINT16,	NULL},
	{	24,	"track_width",	ft_UINT16,	NULL},
	{	26,	"track_height",	ft_UINT16,	NULL},
	{	28,	"border_left",	ft_INT16,	NULL},
	{	30,	"border_top",	ft_INT16,	NULL},
	{	32,	"border_right",	ft_INT16,	NULL},
	{	34,	"border_bottom",ft_INT16,	NULL},
	EOP
};
static const struct parameter parameterRandrSetPanning[] = {
	{	 4,	"crtc",		ft_CRTC},
	{	 8,	"timestamp",	ft_TIMESTAMP,	NULL},
	{	12,	"left",		ft_UINT16,	NULL},
	{	14,	"top",		ft_UINT16,	NULL},
	{	16,	"width",	ft_UINT16,	NULL},
	{	18,	"height",	ft_UINT16,	NULL},
	{	20,	"track_left",	ft_UINT16,	NULL},
	{	22,	"track_top",	ft_UINT16,	NULL},
	{	24,	"track_width",	ft_UINT16,	NULL},
	{	26,	"track_height",	ft_UINT16,	NULL},
	{	28,	"border_left",	ft_INT16,	NULL},
	{	30,	"border_top",	ft_INT16,	NULL},
	{	32,	"border_right",	ft_INT16,	NULL},
	{	34,	"border_bottom",ft_INT16,	NULL},
	EOP
};
static const struct parameter returnRandrSetPanning[] = {
	{	 1,	"status",	ft_RRCONFIGSTATUS},
	{	 8,	"timestamp",	ft_TIMESTAMP,	NULL},
	EOP
};
static const struct parameter parameterRandrSetOutputPrimary[] = {
	{	 4,	"window",	ft_WINDOW,	NULL},
	{	 8,	"output",	ft_OUTPUT},
	EOP
};
static const struct parameter parameterRandrGetOutputPrimary[] = {
	{	 4,	"window",	ft_WINDOW,	NULL},
	EOP
};
static const struct parameter returnRandrGetOutputPrimary[] = {
	{	 8,	"output",	ft_OUTPUT},
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
	rb(RandrGetScreenInfo),
	/* RandR 1.2 */
	rb(RandrGetScreenSizeRange),
	ra(RandrSetScreenSize),
	rb(RandrGetScreenResources),
	rb(RandrGetOutputInfo),
	rb(RandrListOutputProperties),
	rb(RandrQueryOutputProperty),
	ra(RandrConfigureOutputProperty),
	ra(RandrChangeOutputProperty),
	ra(RandrDeleteOutputProperty),
	rb(RandrGetOutputProperty),
	rb(RandrCreateMode),
	ra(RandrDestroyMode),
	ra(RandrAddOutputMode),
	ra(RandrDeleteOutputMode),
	rb(RandrGetCrtcInfo),
	rb(RandrSetCrtcConfig),
	rb(RandrGetCrtcGammaSize),
	rb(RandrGetCrtcGamma),
	ra(RandrSetCrtcGamma),
	
	/* RandR 1.3 */
	rb(RandrGetScreenResourcesCurrent),
	ra(RandrSetCrtcTransform),
	rb(RandrGetCrtcTransform),
	rb(RandrGetPanning),
	rb(RandrSetPanning),
	ra(RandrSetOutputPrimary),
	rb(RandrGetOutputPrimary)
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

static const struct parameter eparamRandrChangeNotify0[] = {
	{	 4,	"timestamp",		ft_TIMESTAMP,	NULL},
	{	 8,	"request window",	ft_WINDOW,	NULL},
	{	12,	"crtc affected",	ft_CRTC},
	{	16,	"mode in use",		ft_MODE},
	{	20,	"new rr",		ft_RANDR_RR},
	{	24,	"x",			ft_INT16,	NULL},
	{	26,	"y",			ft_INT16,	NULL},
	{	28,	"width",		ft_UINT16,	NULL},
	{	30,	"height",		ft_UINT16,	NULL},
	EOP
};

static const struct parameter eparamRandrChangeNotify1[] = {
	{	 4,	"timestamp",		ft_TIMESTAMP,	NULL},
	{	 8,	"config timestamp",	ft_TIMESTAMP,	NULL},
	{	12,	"request window",	ft_WINDOW,	NULL},
	{	16,	"output affected",	ft_OUTPUT},
	{	20,	"crtc in use",		ft_CRTC},
	{	24,	"mode in use",		ft_MODE},
	{	28,	"rr",			ft_RANDR_RR},
	{	30,	"connection status",	ft_CONNECTION},
	{	31,	"subpixel order",	ft_SUBPIXELORDER},
	EOP
};

static const struct parameter eparamRandrChangeNotify2[] = {
	{	 4,	"window",	ft_WINDOW,	NULL},
	{	 8,	"output",	ft_OUTPUT},
	{	12,	"atom",		ft_ATOM,	NULL},
	{	16,	"time",		ft_TIMESTAMP,	NULL},
	{	20,	"state",	ft_ENUM8, c_randr_changenotifystate},
	EOP
};

static const struct parameter eparamRandrChangeNotify1dot2[] = {
	{	 1,	"\0",	ft_IF8,	(void*)eparamRandrChangeNotify0 },
	{	 1,	"\1",	ft_IF8,	(void*)eparamRandrChangeNotify1 },
	{	 1,	"\2",	ft_IF8,	(void*)eparamRandrChangeNotify2 },
	EOP
};

#define ev(name) { #name , eparam ## name }
static const struct event eventsRANDR[] = {
	ev(RandrScreenChangeNotify),
	ev(RandrChangeNotify1dot2),
};
#undef ev

static const char *errorsRANDR[] = { "BadOutput", "BadCrtc", "BadMode" };

#undef EOP
