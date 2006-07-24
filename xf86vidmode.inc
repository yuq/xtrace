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
/* This file is based on /usr/include/X11/extensions/xf86vmstr.h which states:
Copyright 1995  Kaleb S. KEITHLEY

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL Kaleb S. KEITHLEY BE LIABLE FOR ANY CLAIM, DAMAGES 
OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of Kaleb S. KEITHLEY 
shall not be used in advertising or otherwise to promote the sale, use 
or other dealings in this Software without prior written authorization
from Kaleb S. KEITHLEY

*/

#define EOC {-1, NULL}
static const struct constant c_xf86vidmode_perms[] = {
	{1,	"read"},
	{2,	"write"},
	EOC
};
static const struct constant c_xf86vidmode_flags[] = {
	/* taken from xvidtune: */
	{1,	"+hsync"},
	{2,	"-hsync"},
	{4,	"+vsync"},
	{8,	"-vsync"},
	{16,	"interlace"},
	{32,	"doublescan"},
	{64,	"csync"},
	{128,	"+csync"},
	{256,	"-csync"},
	EOC
};
#undef EOC
#define EOP {0,NULL,0,NULL}
#define LC(len) {len,NULL,0,NULL}

static const struct parameter parameterXF86VidModeQueryVersion[] = {
	EOP
};
static const struct parameter returnXF86VidModeQueryVersion[] = {
	{ 	 8,	"major-version",	ft_UINT16,	NULL},
	{	10,	"minor-version",	ft_UINT16,	NULL},
	EOP
};

static const struct parameter parameterXF86VidModeGetModeLine[] = {
	{	 4,	"screen",		ft_UINT16,	NULL},
	EOP
};
#define parameterXF86VidModeGetAllModeLines parameterXF86VidModeGetModeLine
#define parameterXF86VidModeGetMonitor parameterXF86VidModeGetModeLine
#define parameterXF86VidModeGetViewPort parameterXF86VidModeGetModeLine
#define parameterXF86VidModeGetDotClocks parameterXF86VidModeGetModeLine
#define parameterXF86VidModeGetPermissions parameterXF86VidModeGetModeLine
#define parameterXF86VidModeGetGamma parameterXF86VidModeGetModeLine

static const struct parameter returnXF86VidModeGetModeLine[] = {
	{	 8,	"dotclock",	ft_UINT32,	NULL},
	{	12,	"hdisplay",	ft_UINT16,	NULL},
	{	14,	"hsyncstart",	ft_UINT16,	NULL},
	{	16,	"hsyncend",	ft_UINT16,	NULL},
	{	18,	"htotal",	ft_UINT16,	NULL},
	{	20,	"hskew",	ft_UINT16,	NULL},
	{	22,	"vdisplay",	ft_UINT16,	NULL},
	{	24,	"vsyncstart",	ft_UINT16,	NULL},
	{	26,	"vsyncend",	ft_UINT16,	NULL},
	{	28,	"vtotal",	ft_UINT16,	NULL},
	{	32,	"flags",	ft_BITMASK32,	c_xf86vidmode_flags},
	{	36,	"reserved1",	ft_UINT32,	NULL},
	{	40,	"reserved2",	ft_UINT32,	NULL},
	{	44,	"reserved3",	ft_UINT32,	NULL},
	{	48,	"privsize",	ft_UINT32,	NULL},
	EOP
};

static const struct parameter structXF86Modes[] = {
	LC(48),
	/* This is somehow buggy, xf86vmstr.h values cannot
	   be, this looks a bit better, but I'm still not sure */
	{	 0,	"dotclock",	ft_UINT32,	NULL},
	{	 4,	"hdisplay",	ft_UINT16,	NULL},
	{	 6,	"hsyncstart",	ft_UINT16,	NULL},
	{	 8,	"hsyncend",	ft_UINT16,	NULL},
	{	10,	"htotal",	ft_UINT16,	NULL},
	{	12,	"hskew",	ft_UINT32,	NULL},
	{	16,	"vdisplay",	ft_UINT16,	NULL},
	{	18,	"vsyncstart",	ft_UINT16,	NULL},
	{	20,	"vsyncend",	ft_UINT16,	NULL},
	{	22,	"vtotal",	ft_UINT16,	NULL},
	{	28,	"flags",	ft_BITMASK32,	c_xf86vidmode_flags},
	{	32,	"reserved1",	ft_UINT32,	NULL},
	{	36,	"reserved2",	ft_UINT32,	NULL},
	{	40,	"reserved3",	ft_UINT32,	NULL},
	{	44,	"privsize",	ft_UINT32,	NULL},
	EOP,
};
#define ft_LISTofModes ft_LISTofStruct, (void*)structXF86Modes
static const struct parameter returnXF86VidModeGetAllModeLines[] = {
	{	 8,	"modecount",	ft_UINT32,	NULL},
	{	 8,	"modecount",	ft_COUNT32,	NULL},
	{	32,	"modes",	ft_LISTofModes},
	EOP
};

static const struct parameter structSync[] = {
	LC(4),
	{ 	 0,	"min",		ft_UINT16,	NULL},
	{ 	 2,	"max",		ft_UINT16,	NULL},
	EOP
};
#define ft_LISTofSync ft_LISTofStruct,	(void*)structSync


static const struct parameter returnXF86VidModeGetMonitor[] = {
	{	 8,	"vendorLength",	ft_COUNT8,	NULL},
	{	32,	"vendor",	ft_STRING8,	NULL},
	{	 9,	"modelLength",	ft_COUNT8,	NULL},
	{ OFS_LATER,	"model",	ft_STRING8,	NULL},
	{	10,	"nhsync",	ft_COUNT8,	NULL},
	{ OFS_LATER,	"hsync",	ft_LISTofSync},
	{	11,	"nvsync",	ft_COUNT8,	NULL},
	{ OFS_LATER,	"vsync",	ft_LISTofSync},
	EOP
};

static const struct parameter parameterXF86VidModeAddModeLine[] = {
	{	 4,	"screen",	ft_CARD32,	NULL},
	{	 8,	"dotclock",	ft_UINT32,	NULL},
	{	12,	"hdisplay",	ft_UINT16,	NULL},
	{	14,	"hsyncstart",	ft_UINT16,	NULL},
	{	16,	"hsyncend",	ft_UINT16,	NULL},
	{	18,	"htotal",	ft_UINT16,	NULL},
	{	20,	"hskew",	ft_UINT16,	NULL},
	{	22,	"vdisplay",	ft_UINT16,	NULL},
	{	24,	"vsyncstart",	ft_UINT16,	NULL},
	{	26,	"vsyncend",	ft_UINT16,	NULL},
	{	28,	"vtotal",	ft_UINT16,	NULL},
	{	32,	"flags",	ft_BITMASK32,	c_xf86vidmode_flags},
	{	36,	"reserved1",	ft_UINT32,	NULL},
	{	40,	"reserved2",	ft_UINT32,	NULL},
	{	44,	"reserved3",	ft_UINT32,	NULL},
	{	48,	"privsize",	ft_UINT32,	NULL},
	{	52,	"after_dotclock",	ft_UINT32,	NULL},
	{	56,	"after_hdisplay",	ft_UINT16,	NULL},
	{	58,	"after_hsyncstart",	ft_UINT16,	NULL},
	{	60,	"after_hsyncend",	ft_UINT16,	NULL},
	{	62,	"after_htotal",		ft_UINT16,	NULL},
	{	64,	"after_hskew",		ft_UINT16,	NULL},
	{	66,	"after_vdisplay",	ft_UINT16,	NULL},
	{	68,	"after_vsyncstart",	ft_UINT16,	NULL},
	{	70,	"after_vsyncend",	ft_UINT16,	NULL},
	{	72,	"after_vtotal",	ft_UINT16,	NULL},
	{	76,	"after_flags",	ft_CARD32,	NULL},
	{	80,	"reserved4",	ft_UINT32,	NULL},
	{	84,	"reserved5",	ft_UINT32,	NULL},
	{	88,	"reserved6",	ft_UINT32,	NULL},
	EOP
};

static const struct parameter parameterXF86VidModeModModeLine[] = {
	{	 4,	"screen",	ft_CARD32,	NULL},
	{	 8,	"hdisplay",	ft_UINT16,	NULL},
	{	10,	"hsyncstart",	ft_UINT16,	NULL},
	{	12,	"hsyncend",	ft_UINT16,	NULL},
	{	14,	"htotal",	ft_UINT16,	NULL},
	{	16,	"hskew",	ft_UINT16,	NULL},
	{	18,	"vdisplay",	ft_UINT16,	NULL},
	{	20,	"vsyncstart",	ft_UINT16,	NULL},
	{	22,	"vsyncend",	ft_UINT16,	NULL},
	{	24,	"vtotal",	ft_UINT16,	NULL},
	{	28,	"flags",	ft_BITMASK32,	c_xf86vidmode_flags},
	{	32,	"reserved1",	ft_UINT32,	NULL},
	{	36,	"reserved2",	ft_UINT32,	NULL},
	{	40,	"reserved3",	ft_UINT32,	NULL},
	{	44,	"privsize",	ft_UINT32,	NULL},
	EOP
};

static const struct parameter parameterXF86VidModeValidateModeLine[] = {
	{	 4,	"screen",	ft_CARD32,	NULL},
	{	 8,	"dotclock",	ft_UINT32,	NULL},
	{	12,	"hdisplay",	ft_UINT16,	NULL},
	{	14,	"hsyncstart",	ft_UINT16,	NULL},
	{	16,	"hsyncend",	ft_UINT16,	NULL},
	{	18,	"htotal",	ft_UINT16,	NULL},
	{	20,	"hskew",	ft_UINT16,	NULL},
	{	22,	"vdisplay",	ft_UINT16,	NULL},
	{	24,	"vsyncstart",	ft_UINT16,	NULL},
	{	26,	"vsyncend",	ft_UINT16,	NULL},
	{	28,	"vtotal",	ft_UINT16,	NULL},
	{	32,	"flags",	ft_BITMASK32,	c_xf86vidmode_flags},
	{	36,	"reserved1",	ft_UINT32,	NULL},
	{	40,	"reserved2",	ft_UINT32,	NULL},
	{	44,	"reserved3",	ft_UINT32,	NULL},
	{	48,	"privsize",	ft_UINT32,	NULL},
	EOP
};
static const struct parameter returnXF86VidModeValidateModeLine[] = {
	{	 8,	"status",	ft_CARD32,	NULL},
	EOP
};
#define parameterXF86VidModeDeleteModeLine parameterXF86VidModeValidateModeLine
#define parameterXF86VidModeSwitchToMode parameterXF86VidModeValidateModeLine

static const struct parameter parameterXF86VidModeSwitchMode[] = {
	{	 4,	"screen",	ft_CARD16,	NULL},
	{	 6,	"zoom",		ft_UINT16,	NULL},
	EOP
};
static const struct parameter parameterXF86VidModeLockModeSwitch[] = {
	{	 4,	"screen",	ft_CARD16,	NULL},
	{	 6,	"lock",		ft_CARD16,	NULL},
	EOP
};

static const struct parameter returnXF86VidModeGetViewPort[] = {
	{	 8,	"x",	ft_UINT32,	NULL},
	{	12,	"y",	ft_UINT32,	NULL},
	EOP
};

static const struct parameter parameterXF86VidModeSetViewPort[] = {
	{	 4,	"screen",	ft_CARD16,	NULL},
	{	 8,	"x",		ft_UINT32,	NULL},
	{	12,	"y",		ft_UINT32,	NULL},
	EOP
};

static const struct parameter returnXF86VidModeGetDotClocks[] = {
	{	 8,	"flags",	ft_BITMASK32,	c_xf86vidmode_flags},
	{	12,	"clocks",	ft_UINT32,	NULL},
	{	16,	"maxclocks",	ft_UINT32,	NULL},
	EOP
};

static const struct parameter parameterXF86VidModeSetClientVersion[] = {
	{	 4,	"major",	ft_UINT16,	NULL},
	{	 6,	"minor",	ft_UINT16,	NULL},
	EOP
};

static const struct parameter returnXF86VidModeGetGamma[] = {
	{	 8,	"red",		ft_UINT32,	NULL},
	{	12,	"green",	ft_UINT32,	NULL},
	{	16,	"blue",		ft_UINT32,	NULL},
	EOP
};

static const struct parameter parameterXF86VidModeSetGamma[] = {
	{	 4,	"screen",	ft_CARD16,	NULL},
	{	 8,	"red",		ft_UINT32,	NULL},
	{	12,	"green",	ft_UINT32,	NULL},
	{	16,	"blue",		ft_UINT32,	NULL},
	EOP
};

static const struct parameter parameterXF86VidModeSetGammaRamp[] = {
	{	 4,	"screen",	ft_CARD16,	NULL},
	{	 8,	"size",		ft_COUNT32,	NULL},
	{	12,	"red",		ft_LISTofUINT16,	NULL},
	{	 8,	"size",		ft_COUNT32,	NULL},
	{ OFS_LATER,	"green",		ft_LISTofUINT16,	NULL},
	{	 8,	"size",		ft_COUNT32,	NULL},
	{ OFS_LATER,	"blue",		ft_LISTofUINT16,	NULL},
	EOP
};

static const struct parameter parameterXF86VidModeGetGammaRamp[] = {
	{	 4,	"screen",	ft_CARD16,	NULL},
	{	 6,	"size",		ft_UINT16,	NULL},
	EOP
};

static const struct parameter returnXF86VidModeGetGammaRamp[] = {
	{	 8,	"size",		ft_COUNT16,	NULL},
	{	32,	"red",		ft_LISTofUINT16,	NULL},
	{	 8,	"size",		ft_COUNT16,	NULL},
	{ OFS_LATER,	"green",	ft_LISTofUINT16,	NULL},
	{	 8,	"size",		ft_COUNT16,	NULL},
	{ OFS_LATER,	"blue",		ft_LISTofUINT16,	NULL},
	EOP
};
static const struct parameter parameterXF86VidModeGetGammaRampSize[] = {
	{	 4,	"screen",	ft_CARD16,	NULL},
	EOP
};

static const struct parameter returnXF86VidModeGetGammaRampSize[] = {
	{	 8,	"size",		ft_UINT16,	NULL},
	EOP
};
static const struct parameter returnXF86VidModeGetPermissions[] = {
	{	 8,	"permissions",	ft_BITMASK32,	c_xf86vidmode_perms},
	EOP
};

#undef EOV
#undef EOP
#define ra(a) { #a , parameter ## a , NULL,NULL,NULL}
#define rb(a) { #a , parameter ## a , return ## a ,NULL,NULL}
#define rc(a) { #a , NULL, NULL,NULL,NULL}
static const struct request extensionXF86VidMode[] = {
	rb(XF86VidModeQueryVersion),
	rb(XF86VidModeGetModeLine),
	ra(XF86VidModeModModeLine),
	ra(XF86VidModeSwitchMode),
	rb(XF86VidModeGetMonitor),
	ra(XF86VidModeLockModeSwitch),
	rb(XF86VidModeGetAllModeLines),
	ra(XF86VidModeAddModeLine),
	ra(XF86VidModeDeleteModeLine),
	rb(XF86VidModeValidateModeLine),
	ra(XF86VidModeSwitchToMode),
	rb(XF86VidModeGetViewPort),
	ra(XF86VidModeSetViewPort),
	rb(XF86VidModeGetDotClocks),
	ra(XF86VidModeSetClientVersion),
	ra(XF86VidModeSetGamma),
	rb(XF86VidModeGetGamma),
	rb(XF86VidModeGetGammaRamp),
	ra(XF86VidModeSetGammaRamp),
	rb(XF86VidModeGetGammaRampSize),
	rb(XF86VidModeGetPermissions),
};
#undef ra
#undef rb
#undef rc

static const struct event eventsXF86VidMode[] = {};
static const char *errorsXF86VidMode[] = {
	"XF86VidModeBadClock",
	"XF86VidModeBadHTimings",
	"XF86VidModeBadVTimings",
	"XF86VidModeModeUnsuitable",
	"XF86VidModeExtensionDisabled",
	"XF86VidModeClientNotLocal",
	"XF86VidModeZoomLocked"
};

