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
/* This file is based on the
		  X Window System Protocol
		   X Consortium Standard
		 X Version 11, Release 6.4

		    Robert W. Scheifler
		     X Consortium, Inc.

with the following trademark and copyright notices and acknowlegdgments:

X Window System is a trademark of X Consortium, Inc.

Copyright (C) 1986, 1987, 1988, 1994 X Consortium

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documenta-
tion files (the ``Software''), to deal in the Software with-
out restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to
whom the Software is furnished to do so, subject to the fol-
lowing conditions:

The above copyright notice and this permission notice shall
be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED ``AS IS'', WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PUR-
POSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE X CONSOR-
TIUM BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of the X Con-
sortium shall not be used in advertising or otherwise to
promote the sale, use or other dealings in this Software
without prior written authorization from the X Consortium.

		      Acknowledgments

The primary contributers to the X11 protocol are:

     Dave Carver (Digital HPW)
     Branko Gerovac (Digital HPW)
     Jim Gettys (MIT/Project Athena, Digital)
     Phil Karlton (Digital WSL)
     Scott McGregor (Digital SSG)
     Ram Rao (Digital UEG)
     David Rosenthal (Sun)
     Dave Winchell (Digital UEG)

The implementors of initial server who provided useful input
are:

     Susan Angebranndt (Digital)
     Raymond Drewry (Digital)
     Todd Newman (Digital)

The invited reviewers who provided useful input are:

     Andrew Cherenson (Berkeley)
     Burns Fisher (Digital)
     Dan Garfinkel (HP)
     Leo Hourvitz (Next)
     Brock Krizan (HP)
     David Laidlaw (Stellar)
     Dave Mellinger (Interleaf)
     Ron Newman (MIT)
     John Ousterhout (Berkeley)
     Andrew Palay (ITC CMU)
     Ralph Swick (MIT)
     Craig Taylor (Sun)
     Jeffery Vroom (Stellar)
*/

#define EOV {0, NULL, -1, NULL}
#define EOC {-1, NULL}

static const struct constant c_function[] = {
	{0,	"Clear"},
	{1,	"And"},
	{2,	"AndReverse"},
	{3,	"Copy"},
	{4,	"AndInverted"},
	{5,	"NoOp"},
	{6,	"Xor"},
	{7,	"Or"},
	{8,	"Nor"},
	{9,	"Equiv"},
	{10,	"Invert"},
	{11,	"OrReverse"},
	{12,	"CopyInverted"},
	{13,	"OrInverted"},
	{14,	"Nand"},
	{15,	"Set"},
	EOC
};
static const struct constant c_line_style[] = {
	{0,	"Solid"},
	{1,	"OnOffDash"},
	{2,	"DoubleDash"},
	EOC
};
static const struct constant c_cap_style[] = {
	{0,	"NotLast"},
	{1,	"Butt"},
	{2,	"Round"},
	{3,	"Projecting"},
	EOC
};
static const struct constant c_join_style[] = {
	{0,	"Miter"},
	{1,	"Round"},
	{2,	"Bevel"},
	EOC
};
static const struct constant c_fill_style[] = {
	{0,	"Solid"},
	{1,	"Tiled"},
	{2,	"Stippled"},
	{3,	"OpaqueStippled"},
	EOC
};
static const struct constant c_fill_rule[] = {
	{0,	"EvenOdd"},
	{1,	"Winding"},
	EOC
};
static const struct constant c_subwindow_mode[] = {
	{0,	"ClipByChildren"},
	{1,	"IncludeInferiors"},
	EOC
};
#define ft_SubwindowMode	ft_ENUM8, c_subwindow_mode
static const struct constant c_arc_mode[] = {
	{0,	"Chord"},
	{1,	"PieSlice"},
	EOC
};



static const struct constant c_insert_delete[] = {
		{0	,	"Insert"},
		{1	,	"Delete"},
		EOC
};
static const struct constant c_windowclass[] = {
		{0	,	"CopyFromParent"},
		{1	,	"InputOutput"},
		{2	,	"InputOnly"},
		EOC
};
static const struct constant c_copyfromparent[] = {
		{0	,	"CopyFromParent"},
		EOC
};
static const struct constant c_store[] = {
		{0	,	"NotUseful"},
		{1	,	"WhenMapped"},
		{2	,	"Always"},
		EOC
};
static const struct constant c_bitgravity[] = {
		{0,	"Forget"},
		{1,	"NorthWest"},
		{2,	"North"},
		{3,	"NorthEast"},
		{4,	"West"},
		{5,	"Center"},
		{6,	"East"},
		{7,	"SouthWest"},
		{8,	"South"},
		{9,	"SouthEast"},
		{10,	"Static"},
		EOC
};
static const struct constant c_wingravity[] = {
		{0,	"Unmap"},
		{1,	"NorthWest"},
		{2,	"North"},
		{3,	"NorthEast"},
		{4,	"West"},
		{5,	"Center"},
		{6,	"East"},
		{7,	"SouthWest"},
		{8,	"South"},
		{9,	"SouthEast"},
		{10,	"Static"},
		EOC
};

#define ft_WINGRAVITY	ft_ENUM8,	c_wingravity
#define ft_BITGRAVITY	ft_ENUM8,	c_bitgravity

static const struct constant c_mapstate[] = {
		{0	,	"Unmapped"},
		{1	,	"Unviewable"},
		{2	,	"Viewable"},
		EOC
};
static const struct constant c_none[] = {
		{0	,	"None"},
		EOC
};
static const struct constant c_nonerelative[] = {
		{0	,	"None"},
		{1	,	"ParentRelative"},
		EOC
};
static const struct constant c_any[] = {
		{0	,	"any"},
		EOC
};

static const struct constant c_setofevent[] = {
		{0x00000001,"KeyPress"},
		{0x00000002,"KeyRelease"},
		{0x00000004,"ButtonPress"},
		{0x00000008,"ButtonRelease"},
		{0x00000010,"EnterWindow"},
		{0x00000020,"LeaveWindow"},
		{0x00000040,"PointerMotion"},
		{0x00000080,"PointerMotionHint"},
		{0x00000100,"Button1Motion"},
		{0x00000200,"Button2Motion"},
		{0x00000400,"Button3Motion"},
		{0x00000800,"Button4Motion"},
		{0x00001000,"Button5Motion"},
		{0x00002000,"ButtonMotion"},
		{0x00004000,"KeymapState"},
		{0x00008000,"Exposure"},
		{0x00010000,"VisibilityChange"},
		{0x00020000,"StructureNotify"},
		{0x00040000,"ResizeRedirect"},
		{0x00080000,"SubstructureNotify"},
		{0x00100000,"SubstructureRedirect"},
		{0x00200000,"FocusChange"},
		{0x00400000,"PropertyChange"},
		{0x00800000,"ColormapChange"},
		{0x01000000,"OwnerGrabButton"},
		EOC
};
#define ft_SETofEVENT ft_BITMASK32,	c_setofevent
#define ft_SETofDEVICEEVENT ft_SETofEVENT
#define ft_SETofPOINTEREVENT ft_SETofEVENT

static const struct constant c_setofkeybutmask[] = {
		{0x0001, "Shift"},
		{0x0002, "Lock"},
		{0x0004, "Control"},
		{0x0008, "Mod1"},
		{0x0010, "Mod2"},
		{0x0020, "Mod3"},
		{0x0040, "Mod4"},
		{0x0080, "Mod5"},
		{0x0100, "Button1"},
		{0x0200, "Button2"},
		{0x0400, "Button3"},
		{0x0800, "Button4"},
		{0x1000, "Button5"},
		{0x8000, "AnyModifier"},
		EOC
};
#define ft_SETofKEYBUTMASK	ft_BITMASK16,	c_setofkeybutmask
#define ft_SETofKEYMASK	ft_SETofKEYBUTMASK
static const struct constant c_bool[] = {
		{0	,	"false"},
		{1	,	"true"},
		EOC
};
#define ft_BOOL	ft_ENUM8,	c_bool

static const struct constant c_circulate[] = {
		{0	, "RaiseLowest"},
		{1	, "LowerHighest"},
		EOC
};

static const struct constant c_change_mode[] = {
		{0	, "Replace"},
		{1	, "Prepend"},
		{2	, "Append"},
		EOC
};

static const struct constant c_curtime[] = {
	{ 0, "CurrentTime"},
	EOC
};

static const struct constant c_choosewindow[] = {
	{0	, "PointerWindow"},
	{1	, "InputFocus"},
	EOC
};

static const struct constant c_synmode[] = {
	{0	, "Synchronous"},
	{1	, "Asynchronous"},
	EOC
};

static const struct constant c_grabsuccess[] = {
	{0	, "Success"},
	{1	, "AlreadyGrabbed"},
	{2	, "InvalidTime"},
	{3	, "NotViewable"},
	{4	, "Frozen"},
	EOC
};

static const struct constant c_button[] = {
	{0, "any button"},
	{1, "left button"},	
	{2, "middle button"},	
	{3, "right button"},	
	EOC
};
#define ft_BUTTON	ft_CARD8,	c_button

static const struct constant c_allowevents[] = {
	{0	, "AsyncPointer"},
	{1	, "SyncPointer"},
	{2	, "ReplayPointer"},
	{3	, "AsyncKeyboard"},
	{4	, "SyncKeyboard"},
	{5	, "ReplayKeyboard"},
	{6	, "AsyncBoth"},
	{7	, "SyncBoth"},
	EOC
};

static const struct constant c_revertto[] = {
	{0	, "None"},
	{1	, "PointerRoot"},
	{2	, "Parent"},
	EOC
};

static const struct constant c_noneroot[] = {
	{0	, "None"},
	{1	, "PointerRoot"},
	EOC
};
static const struct constant c_copygcvalues[] = {
		{0x00000001, "function"},
		{0x00000002, "plane-mask"},
		{0x00000004, "foreground"},
		{0x00000008, "background"},
		{0x00000010, "line-width"},
		{0x00000020, "line-style"},
		{0x00000040, "cap-style"},
		{0x00000080, "join-style"},
		{0x00000100, "fill-style"},
		{0x00000200, "fill-rule"},
		{0x00000400, "tile"},
		{0x00000800, "stipple"},
		{0x00001000, "tile-stipple-x-origin"},
		{0x00002000, "tile-stipple-y-origin"},
		{0x00004000, "font"},
		{0x00008000, "subwindow-mode"},
		{0x00010000, "graphics-exposures"},
		{0x00020000, "clip-x-origin"},
		{0x00040000, "clip-y-origin"},
		{0x00080000, "clip-mask"},
		{0x00100000, "dash-offset"},
		{0x00200000, "dashes"},
		{0x00400000, "arc-mode"},
		EOC
};
static const struct constant c_direction[] = {
	{0	, "LeftToRight"},
	{1	, "RightToLeft"},
	EOC
};
static const struct constant c_rect_ordering[] = {
	{0,	"UnSorted"},
	{1,	"YSorted"},
	{2,	"YXSorted"},
	{3,	"YXBanded"},
	EOC
};
static const struct constant c_coordinate_mode[] = {
	{0,	"Origin"},
	{1,	"Previous"},
	EOC
};

static const struct constant c_shape[] = {
	{0,	"Complex"},
	{1,	"Nonconvex"},
	{2,	"Convex"},
	EOC
};

static const struct constant c_bitmap_format[] = {
	{0,	"Bitmap"},
	{1,	"XYPixmap"},
	{2,	"ZPixmap"},
	EOC
};

static const struct constant c_alloc[] = {
	{0,	"None"},
	{1,	"All"},
	EOC
};

static const struct constant c_doredgreenblue[] = {
	{0x01,	"red"},
	{0x02,	"green"},
	{0x04,	"blue"},
	EOC
};

static const struct constant c_sizeclass[] = {
	{0,	"Cursor"},
	{1,	"Tile"},
	{2,	"Stipple"},
	EOC
};

static const struct constant c_keyboardvaluemask[] = {
	{0x0001,	"key-click-percent"},
	{0x0002,	"bell-percent"},
	{0x0004,	"bell-pitch"},
	{0x0008,	"bell-duration"},
	{0x0010,	"led"},
	{0x0020,	"led-mode"},
	{0x0040,	"key"},
	{0x0080,	"auto-repeat-mode"},
	EOC
};

static const struct constant c_nyd[] = {
	{0,	"No"},
	{1,	"Yes"},
	{2,	"Default"},
	EOC
};

static const struct constant c_insertdelete[] = {
	{0,	"Insert"},
	{1,	"Delete"},
	EOC
};

static const struct constant c_family[] = {
	{0,	"Internet"},
	{1,	"DECnet"},
	{2,	"Chaos"},
	EOC
};

static const struct constant c_disabledenabled[] = {
	{0,	"Disabled"},
	{1,	"Enabled"},
	EOC
};

static const struct constant c_disableenable[] = {
	{0,	"Disable"},
	{1,	"Enable"},
	EOC
};

static const struct constant c_closemode[] = {
	{0,	"Destroy"},
	{1,	"RetainPermanent"},
	{2,	"RetainTemporary"},
	EOC
};

static const struct constant c_alltemporary[] = {
	{0,	"AllTemporary"},
	EOC
};


static const struct constant c_resetactivate[] = {
	{0,	"Reset"},
	{1,	"Activate"},
	EOC
};


static const struct constant c_successbusyfailed[] = {
	{0,	"Success"},
	{1,	"Busy"},
	{2,	"Failed"},
	EOC
};

static const struct constant c_stack_mode[] = {
	{0,	"Above"},
	{1,	"Below"},
	{2,	"TopIf"},
	{3,	"BottomIf"},
	{4,	"Opposite"},
	EOC
};


#undef EOC
#define EOP {0,NULL,0,NULL}
#define LC(len) {len,NULL,0,NULL}

#define ft_WINDOW	ft_CARD32
#define ft_VISUALID	ft_CARD32
#define ft_COLORMAP	ft_CARD32
#define ft_PIXMAP	ft_CARD32
#define ft_CURSOR	ft_CARD32

static const struct value valuesCreateWindow[] = {
	{0x00000001,	"background-pixmap",	ft_PIXMAP,	c_nonerelative},
	{0x00000002,	"background-pixel",	ft_CARD32,	NULL},
	{0x00000004,	"border-pixmap",	ft_PIXMAP,	c_copyfromparent},
	{0x00000008,	"border-pixel",		ft_CARD32,	NULL},
	{0x00000010,	"bit-gravity",		ft_ENUM8,	c_bitgravity},
	{0x00000020,	"win-gravity",		ft_ENUM8,	c_wingravity},
	{0x00000040,	"backing-store",	ft_ENUM8,	c_store},
	{0x00000080,	"backing-planes",	ft_CARD32,	NULL},
	{0x00000100,	"backing-pixel"	,	ft_CARD32,	NULL},
	{0x00000200,	"override-redirect",	ft_BOOL},
	{0x00000400,	"save-under",		ft_BOOL},
	{0x00000800,	"event-mask",		ft_SETofEVENT},
	{0x00001000,	"do-not-propagate-mask",ft_SETofDEVICEEVENT},
	{0x00002000,	"colormap",		ft_COLORMAP,	c_copyfromparent},
	{0x00004000,	"cursor",		ft_CURSOR,	c_none},
	EOV
};

static const struct parameter parameterCreateWindow[] = {
	{	 1,	"depth",	ft_CARD8,	NULL	},
	{	 4,	"window",	ft_WINDOW,	NULL	},
	{	 8, 	"parent", 	ft_WINDOW,	NULL	},
	{	12,	"x", 		ft_INT16,	NULL	},
	{	14, 	"y", 		ft_INT16,	NULL	},
	{	16,  	"width", 	ft_UINT16,	NULL	},
	{	18, 	"height", 	ft_UINT16,	NULL	},
	{	20, 	"border-width", ft_UINT16,	NULL	},
	{	22, 	"class",	ft_ENUM16,	c_windowclass},
	{	24, 	"visual", 	ft_VISUALID , 	c_copyfromparent},
	{	28, 	"value-mask",	ft_STORE32,	NULL},
	{	32, 	"value-list",	ft_LISTofVALUE, (void*)valuesCreateWindow},
	EOP
};

static const struct parameter parameterChangeWindowAttributes[] = {
	{	4,	"window",	ft_WINDOW,	NULL},
	{	8, 	"value-mask",	ft_STORE32,	NULL},
	{	12, 	"value-list",	ft_LISTofVALUE, (void*)valuesCreateWindow},
	EOP
};

static const struct parameter parameterGetWindowAttributes[] = {
	{	4,	"window",	ft_WINDOW,	NULL	},
	EOP
};
static const struct parameter returnGetWindowAttributes[] = {
	{	1,	"backing-store",ft_ENUM8,	c_store},
	{	8,	"visual",	ft_VISUALID,	NULL},
	{	12,	"class",	ft_ENUM16,	c_windowclass,},
	{	14,	"bit-gravity",	ft_BITGRAVITY},
	{	15,	"win-gravity",	ft_WINGRAVITY},
	{	16,	"backing-planes",ft_CARD32,	NULL	},
	{	20,	"backing-pixel",ft_CARD32,	NULL	},
	{	24,	"save-under",	ft_BOOL},
	{	25,	"map-is-installed",ft_BOOL},
	{	26,	"map-state",	ft_ENUM8,	c_mapstate},
	{	27,	"override-redirect",ft_BOOL},
	{	28,	"colormap",	ft_COLORMAP,	c_none},
	{	32,	"all-event-masks",	ft_SETofEVENT	},
	{	36,	"your-event-mask",	ft_SETofEVENT	},
	{	38,	"do-not-propagate-mask",ft_SETofDEVICEEVENT},
	{	40,	"unused",		ft_CARD16,	NULL	},
	EOP
};

static const struct parameter parameterWINDOW[] = {
	{	4,	"window",	ft_WINDOW,	NULL	},
	EOP
};

static const struct parameter parameterEmpty[] = {
	EOP
};

static const struct parameter parameterChangeSaveSet[] = {
	{	1,	"mode",		ft_ENUM8,	c_insert_delete },
	{	4,	"window",	ft_WINDOW,	NULL	},
	EOP
};

static const struct parameter parameterReparentWindow[] = {
	{	4,	"window",	ft_WINDOW,	NULL	},
	{	8,	"parent",	ft_WINDOW,	NULL	},
	{	12,	"x",	ft_INT16,	NULL	},
	{	14,	"y",	ft_INT16,	NULL	},
	EOP
};

static const struct value valuesConfigureWindow[] = {
	{0x0001, "x",		ft_INT16,	NULL},
	{0x0002, "y",		ft_INT16,	NULL},
	{0x0004, "width",	ft_UINT16,	NULL},
	{0x0008, "height",	ft_UINT16,	NULL},
	{0x0010, "border-width",ft_UINT16,	NULL},
	{0x0020, "sibling",	ft_WINDOW,	NULL},
	{0x0040, "stack-mode", 	ft_ENUM8,	c_stack_mode},
	EOV
};

static const struct parameter parameterConfigureWindow[] = {
	{	4,	"window",	ft_WINDOW,	NULL},
	{	8,	"value-mask",	ft_STORE16,	NULL},
	{	8,	"values",	ft_LISTofVALUE,(void*)valuesConfigureWindow},
	EOP
};


static const struct parameter parameterCirculateWindow[] = {
	{	1,	"direction",	ft_ENUM8,	c_circulate},
	{	4,	"window",	ft_WINDOW,	NULL},
  	EOP
};


#define ft_DRAWABLE ft_CARD32

static const struct parameter parameterGetGeometry[] = {
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	EOP
};


static const struct parameter returnGetGeometry[] = {
	{	1,	"depth",	ft_CARD8,	NULL},
	{	8,	"root",	ft_WINDOW,	NULL},
	{	12,	"x",	ft_INT16,	NULL},
	{	14,	"y",	ft_INT16,	NULL},
	{	16,	"width",	ft_UINT16,	NULL},
	{	18,	"height",	ft_UINT16,	NULL},
	{	20,	"border-width",	ft_UINT16,	NULL},
	EOP
};


#define parameterQueryTree parameterWINDOW

#define ft_LISTofWINDOW ft_LISTofCARD32
static const struct parameter returnQueryTree[] = {
	{	8,	"root",		ft_WINDOW,	NULL},
	{	12,	"parent",	ft_WINDOW,	c_none},
	{	16,	"#",		ft_COUNT16,	NULL},
	{	32,	"children",	ft_LISTofWINDOW,	NULL},
	EOP
};

static const struct parameter parameterInternAtom[] = {
	{	1,	"only-if-exists",	ft_BOOL},
	{	4,	"length of name",	ft_COUNT16,	NULL},
	{	8,	"name",	ft_STRING8,	NULL},
	EOP
};

static const struct parameter returnInternAtom[] = {
	{	8,	"atom",	ft_ATOM,	c_none},
	EOP
};



static const struct parameter parameterAtom[] = {
	{	4,	"atom",	ft_ATOM,	NULL},
	EOP
};

#define parameterGetAtomName parameterAtom

static const struct parameter returnGetAtomName[] = {
	{	8,	"length of name",	ft_COUNT32,	NULL},
	{	32,	"name",	ft_STRING8,	NULL},
	EOP
};

static const struct parameter parameterChangeProperty[] = {
	{	1,	"mode",		ft_ENUM8,	c_change_mode},
	{	4,	"window",	ft_WINDOW,	NULL},
	{	8,	"property",	ft_ATOM,	NULL},
	{	12,	"type",		ft_ATOM,	NULL},
	{	16,	"format",	ft_FORMAT8,	NULL},
	{	20,	"length in format units",ft_COUNT32,	NULL},
	{	12,	"STRING",	ft_IFATOM,	(void*)&parameterChangeProperty[10]},
	{	12,	"ATOM",		ft_IFATOM,	(void*)&parameterChangeProperty[12]},
	{	24,	"data",		ft_LISTofFormat,	NULL},
	EOP,
	{	24,	"data",		ft_STRING8,	NULL},
	EOP,
	{	24,	"data",		ft_LISTofATOM,	NULL},
	EOP
};

static const struct parameter parameterDeleteProperty[] = {
	{	4,	"window",	ft_WINDOW,	NULL},
	{	8,	"property",	ft_ATOM,	NULL},
	EOP
};

static const struct parameter parameterGetProperty[] = {
	{	1,	"delete",	ft_BOOL},
	{	4,	"window",	ft_WINDOW,	NULL},
	{	8,	"property",	ft_ATOM,	NULL},
	{	12,	"type",		ft_ATOM,	c_any},
	{	16,	"long-offset",	ft_CARD32,	NULL},
	{	20,	"long-length",	ft_CARD32,	NULL},
	EOP
};

static const struct parameter returnGetProperty[] = {
	{	1,	"format",	ft_FORMAT8,	NULL},
	{	8,	"type",		ft_ATOM,	c_none},
	{	12,	"bytes-after",	ft_CARD32,	NULL},
	{	16,	"length in format units",ft_COUNT32,	NULL},
	{	8,	"STRING",	ft_IFATOM,	(void*)&returnGetProperty[8]},
	{	8,	"ATOM",		ft_IFATOM,	(void*)&returnGetProperty[10]},
	{	32,	"data",		ft_LISTofFormat,	NULL},
	EOP,
	{	32,	"data",		ft_STRING8,	NULL},
	EOP,
	{	32,	"data",		ft_LISTofATOM,	NULL},
	EOP
};

#define parameterListProperties parameterWINDOW

static const struct parameter returnListProperties[] = {
	{	8,	"#",		ft_COUNT16,	NULL},
	{	32,	"atoms",	ft_LISTofATOM,	NULL},
	EOP
};

#define ft_TIMESTAMP ft_CARD32
static const struct parameter parameterSetSelectionOwner[] = {
	{	4,	"owner",	ft_WINDOW,	c_none},
	{	8,	"selection",	ft_ATOM,	NULL},
	{	12,	"time",		ft_TIMESTAMP,	c_curtime},
	EOP
};


#define parameterGetSelectionOwner parameterAtom

static const struct parameter returnGetSelectionOwner[] = {
	{	8,	"owner",	ft_WINDOW,	c_none},
	EOP
};

static const struct parameter parameterConvertSelection[] = {
	{	4,	"requestor",	ft_WINDOW,	NULL},
	{	8,	"selection",	ft_ATOM,	NULL},
	{	12,	"target",	ft_ATOM,	NULL},
	{	16,	"property",	ft_ATOM,	c_none},
	{	20,	"time",		ft_TIMESTAMP,	c_curtime},
	EOP
};

static const struct parameter parameterSendEvent[] = {
	{	1,	"propagate",	ft_BOOL},
	{	4,	"destination",	ft_WINDOW,	c_choosewindow},
	{	8,	"event-mask",	ft_SETofEVENT},
	{      12,	"event",	ft_EVENT,	NULL},
	EOP
};

static const struct parameter parameterGrabPointer[] = {
	{	1,	"owner-events",	ft_BOOL},
	{	4,	"grab-window",	ft_WINDOW,	NULL},
	{	8,	"event-mask",	ft_SETofPOINTEREVENT},
	{	10,	"pointer-mode",	ft_ENUM8,	c_synmode},
	{	11,	"keyboard-mode",ft_ENUM8,	c_synmode},
	{	12,	"confine-to",	ft_WINDOW,	c_none},
	{	16,	"cursor",	ft_CURSOR,	c_none},
	{	20,	"time",		ft_TIMESTAMP,	c_curtime},
	EOP
};

static const struct parameter returnGrabPointer[] = {
	{	1,	"status",	ft_ENUM8,	c_grabsuccess},
	EOP
};

#define parameterUngrabPointer parameterTimestamp
static const struct parameter parameterTimestamp[] = {
	{	4,	"time",	ft_TIMESTAMP,	c_curtime},
	EOP
};

static const struct parameter parameterGrabButton[] = {
	{	1,	"owner-events",	ft_BOOL},
	{	4,	"grab-window",	ft_WINDOW,	NULL},
	{	8,	"event-mask",	ft_SETofPOINTEREVENT},
	{	10,	"pointer-mode",	ft_ENUM8,	c_synmode},
	{	11,	"keyboard-mode",ft_ENUM8,	c_synmode},
	{	12,	"confine-to",	ft_WINDOW,	c_none},
	{	16,	"cursor",	ft_CURSOR,	c_none},
	{	20,	"button",	ft_BUTTON},
	{	22,	"modifiers",	ft_SETofKEYMASK},
	EOP
};


static const struct parameter parameterUngrabButton[] = {
	{	1,	"button",	ft_BUTTON},
	{	4,	"grab-window",	ft_WINDOW,	NULL},
	{	8,	"modifiers",	ft_SETofKEYMASK},
	EOP
};

static const struct parameter parameterChangeActivePointerGrab[] = {
	{	4,	"cursor",	ft_CURSOR,	c_none},
	{	8,	"time",		ft_TIMESTAMP,	c_curtime},
	{	12,	"event-mask",	ft_SETofPOINTEREVENT},
EOP
};

#define ft_SYNMODE	ft_CARD8,	c_synmode

static const struct parameter parameterGrabKeyboard[] = {
	{	4,	"grab-window",	ft_WINDOW,	NULL},
	{	8,	"time",		ft_TIMESTAMP,	c_curtime},
	{	12,	"pointer-mode",	ft_SYNMODE},
	{	13,	"keyboard-mode",ft_SYNMODE},
	EOP
};

#define returnGrabKeyboard returnGrabPointer

#define parameterUngrabKeyboard parameterTimestamp

#define ft_KEYCODE	ft_CARD8

static const struct parameter parameterGrabKey[] = {
	{	1,	"owner-events",	ft_BOOL},
	{	4,	"grab-window",	ft_WINDOW,	NULL},
	{	8,	"modifiers",	ft_SETofKEYMASK},
	{	10,	"key",		ft_KEYCODE,	c_any},
	{	11,	"pointer-mode",	ft_SYNMODE},
	{	12,	"keyboard-mode",ft_SYNMODE},
	EOP
};

static const struct parameter parameterUngrabKey[] = {
	{	1,	"key",		ft_KEYCODE,	c_any},
	{	4,	"grab-window",	ft_WINDOW,	NULL},
	{	8,	"modifiers",	ft_SETofKEYMASK},
	EOP
};

static const struct parameter parameterAllowEvents[] = {
	{	1,	"mode",	ft_ENUM8,	c_allowevents},
	{	5,	"time",	ft_TIMESTAMP,	c_curtime},
	EOP
};

#define parameterQueryPointer parameterWINDOW

static const struct parameter returnQueryPointer[] = {
	{	1,	"same-screen",	ft_BOOL},
	{	8,	"root",		ft_WINDOW,	NULL},
	{	12,	"child",	ft_WINDOW,	c_none},
	{	16,	"root-x",	ft_INT16,	NULL},
	{	18,	"root-y",	ft_INT16,	NULL},
	{	20,	"win-x",	ft_INT16,	NULL},
	{	22,	"win-y",	ft_INT16,	NULL},
	{	24,	"mask",		ft_SETofKEYBUTMASK},
	EOP
};

static const struct parameter parameterGetMotionEvents[] = {
	{	4,	"window",	ft_WINDOW,	NULL},
	{	8,	"start",	ft_TIMESTAMP,	c_curtime},
	{	12,	"stop",		ft_TIMESTAMP,	c_curtime},
	EOP
};


static const struct parameter listTIMECOORD[] = {
	LC(8),
	{	0,	"time",	ft_TIMESTAMP,	NULL},
	{	4,	"x",	ft_INT16,	NULL},
	{	6,	"y",	ft_INT16,	NULL},
	EOP
};
#define ft_LISTofTIMECOORD ft_LISTofStruct,	(void*)listTIMECOORD

static const struct parameter returnGetMotionEvents[] = {
	{	8,	"#",	ft_COUNT32,	NULL},
	{	32,	"events",ft_LISTofTIMECOORD},
	EOP
};

static const struct parameter parameterTranslateCoordinates[] = {
	{	4,	"src-window",	ft_WINDOW,	NULL},
	{	8,	"dst-window",	ft_WINDOW,	NULL},
	{	12,	"src-x",	ft_INT16,	NULL},
	{	14,	"src-y",	ft_INT16,	NULL},
	EOP
};

static const struct parameter returnTranslateCoordinates[] = {
	{	1,	"same-screen",	ft_BOOL},
	{	8,	"child",	ft_WINDOW,	c_none},
	{	12,	"dst-x",	ft_INT16,	NULL},
	{	14,	"dst-y",	ft_INT16,	NULL},
	EOP
};

static const struct parameter parameterWarpPointer[] = {
	{	4,	"src-window",	ft_WINDOW,	c_none},
	{	8,	"dst-window",	ft_WINDOW,	c_none},
	{	12,	"src-x",	ft_INT16,	NULL},
	{	14,	"src-y",	ft_INT16,	NULL},
	{	16,	"src-width",	ft_UINT16,	NULL},
	{	18,	"src-height",	ft_UINT16,	NULL},
	{	20,	"dst-x",	ft_INT16,	NULL},
	{	22,	"dst-y",	ft_INT16,	NULL},
	EOP
};

static const struct parameter parameterSetInputFocus[] = {
	{	1,	"revert-to",	ft_ENUM8,	c_revertto},
	{	4,	"focus",	ft_WINDOW,	c_noneroot},
	{	8,	"time",		ft_TIMESTAMP,	c_curtime},
	EOP
};

#define parameterGetInputFocus parameterNone
static const struct parameter parameterNone[] = {
	EOP
};

static const struct parameter returnGetInputFocus[] = {
	{	1,	"revert-to",	ft_ENUM8,	c_revertto},
	{	8,	"focus",	ft_WINDOW,	c_noneroot},
	EOP
};

#define parameterQueryKeymap parameterNone

static const struct parameter returnQueryKeymap[] = {
	{	8,	"keys",		ft_LISTofCARD8,	NULL},
	EOP
};

#define ft_FONT ft_CARD32
static const struct parameter parameterOpenFont[] = {
	{	4,	"fid",		ft_FONT,	NULL},
	{	8,	"length of name",ft_COUNT16,	NULL},
	{	12,	"name",		ft_STRING8,	NULL},
	EOP
};

static const struct parameter parameterFONT[] = {
	{	4,	"font",		ft_FONT,	NULL},
  EOP
};
#define parameterCloseFont parameterFONT
#define parameterQueryFont parameterFONT

/* What is that really? */
#define ft_32bits ft_CARD32

static const struct parameter listFONTPROP[] = {
	LC(8),
	{	0,	"name",		ft_ATOM,	NULL},
	{	4,	"value",	ft_32bits,	NULL},
	EOP
};
#define ft_LISTofFONTPROP 	ft_LISTofStruct,	(void*)listFONTPROP

static const struct parameter listCHARINFO[] = {
	LC(12),
	{	0,	"left-side-bearing",	ft_INT16,	NULL},
	{	2,	"right-side-bearing",	ft_INT16,	NULL},
	{	4,	"character-width",	ft_INT16,	NULL},
	{	6,	"ascent",		ft_INT16,	NULL},
	{	8,	"descent",		ft_INT16,	NULL},
	{	10,	"attributes",		ft_CARD16,	NULL},
	EOP
};
#define ft_CHARINFO 		ft_Struct,		(void*)listCHARINFO
#define ft_LISTofCHARINFO 	ft_LISTofStruct,	(void*)listCHARINFO

static const struct parameter returnQueryFont[] = {
	{	8,	"min-bounds",		ft_CHARINFO},
	{	24,	"max-bounds",		ft_CHARINFO},
	{	40,	"min-char-or-byte2",	ft_CARD16,	NULL},
	{	42,	"max-char-or-byte2",	ft_CARD16,	NULL},
	{	44,	"default-char",		ft_CARD16,	NULL},
	{	46,	"#FONTPROPs",		ft_COUNT16,	NULL},
	{	48,	"draw-direction",	ft_ENUM8,	c_direction},
	{	49,	"min-byte1",		ft_CARD8,	NULL},
	{	50,	"max-byte1",		ft_CARD8,	NULL},
	{	51,	"all-chars-exist",	ft_BOOL},
	{	52,	"font-ascent",		ft_INT16,	NULL},
	{	54,	"font-descent",		ft_INT16,	NULL},
	{	60,	"properties",		ft_LISTofFONTPROP},
	{	56,	"#CHARINFOs",		ft_COUNT32,	NULL},
	{OFS_LATER,	"char-infos",		ft_LISTofCHARINFO},
/* ofs 60:
   8n LISTofFONTPROP	 properties
  12m	       LISTofCHARINFOchar-infos
  */
  	EOP
};

#define ft_FONTABLE ft_CARD32
#define ft_STRING16 ft_LISTofCARD16
static const struct parameter parameterQueryTextExtents[] = {
	{	1,	"lastunused",	ft_BOOL},
	{	4,	"font",		ft_FONTABLE,	NULL},
	{	8,	"string",	ft_STRING16,	NULL},
	EOP
};

static const struct parameter returnQueryTextExtents[] = {
	{	1,	"draw-direction",	ft_ENUM8,	c_direction},
	{	8,	"font-ascent",		ft_INT16,	NULL},
	{	10,	"font-descent",		ft_INT16,	NULL},
	{	12,	"overall-ascent",	ft_INT16,	NULL},
	{	14,	"overall-descent",	ft_INT16,	NULL},
	{	16,	"overall-width",	ft_INT32,	NULL},
	{	20,	"overall-left",		ft_INT32,	NULL},
	{	24,	"overall-right",	ft_INT32,	NULL},
	EOP
};

static const struct parameter parameterListFonts[] = {
	{	4,	"max-names",	ft_CARD16,	NULL},
	{	6,	"length of pattern",ft_COUNT16,	NULL},
	{	8,	"pattern",	ft_STRING8,	NULL},
	EOP
};

static const struct parameter listSTRING8[] = {
	LC(1),
	{	0,	"c",	ft_COUNT8,	NULL},
	{	1,	"s",	ft_STRING8,	NULL},
	EOP
};

#define ft_LISTofSTRING8 ft_LISTofVarStruct,	(void*)listSTRING8

static const struct parameter returnListFonts[] = {
	{	 8,	"number of answers",	ft_COUNT16,	NULL},
	{	32,	"names",		ft_LISTofSTRING8},
	EOP
};

#define parameterListFontsWithInfo parameterListFonts

static const struct parameter returnListFontsWithInfo[] = {
	{	8,	"min-bounds",		ft_CHARINFO},
	{	24,	"max-bounds",		ft_CHARINFO},
	{	40,	"min-char-or-byte2",	ft_CARD16,	NULL},
	{	42,	"max-char-or-byte2",	ft_CARD16,	NULL},
	{	44,	"default-char",		ft_CARD16,	NULL},
	{	46,	"#FONTPROPs",		ft_COUNT16,	NULL},
	{	48,	"draw direction",	ft_ENUM8,	c_direction},
	{	49,	"min-byte1",		ft_CARD8,	NULL},
	{	50,	"max-byte1",		ft_CARD8,	NULL},
	{	51,	"all-chars-exist",	ft_BOOL},
	{	52,	"font-ascent",		ft_INT16,	NULL},
	{	54,	"font-descent",		ft_INT16,	NULL},
	{	56,	"replies-hint",		ft_CARD32,	NULL},
	{	60,	"properties",		ft_LISTofFONTPROP},
	{	1,	"length of name",	ft_CARD8,	NULL},
	{OFS_LATER,	"name",			ft_STRING8,	NULL},
/*
  8m LISTofFONTPROP	 properties
  n  STRING8		 name
  p			 unused, p=pad(n)
*/
	EOP
};

static const struct parameter parameterSetFontPath[] = {
	{	4,	"number of STRs in path",	ft_CARD16,	NULL},
	{	8,	"path",				ft_LISTofSTRING8}, 
	EOP
};

#define parameterGetFontPath parameterNone

static const struct parameter returnGetFontPath[] = {
	{	8,	"number of STRs in path",	ft_CARD16,	NULL},
	{	32,	"path",				ft_LISTofSTRING8},
	EOP
};

static const struct parameter parameterCreatePixmap[] = {
	{	1,	"depth",	ft_CARD8,	NULL},
	{	4,	"pid",		ft_PIXMAP,	NULL},
	{	8,	"drawable",	ft_DRAWABLE,	NULL},
	{	12,	"width",	ft_UINT16,	NULL},
	{	14,	"height",	ft_UINT16,	NULL},
	EOP
};

static const struct parameter parameterFreePixmap[] = {
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	EOP
};

#define ft_GCONTEXT ft_CARD32

static const struct value valuesCreateGC[] = {
		{0x00000001, "function",	ft_ENUM8,	c_function},
		{0x00000002, "plane-mask",	ft_CARD32,	NULL},
		{0x00000004, "foreground",	ft_CARD32,	NULL},
		{0x00000008, "background",	ft_CARD32,	NULL},
		{0x00000010, "line-width",	ft_UINT16,	NULL},
		{0x00000020, "line-style",	ft_ENUM8,	c_line_style},
		{0x00000040, "cap-style",	ft_ENUM8,	c_cap_style},
		{0x00000080, "join-style",	ft_ENUM8,	c_join_style},
		{0x00000100, "fill-style",	ft_ENUM8,	c_fill_style},
		{0x00000200, "fill-rule",	ft_ENUM8,	c_fill_rule},
		{0x00000400, "tile",		ft_PIXMAP,	NULL},
		{0x00000800, "stipple",		ft_PIXMAP,	NULL},
		{0x00001000, "tile-stipple-x-origin", ft_INT16,	NULL},
		{0x00002000, "tile-stipple-y-origin", ft_INT16,	NULL},
		{0x00004000, "font",		ft_FONT,	NULL},
		{0x00008000, "subwindow-mode",	ft_SubwindowMode},
		{0x00010000, "graphics-exposures",		ft_BOOL},
		{0x00020000, "clip-x-origin",	ft_INT16,	NULL},
		{0x00040000, "clip-y-origin",	ft_INT16,	NULL},
		{0x00080000, "clip-mask",	ft_PIXMAP,	c_none},
		{0x00100000, "dash-offset",	ft_UINT16,	NULL},
		{0x00200000, "dashes",		ft_UINT8,	NULL},
		{0x00400000, "arc-mode",	ft_ENUM8,	c_arc_mode},
		{0x00800000, "unknown22",	ft_CARD32,	NULL},
		{0x01000000, "unknown23",	ft_CARD32,	NULL},
		{0x02000000, "unknown24",	ft_CARD32,	NULL},
		{0x04000000, "unknown25",	ft_CARD32,	NULL},
		{0x08000000, "unknown26",	ft_CARD32,	NULL},
		{0x10000000, "unknown28",	ft_CARD32,	NULL},
		{0x20000000, "unknown29",	ft_CARD32,	NULL},
		{0x40000000, "unknown30",	ft_CARD32,	NULL},
		{0x80000000, "unknown31",	ft_CARD32,	NULL},
		EOV
};

static const struct parameter parameterCreateGC[] = {
	{	4,	"cid",		ft_GCONTEXT,	NULL},
	{	8,	"drawable",	ft_DRAWABLE,	NULL},
	{	12,	"value-mask",	ft_STORE32,	NULL},
	{	16,	"values",	ft_LISTofVALUE,(void*)valuesCreateGC},
	EOP
};

static const struct parameter parameterChangeGC[] = {
	{	4,	"gc",		ft_GCONTEXT,	NULL},
	{	8,	"value-mask",	ft_STORE32,	NULL},
	{	12,	"values",	ft_LISTofVALUE,(void*)valuesCreateGC},
	EOP
};

static const struct parameter parameterCopyGC[] = {
	{	4,	"src-gc",	ft_GCONTEXT,	NULL},
	{	8,	"dst-gc",	ft_GCONTEXT,	NULL},
	{	12,	"value-mask",	ft_BITMASK32,	c_copygcvalues},
	EOP
};

static const struct parameter parameterSetDashes[] = {
	{	4,	"gc",		ft_GCONTEXT,	NULL},
	{	8,	"dash-offset",	ft_CARD16,	NULL},
	{	10,	"# of dashes",	ft_COUNT16,	NULL},
	{	12,	"dashes",	ft_LISTofCARD8,	NULL},
	EOP
};

static const struct parameter listRECTANGLE[] = {
	LC(8),
	{	0,	"x",		ft_INT16,	NULL},
	{	2,	"y",		ft_INT16,	NULL},
	{	4,	"w",		ft_UINT16,	NULL},
	{	6,	"h",		ft_UINT16,	NULL},
	EOP
};
#define ft_LISTofRECTANGLE ft_LISTofStruct,	(void*)listRECTANGLE


static const struct parameter parameterSetClipRectangles[] = {
	{	1,	"ordering",	ft_ENUM8,	c_rect_ordering},
	{	4,	"gc",		ft_GCONTEXT,	NULL},
	{	8,	"clip-x-origin",ft_INT16,	NULL},
	{	10,	"clip-y-origin",ft_INT16,	NULL},
	{	12,	"rectangles ",	ft_LISTofRECTANGLE},
	EOP
};

#define parameterFreeGC parameterGC
static const struct parameter parameterGC[] = {
	{	4,	"gc",	ft_GCONTEXT,	NULL},
 	 EOP
};

static const struct parameter parameterClearArea[] = {
	{	1,	"exposures",	ft_BOOL},
	{	4,	"window",	ft_WINDOW,	NULL},
	{	8,	"x",		ft_INT16,	NULL},
	{	10,	"y",		ft_INT16,	NULL},
	{	12,	"width",	ft_UINT16,	NULL},
	{	14,	"height",	ft_UINT16,	NULL},
	EOP
};

static const struct parameter parameterCopyArea[] = {
	{	4,	"src-drawable",	ft_DRAWABLE,	NULL},
	{	8,	"dst-drawable",	ft_DRAWABLE,	NULL},
	{	12,	"gc",		ft_GCONTEXT,	NULL},
	{	16,	"src-x",	ft_INT16,	NULL},
	{	18,	"src-y",	ft_INT16,	NULL},
	{	20,	"dst-x",	ft_INT16,	NULL},
	{	22,	"dst-y",	ft_INT16,	NULL},
	{	24,	"width",	ft_UINT16,	NULL},
	{	26,	"height",	ft_UINT16,	NULL},
	EOP
};

static const struct parameter parameterCopyPlane[] = {
	{	4,	"src-drawable",	ft_DRAWABLE,	NULL},
	{	8,	"dst-drawable",	ft_DRAWABLE,	NULL},
	{	12,	"gc",	ft_GCONTEXT,	NULL},
	{	16,	"src-x",	ft_INT16,	NULL},
	{	18,	"src-y",	ft_INT16,	NULL},
	{	20,	"dst-x",	ft_INT16,	NULL},
	{	22,	"dst-y",	ft_INT16,	NULL},
	{	24,	"width",	ft_UINT16,	NULL},
	{	26,	"height",	ft_UINT16,	NULL},
	{	28,	"bit-plane",	ft_CARD32,	NULL},
	EOP
};

static const struct parameter listPOINT[] = {
	LC(4),
	{	0,	"x",		ft_INT16,	NULL},
	{	2,	"y",		ft_INT16,	NULL},
	EOP
};
#define ft_LISTofPOINT ft_LISTofStruct,	(void*)listPOINT


static const struct parameter parameterPolyPoint[] = {
	{	1,	"coordinate-mode",ft_ENUM8,	c_coordinate_mode},
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	{	8,	"gc",		ft_GCONTEXT,	NULL},
	{	12,	"points",	ft_LISTofPOINT},
	EOP
};

static const struct parameter parameterPolyLine[] = {
	{	1,	"coordinate-mode",ft_ENUM8,	c_coordinate_mode},
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	{	8,	"gc",		ft_GCONTEXT,	NULL},
	{	12,	"points",	ft_LISTofPOINT},
	EOP
};

static const struct parameter listSEGMENT[] = {
	LC(8),
	{	0,	"x1",		ft_INT16,	NULL},
	{	2,	"y1",		ft_INT16,	NULL},
	{	4,	"x2",		ft_INT16,	NULL},
	{	6,	"y2",		ft_INT16,	NULL},
	EOP
};
#define ft_LISTofSEGMENT ft_LISTofStruct,	(void*)listSEGMENT

static const struct parameter parameterPolySegment[] = {
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	{	8,	"gc",		ft_GCONTEXT,	NULL},
	{	12,	"segments",	ft_LISTofSEGMENT},
	EOP
};

static const struct parameter parameterPolyRectangle[] = {
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	{	8,	"gc",		ft_GCONTEXT,	NULL},
	{	12,	"rectangles",	ft_LISTofRECTANGLE},
	EOP
};

static const struct parameter listARC[] = {
	LC(12),
	{	0,	"x",		ft_INT16,	NULL},
	{	2,	"y",		ft_INT16,	NULL},
	{	4,	"w",		ft_UINT16,	NULL},
	{	6,	"h",		ft_UINT16,	NULL},
	{	8,	"angle1",	ft_INT16,	NULL},
	{	10,	"angle2",	ft_INT16,	NULL},
	EOP
};
#define ft_LISTofARC ft_LISTofStruct,	(void*)listARC

static const struct parameter parameterPolyArc[] = {
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	{	8,	"gc",		ft_GCONTEXT,	NULL},
	{	12,	"arcs",		ft_LISTofARC},
	EOP
};

static const struct parameter parameterFillPoly[] = {
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	{	8,	"gc",		ft_GCONTEXT,	NULL},
	{	12,	"shape",	ft_ENUM8,	c_shape},
	{	13,	"coordinate-mode",ft_ENUM8,	c_coordinate_mode},
	{	16,	"points",	ft_LISTofPOINT},
     	EOP
};

static const struct parameter parameterPolyFillRectangle[] = {
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	{	8,	"gc",		ft_GCONTEXT,	NULL},
	{	12,	"rectangles",	ft_LISTofRECTANGLE},
	EOP
};

#define parameterPolyFillArc parameterPolyArc

static const struct parameter parameterPutImage[] = {
	{	1,	"format",	ft_ENUM8,	c_bitmap_format},
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	{	8,	"gc",	ft_GCONTEXT,	NULL},
	{	12,	"width",	ft_UINT16,	NULL},
	{	14,	"height",	ft_UINT16,	NULL},
	{	16,	"dst-x",	ft_INT16,	NULL},
	{	18,	"dst-y",	ft_INT16,	NULL},
	{	20,	"left-pad",	ft_CARD8,	NULL},
	{	21,	"depth",	ft_CARD8,	NULL},
	EOP
};


static const struct parameter parameterGetImage[] = {
	{	1,	"format",	ft_ENUM8,	c_bitmap_format},
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	{	8,	"x",		ft_INT16,	NULL},
	{	10,	"y",		ft_INT16,	NULL},
	{	12,	"width",	ft_UINT16,	NULL},
	{	14,	"height",	ft_UINT16,	NULL},
	{	16,	"plane-mask",	ft_CARD32,	NULL},
	EOP
};


static const struct parameter returnGetImage[] = {
	{	1,	"depth",	ft_CARD8,	NULL},
	{	4,	"32-bit values got",	ft_CARD32,	NULL},
	{	8,	"visual",	ft_VISUALID,	c_none},
	EOP
};

static const struct parameter listPolyTextFont[] = {
	{	1,	"font",		ft_BE32,	NULL},
	{	5,	"",		ft_LASTMARKER,	NULL},
	EOP
};

static const struct parameter listPolyText8[] = {
	LC(3), /* minimum as VarStruct */
	{	0,	"\377",	ft_IF8,(void*)listPolyTextFont},
	/* prevent a empty string fitting in the last 3 pad bytes
	   showing up. (as this 3 pad bytes could contain a
	   string of length 1 I think) */
	{	0,	"\000",	ft_IF8,(void*)(&listPolyText8[5])},
	{	0,	"#",	ft_COUNT8,	NULL},
	{	1,	"delta",ft_INT8,	NULL},
	{	2,	"s",	ft_STRING8,	NULL},
	EOP
};
#define ft_LISTofPolyText8 ft_LISTofVarStruct,(const void*)listPolyText8

static const struct parameter parameterPolyText8[] = {
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	{	8,	"gc",		ft_GCONTEXT,	NULL},
	{	12,	"x",		ft_INT16,	NULL},
	{	14,	"y",		ft_INT16,	NULL},
	{	16,	"texts",	ft_LISTofPolyText8},
	EOP
};

static const struct parameter listPolyText16[] = {
	LC(4), /* minimum as VarStruct */
	{	0,	"\377",	ft_IF8,(void*)&listPolyTextFont},
	{	0,	"#",	ft_COUNT8,	NULL},
	{	1,	"delta",ft_INT8,	NULL},
	{	2,	"s",	ft_STRING16,	NULL},
	EOP
};
#define ft_LISTofPolyText16 ft_LISTofVarStruct,(const void*)listPolyText16

static const struct parameter parameterPolyText16[] = {
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	{	8,	"gc",		ft_GCONTEXT,	NULL},
	{	12,	"x",		ft_INT16,	NULL},
	{	14,	"y",		ft_INT16,	NULL},
	{	16,	"texts", 	ft_LISTofPolyText16},
	EOP
};

static const struct parameter parameterImageText8[] = {
	{	1,	"length of string",	ft_COUNT8,	NULL},
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	{	8,	"gc",	ft_GCONTEXT,	NULL},
	{	12,	"x",	ft_INT16,	NULL},
	{	14,	"y",	ft_INT16,	NULL},
	{	16,	"string",	ft_STRING8,	NULL},
	EOP
};

#define ft_STRING16 ft_LISTofCARD16

static const struct parameter parameterImageText16[] = {
	{	1,	"#",		ft_COUNT8,	NULL},
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	{	8,	"gc",	ft_GCONTEXT,	NULL},
	{	12,	"x",	ft_INT16,	NULL},
	{	14,	"y",	ft_INT16,	NULL},
	{	16,	"string",	ft_STRING16,	NULL},
	EOP
};

static const struct parameter parameterCreateColormap[] = {
	{	1,	"alloc",	ft_ENUM8,	c_alloc},
	{	4,	"mid",	ft_COLORMAP,	NULL},
	{	8,	"window",	ft_WINDOW,	NULL},
	{	12,	"visual",	ft_VISUALID,	NULL},
	EOP
};

static const struct parameter parameterCOLORMAP[] = {
	{	4,	"cmap",	ft_COLORMAP,	NULL},
	EOP
};
#define parameterFreeColormap parameterCOLORMAP

static const struct parameter parameterCopyColormapAndFree[] = {
	{	4,	"mid",	ft_COLORMAP,	NULL},
	{	8,	"src-cmap",	ft_COLORMAP,	NULL},
	EOP
};

#define parameterInstallColormap parameterCOLORMAP
#define parameterUninstallColormap parameterCOLORMAP

#define parameterListInstalledColormaps parameterWINDOW

#define ft_LISTofCOLORMAP ft_LISTofCARD32,	NULL

static const struct parameter returnListInstalledColormaps[] = {
	{	8,	"#",		ft_COUNT16,	NULL},
	{	32,	"cmaps",	ft_LISTofCOLORMAP},
	EOP
};

static const struct parameter parameterAllocColor[] = {
	{	4,	"cmap",	ft_COLORMAP,	NULL},
	{	8,	"red",	ft_CARD16,	NULL},
	{	10,	"green",ft_CARD16,	NULL},
	{	12,	"blue",	ft_CARD16,	NULL},
	EOP
};

static const struct parameter returnAllocColor[] = {
	{	8,	"red",	ft_CARD16,	NULL},
	{	10,	"green",ft_CARD16,	NULL},
	{	12,	"blue",	ft_CARD16,	NULL},
	{	16,	"pixel",ft_CARD32,	NULL},
	EOP
};

static const struct parameter parameterAllocNamedColor[] = {
	{	4,	"cmap",	ft_COLORMAP,	NULL},
	{	8,	"#",	ft_COUNT16,	NULL},
	{	12,	"name",	ft_STRING8,	NULL},
	EOP
};

static const struct parameter returnAllocNamedColor[] = {
	{	8,	"pixel",	ft_CARD32,	NULL},
	{	12,	"exact-red",	ft_CARD16,	NULL},
	{	14,	"exact-green",	ft_CARD16,	NULL},
	{	16,	"exact-blue",	ft_CARD16,	NULL},
	{	18,	"visual-red",	ft_CARD16,	NULL},
	{	20,	"visual-green",	ft_CARD16,	NULL},
	{	22,	"visual-blue",	ft_CARD16,	NULL},
	EOP
};

static const struct parameter parameterAllocColorCells[] = {
	{	1,	"contiguous",	ft_BOOL},
	{	4,	"cmap",		ft_COLORMAP,	NULL},
	{	8,	"colors",	ft_CARD16,	NULL},
	{	10,	"planes",	ft_CARD16,	NULL},
	EOP
};

static const struct parameter returnAllocColorCells[] = {
	{	4,	"reply length",	ft_COUNT32,	NULL},
/*
	{	8,	"number of CARD32s in pixels",	ft_COUNT16,	NULL},
	{	10,	"number of CARD32s in masks",	ft_COUNT16,	NULL},
	{	32,	"pixels",	ft_LISTofCARD32,	NULL},
4n
	{	32+,	"masks",	ft_LISTofCARD32,	NULL},
4m
*/
	{	32,	"pixels and masks",	ft_LISTofCARD32,	NULL},
	EOP
};

static const struct parameter parameterAllocColorPlanes[] = {
	{	1,	"contiguous",	ft_BOOL},
	{	4,	"cmap",		ft_COLORMAP,	NULL},
	{	8,	"colors",	ft_CARD16,	NULL},
	{	10,	"reds",		ft_CARD16,	NULL},
	{	12,	"greens",	ft_CARD16,	NULL},
	{	14,	"blues",	ft_CARD16,	NULL},
	EOP
};

static const struct parameter returnAllocColorPlanes[] = {
	{	8,	"#",		ft_COUNT16,	NULL},
	{	12,	"red-mask",	ft_CARD32,	NULL},
	{	16,	"green-mask",	ft_CARD32,	NULL},
	{	20,	"blue-mask",	ft_CARD32,	NULL},
	{	32,	"pixels",	ft_LISTofCARD32,NULL},
	EOP
};

static const struct parameter parameterFreeColors[] = {
	{	4,	"cmap",	ft_COLORMAP,	NULL},
	{	8,	"plane-mask",	ft_CARD32,	NULL},
	{	12,	"pixels",	ft_LISTofCARD32,	NULL},
	EOP
};


static const struct parameter listCOLORITEM[] = {
	LC(12),
	{	0,	"pixel",	ft_CARD32,	NULL},
	{	4,	"red",		ft_CARD16,	NULL},
	{	6,	"green",	ft_CARD16,	NULL},
	{	8,	"blue",		ft_CARD16,	NULL},
	{	10,	"do ",		ft_BITMASK8,	c_doredgreenblue},
	EOP
};

#define ft_LISTofCOLORITEM ft_LISTofStruct,	(void*)listCOLORITEM

static const struct parameter parameterStoreColors[] = {
	{	4,	"cmap",	ft_COLORMAP,	NULL},
	{	8,	"items",	ft_LISTofCOLORITEM},
	EOP
};

static const struct parameter parameterStoreNamedColor[] = {
	{	1,	"do",		ft_ENUM8,	c_doredgreenblue},
	{	4,	"cmap",		ft_COLORMAP,	NULL},
	{	8,	"pixel",	ft_CARD32,	NULL},
	{	12,	"#",		ft_COUNT16,	NULL},
	{	16,	"name",		ft_STRING8,	NULL},
	EOP
};

static const struct parameter parameterQueryColors[] = {
	{	4,	"cmap",		ft_COLORMAP,	NULL},
	{	12,	"pixels",	ft_LISTofCARD32,	NULL},
	EOP
};

static const struct parameter listRGB[] = {
	LC(8),
	{	0,	"r",	ft_CARD16,	NULL},
	{	2,	"g",	ft_CARD16,	NULL},
	{	4,	"b",	ft_CARD16,	NULL},
	EOP
};
#define ft_LISTofRGB	ft_LISTofStruct,	(void*)listRGB


static const struct parameter returnQueryColors[] = {
	{	8,	"#",		ft_COUNT16,	NULL},
	{	32,	"colors",	ft_LISTofRGB},
	EOP
};

static const struct parameter parameterLookupColor[] = {
	{	4,	"cmap",	ft_COLORMAP,	NULL},
	{	8,	"#",	ft_COUNT16,	NULL},
	{	12,	"name",	ft_STRING8,	NULL},
	EOP
};

static const struct parameter returnLookupColor[] = {
	{	8,	"exact-red",	ft_CARD16,	NULL},
	{	10,	"exact-green",	ft_CARD16,	NULL},
	{	12,	"exact-blue",	ft_CARD16,	NULL},
	{	14,	"visual-red",	ft_CARD16,	NULL},
	{	16,	"visual-green",	ft_CARD16,	NULL},
	{	18,	"visual-blue",	ft_CARD16,	NULL},
	EOP
};

static const struct parameter parameterCreateCursor[] = {
	{	4,	"cid",		ft_CURSOR,	NULL},
	{	8,	"source",	ft_PIXMAP,	NULL},
	{	12,	"mask",		ft_PIXMAP,	c_none},
	{	16,	"fore-red",	ft_CARD16,	NULL},
	{	18,	"fore-green",	ft_CARD16,	NULL},
	{	20,	"fore-blue",	ft_CARD16,	NULL},
	{	22,	"back-red",	ft_CARD16,	NULL},
	{	24,	"back-green",	ft_CARD16,	NULL},
	{	26,	"back-blue",	ft_CARD16,	NULL},
	{	28,	"x",		ft_UINT16,	NULL},
	{	30,	"y",		ft_UINT16,	NULL},
	EOP
};

static const struct parameter parameterCreateGlyphCursor[] = {
	{	4,	"cid",	ft_CURSOR,	NULL},
	{	8,	"source-font",	ft_FONT,	NULL},
	{	12,	"mask-font",	ft_FONT,	c_none},
	{	16,	"source-char",	ft_CARD16,	NULL},
	{	18,	"mask-char",	ft_CARD16,	NULL},
	{	20,	"fore-red",	ft_CARD16,	NULL},
	{	22,	"fore-green",	ft_CARD16,	NULL},
	{	24,	"fore-blue",	ft_CARD16,	NULL},
	{	26,	"back-red",	ft_CARD16,	NULL},
	{	28,	"back-green",	ft_CARD16,	NULL},
	{	30,	"back-blue",	ft_CARD16,	NULL},
	EOP
};

#define parameterFreeCursor parameterCURSOR
static const struct parameter parameterCURSOR[] = {
	{	4,	"cursor",	ft_CURSOR,	NULL},
	EOP
};

static const struct parameter parameterRecolorCursor[] = {
	{	4,	"cursor",	ft_CURSOR,	NULL},
	{	8,	"fore-red",	ft_CARD16,	NULL},
	{	10,	"fore-green",	ft_CARD16,	NULL},
	{	12,	"fore-blue",	ft_CARD16,	NULL},
	{	14,	"back-red",	ft_CARD16,	NULL},
	{	16,	"back-green",	ft_CARD16,	NULL},
	{	18,	"back-blue",	ft_CARD16,	NULL},
	EOP
};

static const struct parameter parameterQueryBestSize[] = {
	{	1,	"class",	ft_ENUM8,	c_sizeclass},
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	{	8,	"width",	ft_UINT16,	NULL},
	{	10,	"height",	ft_UINT16,	NULL},
	EOP
};

static const struct parameter returnQueryBestSize[] = {
	{	8,	"width",	ft_UINT16,	NULL},
	{	10,	"height",	ft_UINT16,	NULL},
	EOP
};



static const struct parameter parameterQueryExtension[] = {
	{	4,	"#",	ft_COUNT16,	NULL},
	{	8,	"name",	ft_STRING8,	NULL},
	EOP
};

static const struct parameter returnQueryExtension[] = {
	{	8,	"present",	ft_BOOL},
	{	9,	"major-opcode",	ft_UINT8,	NULL},
	{	10,	"first-event",	ft_UINT8,	NULL},
	{	11,	"first-error",	ft_UINT8,	NULL},
	EOP
};


#define parameterListExtensions parameterNone

static const struct parameter returnListExtensions[] = {
	{	1,	"number of STRs in names",	ft_CARD8,	NULL},
	{	32,	"names",			ft_LISTofSTRING8},
	EOP
};

#define ft_LISTofKEYSYM ft_LISTofCARD32

static const struct parameter parameterChangeKeyboardMapping[] = {
	{	2,	"keycode-count",	ft_CARD8,	NULL},
	{	4,	"first-keycode",	ft_KEYCODE,	NULL},
	{	5,	"keysyms-per-keycode",	ft_CARD8,	NULL},
	/* it's CARD8(2)*CARD8(5) many, just list until end of package: */
	{	8,	"keysyms",	ft_LISTofKEYSYM,	NULL},
	EOP
};


static const struct parameter parameterGetKeyboardMapping[] = {
	{	4,	"first-keycode",ft_KEYCODE,	NULL},
	{	5,	"count",	ft_CARD8,	NULL},
	EOP
};


static const struct parameter returnGetKeyboardMapping[] = {
	{	1,	"keysyms-per-keycode",	ft_CARD8,	NULL},
	{	32,	"keysyms",	ft_LISTofKEYSYM,	NULL},
	EOP
};



static const struct parameter parameterChangeKeyboardControl[] = {
	{	4,	"value-mask",	ft_BITMASK16,	c_keyboardvaluemask},
/*
  4n LISTofVALUE	 value-list


  VALUEs
  1  INT8		 key-click-percent
  1  INT8		 bell-percent
  2  INT16		 bell-pitch
  2  INT16		 bell-duration
  1  CARD8		 led
  1			 led-mode
     0	       Off
     1	       On
  1  KEYCODE		 key
  1			 auto-repeat-mode
     0	       Off
     1	       On
     2	       Default
*/
	EOP
};

#define parameterGetKeyboardControl parameterNone

static const struct parameter returnGetKeyboardControl[] = {
	{	1,	"global-auto-repeat",	ft_BOOL},
	{	8,	"led-mask",		ft_CARD32,	NULL},
	{	12,	"key-click-percent",	ft_CARD8,	NULL},
	{	13,	"bell-percent",		ft_CARD8,	NULL},
	{	14,	"bell-pitch",		ft_CARD16,	NULL},
	{	16,	"bell-duration",	ft_CARD16,	NULL},
	{	20,	"auto-repeats",		ft_LISTofCARD8,	NULL},
	EOP
};

static const struct parameter parameterBell[] = {
	{	1,	"percent",	ft_INT8,	NULL},
	EOP
};

static const struct parameter parameterChangePointerControl[] = {
	{	4,	"acceleration-numerator",	ft_INT16,	NULL},
	{	6,	"acceleration-denominator",	ft_INT16,	NULL},
	{	8,	"threshold",			ft_INT16,	NULL},
	{	10,	"do-acceleration",		ft_BOOL},
	{	11,	"do-threshold",			ft_BOOL},
	EOP
};

#define parameterGetPointerControl parameterNone

static const struct parameter returnGetPointerControl[] = {
	{	8,	"acceleration-numerator",	ft_CARD16,	NULL},
	{	10,	"acceleration-denominator",	ft_CARD16,	NULL},
	{	12,	"threshold",			ft_CARD16,	NULL},
	EOP
};

static const struct parameter parameterSetScreenSaver[] = {
	{	4,	"timeout",		ft_INT16,	NULL},
	{	6,	"interval",		ft_INT16,	NULL},
	{	8,	"prefer-blanking",	ft_ENUM8,	c_nyd},
	{	9,	"allow-exposures",	ft_ENUM8,	c_nyd},
	EOP
};


#define parameterGetScreenSaver parameterNone

static const struct parameter returnGetScreenSaver[] = {
	{	8,	"timeout",		ft_CARD16,	NULL},
	{	10,	"interval",		ft_CARD16,	NULL},
	{	12,	"prefer-blanking",	ft_ENUM8,	c_nyd},
	{	13,	"allow-exposures",	ft_ENUM8,	c_nyd},
	EOP
};

static const struct parameter parameterChangeHosts[] = {
	{	1,	"mode",		ft_ENUM8,	c_insertdelete},
	{	4,	"family",	ft_ENUM8,	c_family},
	{	6,	"#",		ft_COUNT16,	NULL},
	{	8,	"address",	ft_LISTofCARD8,	NULL},
	EOP
};

#define parameterListHosts parameterNone

#define ft_LISTofHOST ft_LISTofCARD32

static const struct parameter returnListHosts[] = {
	{	1,	"mode",	ft_ENUM8,	c_disabledenabled},
	{	8,	"#",	ft_COUNT16,	NULL},
	{	32,	"hosts",	ft_LISTofHOST,	NULL},
	EOP
};

static const struct parameter parameterSetAccessControl[] = {
	{	1,	"mode",	ft_ENUM8,c_disableenable},
	EOP
};

static const struct parameter parameterSetCloseDownMode[] = {
	{	1,	"mode",	ft_ENUM8,	c_closemode},
	EOP
};

static const struct parameter parameterKillClient[] = {
	{	4,	"resource",	ft_CARD32,	c_alltemporary},
	EOP
};

static const struct parameter parameterRotateProperties[] = {
	{	4,	"window",	ft_WINDOW,	NULL},
	{	8,	"#",		ft_COUNT16,	NULL},
	{	10,	"delta",	ft_INT16,	NULL},
	{	12,	"properties",	ft_LISTofATOM,	NULL},
	EOP
};

static const struct parameter parameterForceScreenSaver[] = {
	{	1,	"mode",	ft_ENUM8	,c_resetactivate},
     	EOP
};


static const struct parameter parameterSetPointerMapping[] = {
	{	1,	"#",	ft_COUNT8,	NULL},
	{	4,	"map",	ft_LISTofCARD8,	NULL},
	EOP
};

static const struct parameter returnSuccessBusyFailed[] = {
	{	1,	"status",	ft_ENUM8,	c_successbusyfailed},
	EOP
};
#define returnSetPointerMapping returnSuccessBusyFailed

#define parameterGetPointerMapping parameterNone

static const struct parameter returnGetPointerMapping[] = {
	{	1,	"length of map",ft_COUNT8,	NULL},
	{	32,	"map",		ft_LISTofCARD8,	NULL},
	EOP
};

#define ft_LISTofKEYCODE ft_LISTofCARD8

static const struct parameter parameterSetModifierMapping[] = {
	{	1,	"keycodes-per-modifier",	ft_CARD8,	NULL},
	{	4,	"keycodes",		ft_LISTofKEYCODE,	NULL},
	EOP
};

#define returnSetModifierMapping returnSuccessBusyFailed

#define parameterGetModifierMapping parameterNone

static const struct parameter returnGetModifierMapping[] = {
	{	1,	"keycodes-per-modifier",ft_CARD8,		NULL},
	{	32,	"keycodes",		ft_LISTofKEYCODE,	NULL},
	EOP
};

#undef EOP
#undef EOV
#define ra(a) { #a , parameter ## a , NULL,NULL,NULL}
#define ra2(a) { #a , parameter ## a , NULL, request ## a ,NULL}
#define rb(a) { #a , parameter ## a , return ## a ,NULL,NULL}
#define rb2(a) { #a , parameter ## a , return ## a ,NULL,reply ## a}
#define rb3(a) { #a , parameter ## a , return ## a ,request ## a,reply ## a}
#define rw(a) { #a , parameterWINDOW, NULL,NULL,NULL}
#define ro(a) { #a , parameterNone, NULL,NULL,NULL}
static const struct request requests[] = {
	{"unknown", parameterEmpty, NULL, NULL, NULL},
	ra(CreateWindow),
	ra(ChangeWindowAttributes),
	rb(GetWindowAttributes),
	rw(DestroyWindow),
	rw(DestroySubwindows),
	ra(ChangeSaveSet),
	ra(ReparentWindow),
	rw(MapWindow), /*8*/
	rw(MapSubwindows),
	rw(UnmapWindow),
	rw(UnmapSubwindows),
	ra(ConfigureWindow),
	ra(CirculateWindow),
	rb(GetGeometry),
	rb(QueryTree),
	rb3(InternAtom),
	rb(GetAtomName),
	ra(ChangeProperty),
	ra(DeleteProperty),
	rb(GetProperty), /*20*/
	rb(ListProperties),
	ra(SetSelectionOwner),
	rb(GetSelectionOwner),
	ra(ConvertSelection),
	ra(SendEvent),
	rb(GrabPointer),
	ra(UngrabPointer),
	ra(GrabButton),
	ra(UngrabButton),
	ra(ChangeActivePointerGrab), /*30*/
	rb(GrabKeyboard),
	ra(UngrabKeyboard),
	ra(GrabKey),
	ra(UngrabKey),
	ra(AllowEvents),
	ro(GrabServer),
	ro(UngrabServer),
	rb(QueryPointer),
	rb(GetMotionEvents),
	rb(TranslateCoordinates), /*40*/
	ra(WarpPointer),
	ra(SetInputFocus),
	rb(GetInputFocus),
	rb(QueryKeymap),
	ra(OpenFont),
	ra(CloseFont),
	rb(QueryFont),
	rb(QueryTextExtents),
	rb(ListFonts),
	rb2(ListFontsWithInfo), /*50*/
	ra(SetFontPath),
	rb(GetFontPath),
	ra(CreatePixmap),
	ra(FreePixmap),
	ra(CreateGC),
	ra(ChangeGC),
	ra(CopyGC),
	ra(SetDashes),
	ra(SetClipRectangles),
	ra(FreeGC), /*60*/
	ra(ClearArea),
	ra(CopyArea),
	ra(CopyPlane),
	ra(PolyPoint),
	ra(PolyLine),
	ra(PolySegment),
	ra(PolyRectangle),
	ra(PolyArc),
	ra(FillPoly),
	ra(PolyFillRectangle),
	ra(PolyFillArc),
	ra(PutImage),
	rb(GetImage),
	ra(PolyText8),
	ra(PolyText16),
	ra(ImageText8),
	ra(ImageText16),
	ra(CreateColormap),
	ra(FreeColormap),
	ra(CopyColormapAndFree),
	ra(InstallColormap),
	ra(UninstallColormap),
	rb(ListInstalledColormaps),
	rb(AllocColor),
	rb(AllocNamedColor),
	rb(AllocColorCells),
	rb(AllocColorPlanes),
	ra(FreeColors),
	ra(StoreColors),
	ra(StoreNamedColor),
	rb(QueryColors),
	rb(LookupColor),
	ra(CreateCursor),
	ra(CreateGlyphCursor),
	ra(FreeCursor),
	ra(RecolorCursor),
	rb(QueryBestSize),
	rb3(QueryExtension),
	rb(ListExtensions),
	ra(ChangeKeyboardMapping), /*100*/
	rb(GetKeyboardMapping),
	ra(ChangeKeyboardControl),
	rb(GetKeyboardControl),
	ra(Bell),
	ra(ChangePointerControl),
	rb(GetPointerControl),
	ra(SetScreenSaver),
	rb(GetScreenSaver),
	ra(ChangeHosts),
	rb(ListHosts),
	ra(SetAccessControl),
	ra(SetCloseDownMode),
	ra(KillClient),
	ra(RotateProperties),
	ra(ForceScreenSaver), /*115*/
	rb(SetPointerMapping),
	rb(GetPointerMapping),
	rb(SetModifierMapping),
	rb(GetModifierMapping),
};

#undef ra
#undef rb
