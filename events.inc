/*  This file is part of "xtrace"
 *  Copyright (C) 2005 Bernhard R. Link
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

#define eparamInnerCommons \
	{	4,	"time",		ft_TIMESTAMP,	NULL},	\
	{	8,	"root",		ft_WINDOW,	NULL},	\
	{	12,	"event",	ft_WINDOW,	NULL},	\
	{	16,	"child",	ft_WINDOW,	c_none},\
	{	20,	"root-x",	ft_INT16,	NULL},	\
	{	22,	"root-y",	ft_INT16,	NULL},	\
	{	24,	"event-x",	ft_INT16,	NULL},	\
	{	26,	"event-y",	ft_INT16,	NULL},	\
	{	28,	"state",	ft_SETofKEYBUTMASK}

#define eparamCommons eparamInnerCommons, \
	{	30,	"same-screen",	ft_BOOL},		\
	EOP

#define EOP {	0,	NULL,		0,		NULL}
#define EOC {	0,	NULL}

static const struct parameter eparamKey[] = {
	{	1,	"keycode",	ft_KEYCODE,	NULL},
	eparamCommons
};

#define eparamKeyPress eparamKey
#define eparamKeyRelease eparamKey

static const struct parameter eparamButton[] = {
	{	1,	"button",	ft_BUTTON},
	eparamCommons
};

#define eparamButtonPress eparamButton
#define eparamButtonRelease eparamButton

static const struct constant c_normalhint[] = {
	{0,	"Normal"},
	{1,	"Hint"},
	EOC
};

static const struct parameter eparamMotionNotify[] = {
	{	1,	"detail",	ft_ENUM8,	c_normalhint},
	eparamCommons
};

static const struct constant c_enterdetail[] = {
	{0,	"Ancestor"},
	{1,	"Virtual"},
	{2,	"Inferior"},
	{3,	"Nonlinear"},
	{4,	"NonlinearVirtual"},
	{5,	"Pointer"},
	{6,	"PointerRoot"},
	{7,	"None"},
	EOC
};
static const struct constant c_grabmode[] = {
	{0,	"Normal"},
	{1,	"Grab"},
	{2,	"Ungrab"},
	{3,	"WhileGrabbed"},
	EOC
};
static const struct constant c_focusscreen[] = {
	{0x01,	"focus"},
	{0x02,	"same-screen"},
	{0xFC,	"unused"},
	EOC
};

static const struct parameter eparamEnterNotify[] = {
	{	1,	"detail",	ft_ENUM8,	c_enterdetail},
	{	30,	"mode",		ft_ENUM8,	c_grabmode},
	{	31,	"flags",	ft_BITMASK8,	c_focusscreen},
	eparamInnerCommons,
	EOP
};
#define eparamLeaveNotify eparamEnterNotify

static const struct parameter eparamFocusIn[] = {
	{	1,	"detail",	ft_ENUM8,	c_enterdetail},
	{	4,	"event",	ft_WINDOW,	NULL},
	{	8,	"mode",		ft_ENUM8,	c_grabmode},
	EOP
};
#define eparamFocusOut eparamFocusIn

static const struct parameter eparamKeymapNotify[] = {
	{	1,	"keys(0-7 omitted)",	ft_LISTofCARD8, NULL},
	EOP
};

static const struct parameter eparamExpose[] = {
	{	4,	"window",	ft_WINDOW,	NULL},
	{	8,	"x",		ft_CARD16,	NULL},
	{	10,	"y",		ft_CARD16,	NULL},
	{	12,	"width",	ft_UINT16,	NULL},
	{	14,	"height",	ft_UINT16,	NULL},
	{	16,	"count",	ft_CARD16,	NULL},
	EOP
};

static const struct parameter eparamGraphicsExposure[] = {
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	{	8,	"x",		ft_CARD16,	NULL},
	{	10,	"y",		ft_CARD16,	NULL},
	{	12,	"width",	ft_UINT16,	NULL},
	{	13,	"height",	ft_UINT16,	NULL},
	{	14,	"minor-opcode",	ft_CARD16,	NULL},
	{	18,	"count",	ft_CARD16,	NULL},
	{	20,	"major-opcode",	ft_CARD8,	NULL},
	EOP
};

static const struct parameter eparamNoExposure[] = {
	{	4,	"drawable",	ft_DRAWABLE,	NULL},
	{	8,	"minor-opcode",	ft_CARD16,	NULL},
	{	10,	"major-opcode",	ft_CARD8,	NULL},
	EOP
};

static const struct constant c_obscure[] = {
	{0,	"Unobscured"},
	{1,	"PartiallyObscured"},
	{2,	"FullyObscured"},
	EOC
};

static const struct parameter eparamVisibilityNotify[] = {
	{	4,	"window",	ft_WINDOW,	NULL},
	{	8,	"state",	ft_ENUM8,	c_obscure},
	EOP
};

static const struct parameter eparamCreateNotify[] = {
	{	4,	"parent",	ft_WINDOW,	NULL},
	{	8,	"window",	ft_WINDOW,	NULL},
	{	12,	"x",	ft_INT16,	NULL},
	{	14,	"y",	ft_INT16,	NULL},
	{	16,	"width",	ft_UINT16,	NULL},
	{	18,	"height",	ft_UINT16,	NULL},
	{	20,	"border-width",	ft_UINT16,	NULL},
	{	22,	"override-redirect",	ft_BOOL},
	EOP
};

static const struct parameter eparamDestroyNotify[] = {
	{	4,	"event",	ft_WINDOW,	NULL},
	{	8,	"window",	ft_WINDOW,	NULL},
	EOP
};

static const struct parameter eparamUnmapNotify[] = {
	{	4,	"event",	ft_WINDOW,	NULL},
	{	8,	"window",	ft_WINDOW,	NULL},
	{	12,	"from-configure",	ft_BOOL},
	EOP
};

static const struct parameter eparamMapNotify[] = {
	{	4,	"event",	ft_WINDOW,	NULL},
	{	8,	"window",	ft_WINDOW,	NULL},
	{	12,	"override-redirect",	ft_BOOL},
	EOP
};

static const struct parameter eparamMapRequest[] = {
	{	4,	"parent",	ft_WINDOW,	NULL},
	{	8,	"window",	ft_WINDOW,	NULL},
	EOP
};

static const struct parameter eparamReparentNotify[] = {
	{	4,	"event",	ft_WINDOW,	NULL},
	{	8,	"window",	ft_WINDOW,	NULL},
	{	12,	"parent",	ft_WINDOW,	NULL},
	{	16,	"x",		ft_INT16,	NULL},
	{	18,	"y",		ft_INT16,	NULL},
	{	20,	"override-redirect",	ft_BOOL},
	EOP
};

static const struct parameter eparamConfigureNotify[] = {
	{	4,	"event",		ft_WINDOW,	NULL},
	{	8,	"window",		ft_WINDOW,	NULL},
	{	12,	"above-sibling",	ft_WINDOW,	c_none},
	{	16,	"x",			ft_INT16,	NULL},
	{	18,	"y",			ft_INT16,	NULL},
	{	20,	"width",		ft_UINT16,	NULL},
	{	22,	"height",		ft_UINT16,	NULL},
	{	24,	"border-width",		ft_UINT16,	NULL},
	{	26,	"override-redirect",	ft_BOOL},
	EOP
};

const struct constant c_configure_mask[] = {
	{0x0001, "x"},
	{0x0002, "y"},
	{0x0004, "width"},
	{0x0008, "height"},
	{0x0010, "border-width"},
	{0x0020, "sibling"},
	{0x0040, "stack-mode"},
	EOC
};

static const struct parameter eparamConfigureRequest[] = {
	{	4,	"parent",	ft_WINDOW,	NULL},
	{	8,	"window",	ft_WINDOW,	NULL},
	{	26,	"value-mask",	ft_BITMASK16,	c_configure_mask},
	{	1,	"stack-mode",	ft_ENUM8,	c_stack_mode},
	{	12,	"sibling",	ft_WINDOW,	c_none},
	{	16,	"x",	ft_INT16,	NULL},
	{	18,	"y",	ft_INT16,	NULL},
	{	20,	"width",	ft_UINT16,	NULL},
	{	22,	"height",	ft_UINT16,	NULL},
	{	24,	"border-width",	ft_UINT16,	NULL},
	EOP
};

static const struct parameter eparamGravityNotify[] = {
	{	4,	"event",	ft_WINDOW,	NULL},
	{	8,	"window",	ft_WINDOW,	NULL},
	{	12,	"x",	ft_INT16,	NULL},
	{	14,	"y",	ft_INT16,	NULL},
	EOP
};

static const struct parameter eparamResizeRequest[] = {
	{	4,	"window",	ft_WINDOW,	NULL},
	{	8,	"width",	ft_UINT16,	NULL},
	{	10,	"height",	ft_UINT16,	NULL},
	EOP
};

static const struct constant c_topbottom[] = {
	{0,	"Top"},
	{1,	"Bottom"},
	EOC
};

static const struct parameter eparamCirculateNotify[] = {
	{	4,	"event",	ft_WINDOW,	NULL},
	{	8,	"window",	ft_WINDOW,	NULL},
	{	16,	"place",	ft_ENUM8,	c_topbottom},
	EOP
};
#define eparamCirculateRequest eparamCirculateNotify

static const struct constant c_newdeleted[] = {
	{0,	"NewValue"},
	{1,	"Deleted"},
	EOC
};

static const struct parameter eparamPropertyNotify[] = {
	{	4,	"window",	ft_WINDOW,	NULL},
	{	8,	"atom",	ft_ATOM,	NULL},
	{	12,	"time",	ft_TIMESTAMP,	NULL},
	{	16,	"state",	ft_ENUM8,	c_newdeleted},
	EOP
};

static const struct parameter eparamSelectionClear[] = {
	{	4,	"time",	ft_TIMESTAMP,	NULL},
	{	8,	"owner",	ft_WINDOW,	NULL},
	{	12,	"selection",	ft_ATOM,	NULL},
	EOP
};


static const struct parameter eparamSelectionRequest[] = {
	{	4,	"time",		ft_TIMESTAMP,	c_curtime},
	{	8,	"owner",	ft_WINDOW,	NULL},
	{	12,	"requestor",	ft_WINDOW,	NULL},
	{	16,	"selection",	ft_ATOM,	NULL},
	{	20,	"target",	ft_ATOM,	NULL},
	{	24,	"property",	ft_ATOM,	c_none},
	EOP
};

#define eparamSelectionNotify eparamSelectionRequest


static const struct constant c_uninstalledinstalled[] = {
	{0,	"Uninstalled"},
	{1,	"Installed"},
	EOC
};

static const struct parameter eparamColormapNotify[] = {
	{	4,	"window",	ft_WINDOW,	NULL},
	{	8,	"colormap",	ft_COLORMAP,	c_none},
	{	12,	"new",		ft_BOOL},
	{	13,	"state",	ft_ENUM8,	NULL},
	EOP
};

static const struct parameter eparamClientMessage[] = {
	{	1,	"format",	ft_CARD8,	NULL},
	{	4,	"window",	ft_WINDOW,	NULL},
	{	8,	"type",		ft_ATOM,	NULL},
	{	12,	"data",		ft_LISTofCARD8,	NULL},
	EOP
};

static const struct constant c_modkeypoi[] = {
	{0,	"Modifier"},
	{1,	"Keyboard"},
	{2,	"Pointer"},
	EOC
};

static const struct parameter eparamMappingNotify[] = {
	{	4,	"request",	ft_ENUM8,	c_modkeypoi},
	{	5,	"first-keycode",ft_KEYCODE,	NULL},
	{	6,	"count",	ft_CARD8,	NULL},
	EOP
};

#define ev(name) { #name , eparam ## name }
static const struct event events[] = {
	{"unknown(0)", NULL},
	{"unknown(1)", NULL},
	ev(KeyPress),
	ev(KeyRelease),
	ev(ButtonPress),
	ev(ButtonRelease),
	ev(MotionNotify),
	ev(EnterNotify),
	ev(LeaveNotify),
	ev(FocusIn),
	ev(FocusOut),
	ev(KeymapNotify),
	ev(Expose),
	ev(GraphicsExposure),
	ev(NoExposure),
	ev(VisibilityNotify),
	ev(CreateNotify),
	ev(DestroyNotify),
	ev(UnmapNotify),
	ev(MapNotify),
	ev(MapRequest),
	ev(ReparentNotify),
	ev(ConfigureNotify),
	ev(ConfigureRequest),
	ev(GravityNotify),
	ev(ResizeRequest),
	ev(CirculateNotify),
	ev(CirculateRequest),
	ev(PropertyNotify),
	ev(SelectionClear),
	ev(SelectionRequest),
	ev(SelectionNotify),
	ev(ColormapNotify),
	ev(ClientMessage),
	ev(MappingNotify),
};
#undef ev
#undef EOC
#undef EOP
