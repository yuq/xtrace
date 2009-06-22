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
/* This file is based on the render.h and renderproto.h files
   from the Xorg server:
 * Copyright © 2000 SuSE, Inc.
 *
 * Permission to use, copy, modify, distribute, and sell this software and its
 * documentation for any purpose is hereby granted without fee, provided that
 * the above copyright notice appear in all copies and that both that
 * copyright notice and this permission notice appear in supporting
 * documentation, and that the name of SuSE not be used in advertising or
 * publicity pertaining to distribution of the software without specific,
 * written prior permission.  SuSE makes no representations about the
 * suitability of this software for any purpose.  It is provided "as is"
 * without express or implied warranty.
 *
 * SuSE DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING ALL
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL SuSE
 * BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 * Author:  Keith Packard, SuSE, Inc.
 */


#define EOV {0, NULL, -1, NULL}
#define EOC {-1, NULL}

static const struct constant c_picttype[] = {
	{0,	"Indexed"},
	{1,	"Direct"},
	EOC
};
#define ft_PictType ft_ENUM8,c_picttype

static const struct constant c_pictop[] = {
	{0,	"Minimum/Clear"},
	{1,	"Src"},
	{2,	"Dst"},
	{3,	"Over"},
	{4,	"OverReverse"},
	{5,	"In"},
	{6,	"InReverse"},
	{7,	"Out"},
	{8,	"OutReverse"},
	{9,	"Atop"},
	{10,	"AtopReverse"},
	{11,	"Xor"},
	{12,	"Add"},
	{13,	"Saturate/Maximum"},
	{0x10,	"DisjointMinimum"},
	{0x10,	"DisjointClear"},
	{0x11,	"DisjointSrc"},
	{0x12,	"DisjointDst"},
	{0x13,	"DisjointOver"},
	{0x14,	"DisjointOverReverse"},
	{0x15,	"DisjointIn"},
	{0x16,	"DisjointInReverse"},
	{0x17,	"DisjointOut"},
	{0x18,	"DisjointOutReverse"},
	{0x19,	"DisjointAtop"},
	{0x1a,	"DisjointAtopReverse"},
	{0x1b,	"DisjointXor"},
	{0x1b,	"DisjointMaximum"},
	{0x20,	"ConjointMinimum"},
	{0x20,	"ConjointClear"},
	{0x21,	"ConjointSrc"},
	{0x22,	"ConjointDst"},
	{0x23,	"ConjointOver"},
	{0x24,	"ConjointOverReverse"},
	{0x25,	"ConjointIn"},
	{0x26,	"ConjointInReverse"},
	{0x27,	"ConjointOut"},
	{0x28,	"ConjointOutReverse"},
	{0x29,	"ConjointAtop"},
	{0x2a,	"ConjointAtopReverse"},
	{0x2b,	"ConjointXor"},
	{0x2b,	"ConjointMaximum"},
	EOC
};
#define ft_PictOp ft_ENUM8,c_pictop

static const struct constant c_polyedge[] = {
	{0,	"Sharp"},
	{1,	"Smooth"},
	EOC
};
#define ft_PolyEdge ft_ENUM8,c_polyedge

static const struct constant c_polymode[] = {
	{0,	"Precise"},
	{1,	"Imprecise"},
	EOC
};
#define ft_PolyMode ft_ENUM8,c_polymode

static const struct constant c_subpixel[] = {
	{0,	"Unknown"},
	{1,	"HorizontalRGB"},
	{2,	"HorizontalBGR"},
	{3,	"VerticalRGB"},
	{4,	"VerticalBGR"},
	{5,	"None"},
	EOC
};
#define ft_SUBPIXEL ft_ENUM8,c_subpixel
#undef EOC
#define EOP {0,NULL,0,NULL}
#define LC(len) {len,NULL,0,NULL}

#define Window CARD32
#define Drawable CARD32
#define Font CARD32
#define Pixmap CARD32
#define Cursor CARD32
#define GContext CARD32
#define ft_VisualID ft_CARD32
#define Time CARD32

#define ft_PICTURE	ft_CARD32
#define ft_PICTFORMAT	ft_CARD32
#define ft_Fixed	ft_FIXED
#define ft_GLYPHSET    	ft_CARD32

static const struct parameter listPictFormInfo[] = {
	LC(28),
	{	 0,	"id",		ft_PICTFORMAT,	NULL},
	{	 4,	"type",		ft_PictType},
	{	 5,	"depth",	ft_CARD8,	NULL},
	{	 8,	"red",		ft_CARD16,	NULL},
	{	10,	"redMask",	ft_CARD16,	NULL},
	{	12,	"green",	ft_CARD16,	NULL},
	{	14,	"greenMask",	ft_CARD16,	NULL},
	{	16,	"blue",		ft_CARD16,	NULL},
	{	18,	"blueMask",	ft_CARD16,	NULL},
	{	20,	"alpha",	ft_CARD16,	NULL},
	{	22,	"alphaMask",	ft_CARD16,	NULL},
	{	24,	"colormap",	ft_COLORMAP,	NULL},
	EOP
};
#define ft_LISTofPictFormInfo	ft_LISTofStruct, (void*)listPictFormInfo
static const struct parameter listPictFormats[] = {
	LC(28),
	{	 0,     "numFormats",	ft_GET,		NULL},
	{	 0,	"formats",	ft_LISTofPictFormInfo},
	EOP
};
#define ft_LISTofPictFormats	ft_LISTofVarStruct, (void*)listPictFormats

static const struct parameter listPictVisual[] = {
	LC(8),
	{	 0,	"visual",	ft_VisualID,	NULL},
	{	 4,	"format",	ft_PICTFORMAT,	NULL},
	EOP
};
#define ft_LISTofPictVisual	ft_LISTofStruct, (void*)listPictVisual

static const struct parameter listPictDepth[] = {
	LC(8), /* min length */
	{	 0,	"depth",	ft_CARD8,	NULL},
	{	 2,	"nPictVisuals",	ft_COUNT16,	NULL},
	{	 8,	"visuals",	ft_LISTofPictVisual},
	EOP
};
#define ft_LISTofPictDepth	ft_LISTofVarStruct,(void*)listPictDepth

static const struct parameter listPictScreen[] = {
	LC(8), /* min length */
	{	 0,	"nDepth",	ft_COUNT32,	NULL},
	{	 4,	"fallback",	ft_PICTFORMAT,	NULL},
	{	 8,	"depths",	ft_LISTofPictDepth},
	EOP
};
#define ft_LISTofPictScreen	ft_LISTofVarStruct,(void*)listPictScreen

#define parameterRenderQueryPictFormats parameterNone

static const struct parameter returnRenderQueryPictFormats[] = {
	{	 8,	"numFormats",	ft_PUSH32,	NULL},
	{	 12,	"numScreens",	ft_COUNT32,	NULL},
	{	 32,	"formats",	ft_LISTofPictFormats},
	{	 12,	"numScreens",	ft_COUNT32,	NULL},
	{	 OFS_LATER,	"screens",	ft_LISTofPictScreen},
	{	 24,	"numSubpixel",	ft_COUNT32,	NULL},
	{	 OFS_LATER,	"subpixels",	ft_LISTofCARD32, c_subpixel},
	EOP
};

static const struct parameter listIndexValue[] = {
	LC(12),
	{	 0,	"pixel",	ft_CARD32,	NULL},
	{	 4,	"red",		ft_CARD16,	NULL},
	{	 6,	"green",	ft_CARD16,	NULL},
	{	 8,	"blue",		ft_CARD16,	NULL},
	{	 10,	"alpha",	ft_CARD16,	NULL},
	EOP
};
#define ft_LISTofIndexValues ft_LISTofStruct, (void*)listIndexValue

static const struct parameter listPointFixed[] = {
	LC(8),
	{	 0,	"x",	ft_Fixed,	NULL},
	{	 4,	"y",	ft_Fixed,	NULL},
	EOP
};
#define ft_LISTofPOINTFIXED ft_LISTofStruct, (void*)listPointFixed

static const struct parameter listLineFixed[] = {
	LC(16),
	{	 0,	"x1",	ft_Fixed,	NULL},
	{	 4,	"y1",	ft_Fixed,	NULL},
	{	 8,	"x2",	ft_Fixed,	NULL},
	{	12,	"y2",	ft_Fixed,	NULL},
	EOP
};
#define ft_xLineFixed ft_Struct, (void*)listLineFixed

static const struct parameter listTriangle[] = {
	LC(24),
	{	 0,	"x1",	ft_Fixed,	NULL},
	{	 4,	"y1",	ft_Fixed,	NULL},
	{	 8,	"x2",	ft_Fixed,	NULL},
	{	12,	"y2",	ft_Fixed,	NULL},
	{	16,	"x3",	ft_Fixed,	NULL},
	{	20,	"y3",	ft_Fixed,	NULL},
	EOP
};
#define ft_LISTofTRIANGLE ft_LISTofStruct, (void*)listTriangle

static const struct parameter listTrapezoid[] = {
	LC(40),
	{	 0,	"top",		ft_Fixed,	NULL},
	{	 4,	"bottom",	ft_Fixed,	NULL},
	{	 8,	"left",		ft_xLineFixed},
	{	24,	"right",	ft_xLineFixed},
	EOP
};
#define ft_LISTofTRAPEZOID ft_LISTofStruct, (void*)listTrapezoid


/*
 * requests and replies
 */
static const struct parameter parameterRenderQueryVersion[] = {
	{	 4,	"majorVersion",	ft_UINT32,	NULL},
	{	 8,	"minorVersion",	ft_UINT32,	NULL},
	EOP
};
static const struct parameter returnRenderQueryVersion[] = {
	{	 8,	"majorVersion",	ft_UINT32,	NULL},
	{	 12,	"minorVersion",	ft_UINT32,	NULL},
	EOP
};

static const struct parameter parameterRenderQueryPictIndexValues[] = {
	{	 4,	"format",	ft_PICTFORMAT,	NULL},
	EOP
};
static const struct parameter returnRenderQueryPictIndexValues[] = {
	{	 8,	"numIndexValues",	ft_COUNT32,	NULL},
	{	32,	"IndexValues",		ft_LISTofIndexValues},
	EOP
};

static const struct value valuesRenderCP[] = {
	{(1 << 0),	"repeat",		ft_BOOL},
	{(1 << 1),	"alphaMap",		ft_PICTURE,	c_none},
	{(1 << 2),	"alpha-x-origin",		ft_INT16,	NULL},
	{(1 << 3),	"alpha-y-origin",		ft_INT16,	NULL},
	{(1 << 4),	"clip-x-origin",		ft_INT16,	NULL},
	{(1 << 5),	"clip-y-origin",		ft_INT16,	NULL},
	{(1 << 6),	"clip-mask",		ft_PIXMAP,	c_none},
	{(1 << 7),	"graphics-exposure",	ft_BOOL},
	{(1 << 8),	"subwindow-mode",	ft_SubwindowMode},
	{(1 << 9),	"poly-edge",		ft_PolyEdge},
	{(1 << 10),	"poly-mode",		ft_PolyMode},
	{(1 << 11),	"dither",		ft_ATOM,	c_none},
	{(1 << 12),	"component-alpha",	ft_BOOL},
	EOV
};

static const struct parameter parameterRenderCreatePicture[] = {
	{	 4,	"pid",		ft_PICTURE,	NULL},
	{	 8,	"drawable",	ft_DRAWABLE,	NULL},
	{	12,	"format",	ft_PICTFORMAT,	NULL},
	{	16,	"mask",		ft_STORE32,	NULL},
	{	20,	"values",	ft_LISTofVALUE, (void*)valuesRenderCP},
	EOP
};

static const struct parameter parameterRenderChangePicture[] = {
	{	 4,	"picture",	ft_PICTURE,	NULL},
	{	 8,	"mask",		ft_STORE32,	NULL},
	{	12,	"values",	ft_LISTofVALUE, (void*)valuesRenderCP},
	EOP
};

static const struct parameter parameterRenderSetPictureClipRectangles[] = {
	{	 4,	"picture",	ft_PICTURE,	NULL},
	{	 8,	"xOrigin",	ft_INT16,	NULL},
	{	10,	"yOrigin",	ft_INT16,	NULL},
	{	12,	"rectangles",	ft_LISTofRECTANGLE},
	EOP
};

static const struct parameter parameterRenderFreePicture[] = {
	{	 4,	"picture",	ft_PICTURE,	NULL},
	EOP
};

static const struct parameter parameterRenderComposite[] = {
	{	 4,	"op",	ft_PictOp},
	{	 8,	"src",	ft_PICTURE,	NULL},
	{	12,	"mask",	ft_PICTURE,	c_none},
	{	16,	"dst",	ft_PICTURE,	NULL},
	{	20,	"xSrc",	ft_INT16,	NULL},
	{	22,	"ySrc",	ft_INT16,	NULL},
	{	24,	"xMask",ft_INT16,	NULL},
	{	26,	"yMask",ft_INT16,	NULL},
	{	28,	"xDst",	ft_INT16,	NULL},
	{	30,	"yDst",	ft_INT16,	NULL},
	{	32,	"width",ft_UINT16,	NULL},
	{	34,	"height",ft_UINT16,	NULL},
	EOP
};

static const struct parameter parameterRenderScale[] = {
	{	 4,	"src",		ft_PICTURE,	NULL},
	{	 8,	"dst",		ft_PICTURE,	NULL},
	{	12,	"colorScale",	ft_UINT32,	NULL},
	{	16,	"alphaScale",	ft_UINT32,	NULL},
	{	20,	"xSrc",		ft_INT16,	NULL},
	{	22,	"ySrc",		ft_INT16,	NULL},
	{	24,	"xDst",		ft_INT16,	NULL},
	{	26,	"yDst",		ft_INT16,	NULL},
	{	28,	"width",	ft_UINT16,	NULL},
	{	30,	"height",	ft_UINT16,	NULL},
	EOP
};

static const struct parameter parameterRenderTrapezoids[] = {
	{	 4,	"op",		ft_PictOp},
	{	 8,	"src",		ft_PICTURE,	NULL},
	{	20,	"xSrc",		ft_INT16,	NULL},
	{	22,	"ySrc",		ft_INT16,	NULL},
	{	12,	"dst",		ft_PICTURE,	NULL},
	{	16,	"maskFormat",	ft_PICTFORMAT,	c_none},
	{	20,	"trapezoids",	ft_LISTofTRAPEZOID},
	EOP
};

static const struct parameter parameterRenderTriangles[] = {
	{	 4,	"op",		ft_PictOp},
	{	 8,	"src",		ft_PICTURE,	NULL},
	{	 20,	"xSrc",		ft_INT16,	NULL},
	{	 22,	"ySrc",		ft_INT16,	NULL},
	{	 12,	"dst",		ft_PICTURE,	NULL},
	{	 16,	"maskFormat",	ft_PICTFORMAT,	c_none},
	{	20,	"triangles",	ft_LISTofTRIANGLE},
	EOP
};

static const struct parameter parameterRenderTriStrip[] = {
	{	 4,	"op",		ft_PictOp},
	{	 8,	"src",		ft_PICTURE,	NULL},
	{	20,	"xSrc",		ft_INT16,	NULL},
	{	22,	"ySrc",		ft_INT16,	NULL},
	{	12,	"dst",		ft_PICTURE,	NULL},
	{	16,	"maskFormat",	ft_PICTFORMAT,	c_none},
	{	20,	"points",	ft_LISTofPOINTFIXED},
	EOP
};

static const struct parameter parameterRenderTriFan[] = {
	{	 4,	"op",		ft_PictOp},
	{	 8,	"src",		ft_PICTURE,	NULL},
	{	20,	"xSrc",		ft_INT16,	NULL},
	{	22,	"ySrc",		ft_INT16,	NULL},
	{	12,	"dst",		ft_PICTURE,	NULL},
	{	16,	"maskFormat",	ft_PICTFORMAT,	c_none},
	{	20,	"points",	ft_LISTofPOINTFIXED},
	EOP
};

static const struct parameter parameterRenderCreateGlyphSet[] = {
	{	 4,	"gsid",		ft_GLYPHSET,	NULL},
	{	 8,	"format",	ft_PICTFORMAT,	NULL},
	EOP
};

static const struct parameter parameterRenderReferenceGlyphSet[] = {
	{	 4,	"gsid",		ft_GLYPHSET,	NULL},
	{	 8,	"existing",	ft_GLYPHSET,	NULL},
	EOP
};

static const struct parameter parameterRenderFreeGlyphSet[] = {
	{	 4,	"glyphset",	ft_GLYPHSET,	NULL},
	EOP
};

static const struct parameter listGlyphInfo[] = {
	LC(12),
	{	 0,	"width",	ft_UINT16,	NULL},
	{	 2,	"height",	ft_UINT16,	NULL},
	{	 4,	"x",		ft_INT16,	NULL},
	{	 6,	"y",		ft_INT16,	NULL},
	{	 8,	"xOff",		ft_INT16,	NULL},
	{	10 ,	"yOff",		ft_INT16,	NULL},
	EOP
};
#define ft_LISTofGLYPHINFO ft_LISTofStruct, (void*)listGlyphInfo

static const struct parameter parameterRenderAddGlyphs[] = {
	{	 4,	"glyphset",	ft_GLYPHSET,	NULL},
	{	 8,	"nglyphs",	ft_COUNT32,	NULL},
	{	12,	"glyphids",	ft_LISTofCARD32, NULL},
	{	OFS_LATER, "glyphs",	ft_LISTofGLYPHINFO},
/*	{	OFS_LATER, "data",	ft_LISTofCARD8, NULL},*/
	EOP
};

static const struct parameter parameterRenderFreeGlyphs[] = {
	{	 4,	"glyphset",	ft_GLYPHSET,	NULL},
	{	 8,	"glyphs",	ft_LISTofCARD32,NULL},
	EOP
};

static const struct parameter listGlyphEltSet[] = {
	{	 8,	"glyphset",	ft_GLYPHSET,	NULL},
	{	12,	"",	ft_LASTMARKER,	NULL},
	EOP
};
static const struct parameter listGlyphElt8[] = {
	LC(8),
	{	 4,	"deltax",	ft_INT16,	NULL},
	{	 6,	"deltay",	ft_INT16,	NULL},
	{	 0,	"\377",		ft_IF8,	(void*)listGlyphEltSet},
	{	 0,	"len",		ft_COUNT8,	NULL},
	{	 8,	"glyphs",	ft_LISTofCARD8, NULL},
	ROUND,
	EOP
};
#define ft_LISTofGlyphElt8 ft_LISTofVarStruct, (void*)listGlyphElt8
static const struct parameter listGlyphElt16[] = {
	LC(8),
	{	 4,	"deltax",	ft_INT16,	NULL},
	{	 6,	"deltay",	ft_INT16,	NULL},
	{	 0,	"\377",		ft_IF8,	(void*)listGlyphEltSet},
	{	 0,	"len",		ft_COUNT8,	NULL},
	{	 8,	"glyphs",	ft_LISTofCARD16, NULL},
	ROUND,
	EOP
};
#define ft_LISTofGlyphElt16 ft_LISTofVarStruct, (void*)listGlyphElt16
static const struct parameter listGlyphElt32[] = {
	LC(8),
	{	 4,	"deltax",	ft_INT16,	NULL},
	{	 6,	"deltay",	ft_INT16,	NULL},
	{	 0,	"\377",		ft_IF8,	(void*)listGlyphEltSet},
	{	 0,	"len",		ft_COUNT8,	NULL},
	{	 8,	"glyphs",	ft_LISTofCARD32, NULL},
	EOP
};
#define ft_LISTofGlyphElt32 ft_LISTofVarStruct, (void*)listGlyphElt32

static const struct parameter parameterRenderCompositeGlyphs8[] = {
	{	 4,	"op",		ft_PictOp},
	{	 8,	"src",		ft_PICTURE,	NULL},
	{	12,	"dst",		ft_PICTURE,	NULL},
	{	16,	"maskFormat",	ft_PICTFORMAT,	c_none},
	{	20,	"glyphset",	ft_GLYPHSET,	NULL},
	{	24,	"xSrc",		ft_INT16,	NULL},
	{	26,	"ySrc",		ft_INT16,	NULL},
	{	28,	"glyphcmds",	ft_LISTofGlyphElt8},
	EOP
};
static const struct parameter parameterRenderCompositeGlyphs16[] = {
	{	 4,	"op",		ft_PictOp},
	{	 8,	"src",		ft_PICTURE,	NULL},
	{	12,	"dst",		ft_PICTURE,	NULL},
	{	16,	"maskFormat",	ft_PICTFORMAT,	c_none},
	{	20,	"glyphset",	ft_GLYPHSET,	NULL},
	{	24,	"xSrc",		ft_INT16,	NULL},
	{	26,	"ySrc",		ft_INT16,	NULL},
	{	28,	"glyphcmds",	ft_LISTofGlyphElt16},
	EOP
};
static const struct parameter parameterRenderCompositeGlyphs32[] = {
	{	 4,	"op",		ft_PictOp},
	{	 8,	"src",		ft_PICTURE,	NULL},
	{	12,	"dst",		ft_PICTURE,	NULL},
	{	16,	"maskFormat",	ft_PICTFORMAT,	c_none},
	{	20,	"glyphset",	ft_GLYPHSET,	NULL},
	{	24,	"xSrc",		ft_INT16,	NULL},
	{	26,	"ySrc",		ft_INT16,	NULL},
	{	28,	"glyphcmds",	ft_LISTofGlyphElt32},
	EOP
};

/* 0.1 and higher */

static const struct parameter parameterRenderFillRectangles[] = {
	{	 4,	"op",	ft_PictOp},
	{	 8,	"dst",	ft_PICTURE,	NULL},
	{	12,	"red",	ft_CARD16,	NULL},
	{	14,	"green",ft_CARD16,	NULL},
	{	16,	"blue",	ft_CARD16,	NULL},
	{	18,	"alpha",ft_CARD16,	NULL},
	{	20,	"rects",ft_LISTofRECTANGLE},
	EOP
};

/* 0.5 and higher */

static const struct parameter parameterRenderCreateCursor[] = {
	{	 4,	"cid",	ft_CURSOR,	NULL},
	{	 8,	"src",	ft_PICTURE,	NULL},
	{	 12,	"x",	ft_UINT16,	NULL},
	{	 14,	"y",	ft_UINT16,	NULL},
	EOP
};

/* 0.6 and higher */

static const struct parameter parameterRenderSetPictureTransform[] = {
	{	 4,	"picture",	ft_PICTURE,	NULL},
	{	 8,	"transform",	ft_LISTofCARD32,NULL},
	EOP
};

static const struct parameter parameterRenderQueryFilters[] = {
	{	 4,	"drawable",	ft_DRAWABLE,	NULL},
	EOP
};

static const struct parameter returnRenderQueryFilters[] = {
	{	 8,	"numAliases",	ft_CARD32,	NULL},
	{	32,	"Aliases",	ft_LISTofCARD16,NULL},
	ROUND,
	{	12,	"numFilters",	ft_CARD32,	NULL},
	{	OFS_LATER, "Filters",	ft_LISTofSTRING8},
	EOP
};

static const struct parameter parameterRenderSetPictureFilter[] = {
	{	 4,	"picture",	ft_PICTURE,	NULL},
	{	 8,	"nbytes",	ft_COUNT16,	NULL},
	{	12,	"name", 	ft_STRING8, 	NULL},
	/* params??
	ROUND,
	{OFS_LATER,	"values",	ft_LISTofCARD32,NULL},
	*/
	EOP
};

/* 0.8 and higher */

static const struct parameter listAnimCursorElt[] = {
	LC(8),
	{	 0,	"cursor",	ft_CURSOR,	NULL},
	{	 4,	"delay",	ft_CARD32,	NULL},
	EOP
};
#define ft_LISTofAnimCursorElt ft_LISTofStruct,(void*)listAnimCursorElt

static const struct parameter parameterRenderCreateAnimCursor[] = {
	{	 4,	"cid",	ft_CURSOR,	NULL},
	{	 8,	"cursors", ft_LISTofAnimCursorElt},
	EOP
};

#undef EOV
#define ra(a) { #a , parameter ## a , NULL,NULL,NULL}
#define rb(a) { #a , parameter ## a , return ## a ,NULL,NULL}

static const struct request extensionRENDER[] = {
	rb(RenderQueryVersion),
	rb(RenderQueryPictFormats),
	rb(RenderQueryPictIndexValues),
	ra(None),
	ra(RenderCreatePicture),
	ra(RenderChangePicture),
	ra(RenderSetPictureClipRectangles),
	ra(RenderFreePicture),
	ra(RenderComposite),
	ra(RenderScale),
	ra(RenderTrapezoids),
	ra(RenderTriangles),
	ra(RenderTriStrip),
	ra(RenderTriFan),
	ra(None),
	ra(None),
	ra(None),
	ra(RenderCreateGlyphSet),
	ra(RenderReferenceGlyphSet),
	ra(RenderFreeGlyphSet),
	ra(RenderAddGlyphs),
	ra(None),
	ra(RenderFreeGlyphs),
	ra(RenderCompositeGlyphs8),
	ra(RenderCompositeGlyphs16),
	ra(RenderCompositeGlyphs32),
	ra(RenderFillRectangles),
	ra(RenderCreateCursor),
	ra(RenderSetPictureTransform),
	rb(RenderQueryFilters),
	ra(RenderSetPictureFilter),
	ra(RenderCreateAnimCursor),
};

#undef ra
#undef rb

#define ev(name) { #name , eparam ## name }
static const struct event eventsRENDER[] = {
};
#undef ev

#define err(name) #name
static const char *errorsRENDER[] = {
	err(BadPictFormat),
	err(BadPicture),
	err(BadPictOp),
	err(BadGlyphSet),
	err(BadGlyph)
};
#undef bg

#undef EOP
