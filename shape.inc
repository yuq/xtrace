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
		  X Nonrectangular Window
		  Shape Extension Protocol
			Version 1.0
		   X Consortium Standard
		 X Version 11, Release 6.4
		       Keith Packard
		      MIT X Consortium
Copyright (C) 1989 X Consortium

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
POSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE X
CONSORTIUM BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABIL-
ITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR
THE USE OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of the X Con-
sortium shall not be used in advertising or otherwise to
promote the sale, use or other dealings in this Software
without prior written authorization from the X Consortium.
*/

#define EOV {0, NULL, -1, NULL}
#define EOC {-1, NULL}

static const struct constant c_shape_kind[] = {
	{0,	"Bounding"},
	{1,	"Clip"},
	EOC
};
#define ft_SHAPE_KIND ft_ENUM8,c_shape_kind
static const struct constant c_shape_op[] = {
	{0,	"Set"},
	{1,	"Union"},
	{2,	"Intersect"},
	{3,	"Subtract"},
	{4,	"Invert"},
	EOC
};
#define ft_SHAPE_OP ft_ENUM8,c_shape_op
static const struct constant c_shape_sort[] = {
	{0,	"UnSorted"},
	{1,	"YSorted"},
	{2,	"YXSorted"},
	{3,	"YXBanded"},
	EOC
};
#undef EOC
#define EOP {0,NULL,0,NULL}
#define LC(len) {len,NULL,0,NULL}

#define parameterShapeQueryVersion parameterEmpty

const struct parameter returnShapeQueryVersion[] = {
	{	8,	"major version",	ft_UINT16,	NULL},
	{	10,	"minor version",	ft_UINT16,	NULL},
	EOP
};

const struct parameter parameterShapeRectangles[] = {
	{	4,	"operation",		ft_SHAPE_OP},
	{	5,	"destination kind",	ft_SHAPE_KIND},
	{	6,	"ordering",		ft_ENUM8,	c_shape_sort},
	{	8,	"destination window",	ft_WINDOW,	NULL},
	{	12,	"x-offset",	ft_INT16,	NULL},
	{	14,	"y-offset",	ft_INT16,	NULL},
	{	16,	"rectangles",	ft_LISTofRECTANGLE},
	EOP
};

const struct parameter parameterShapeMask[] = {
	{	4,	"operation",	ft_SHAPE_OP},
	{	5,	"destination-kind",	ft_SHAPE_KIND},
	{	8,	"destination-window",	ft_WINDOW,	NULL},
	{	12,	"x-offset",	ft_INT16,	NULL},
	{	14,	"y-offset",	ft_INT16,	NULL},
	{	16,	"source-bitmap",	ft_PIXMAP,	c_none},
	EOP
};

const struct parameter parameterShapeCombine[] = {
	{	4,	"operation",	ft_SHAPE_OP},
	{	5,	"destination-kind",	ft_SHAPE_KIND},
	{	6,	"source-kind",	ft_SHAPE_KIND},
	{	8,	"destination window",	ft_WINDOW,	NULL},
	{	12,	"x offset",	ft_INT16,	NULL},
	{	14,	"y offset",	ft_INT16,	NULL},
	{	16,	"source-window",	ft_WINDOW,	NULL},
	EOP
};

const struct parameter parameterShapeOffset[] = {
	{	4,	"destination kind",	ft_SHAPE_KIND},
	{	8,	"destination window",	ft_WINDOW,	NULL},
	{	12,	"x offset",	ft_INT16,	NULL},
	{	14,	"y offset",	ft_INT16,	NULL},
	EOP
};

#define parameterShapeQueryExtents parameterWINDOW

const struct parameter returnShapeQueryExtents[] ={
	{	8,	"bounding shaped",		ft_BOOL},
	{	9,	"clip shaped",			ft_BOOL},
	{	12,	"bounding shape extents x",	ft_INT16,	NULL},
	{	14,	"bounding shape extents y",	ft_INT16,	NULL},
	{	16,	"bounding shape extents width",	ft_UINT16,	NULL},
	{	18,	"bounding shape extents height",ft_UINT16,	NULL},
	{	20,	"clip shape extents x",		ft_INT16,	NULL},
	{	22,	"clip shape extents y",		ft_INT16,	NULL},
	{	24,	"clip shape extents width",	ft_UINT16,	NULL},
	{	26,	"clip shape extents height",	ft_UINT16,	NULL},
	EOP
};

const struct parameter parameterShapeSelectInput[] = {
	{	4,	"destination window",	ft_WINDOW,	NULL},
	{	8,	"enable",	ft_BOOL},
	EOP
};

#define parameterShapeInputSelected parameterWINDOW

const struct parameter returnShapeInputSelected[] ={
	{	1,	"enabled",	ft_BOOL},
	EOP
};

const struct parameter parameterShapeGetRectangles[] = {
	{	4,	"window",	ft_WINDOW,	NULL},
	{	8,	"source-kind",	ft_SHAPE_KIND},
	EOP
};

const struct parameter returnShapeGetRectangles[] ={
	{	1,	"ordering",	ft_ENUM8,	c_shape_sort},
	{	8,	"nrects",	ft_COUNT32,	NULL},
	{	32,	"rectangles",	ft_LISTofRECTANGLE},
	EOP
};

#undef EOV
#define ra(a) { #a , parameter ## a , NULL,NULL,NULL}
#define rb(a) { #a , parameter ## a , return ## a ,NULL,NULL}
static const struct request extensionSHAPE[] = {
	rb(ShapeQueryVersion),
	ra(ShapeRectangles),
	ra(ShapeMask),
	ra(ShapeCombine),
	ra(ShapeOffset),
	rb(ShapeQueryExtents),
	ra(ShapeSelectInput),
	rb(ShapeInputSelected),
	rb(ShapeGetRectangles)
};

#undef ra
#undef rb

const struct parameter eparamShapeNotify[] = {
	{	1,	"shape kind",		ft_SHAPE_KIND},
	{	4,	"affected window",	ft_WINDOW,	NULL},
	{	8,	"x value of extents",	ft_INT16,	NULL},
	{	10,	"y value of extents",	ft_INT16,	NULL},
	{	12,	"width of extents",	ft_UINT16,	NULL},
	{	14,	"height of extents",	ft_UINT16,	NULL},
	{	16,	"server time",		ft_TIMESTAMP,	NULL},
	{	22,	"shaped",		ft_BOOL},
	EOP
};

#define ev(name) { #name , eparam ## name }
static const struct event eventsSHAPE[] = {
	ev(ShapeNotify),
};
#undef ev

static const char *errorsSHAPE[] = { };

#undef EOP
