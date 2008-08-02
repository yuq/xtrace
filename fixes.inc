/*  This file is part of "xtrace"
 *  Copyright (C) 2008 Bernhard R. Link
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

#define EOV {0, NULL, -1, NULL}
#define EOC {-1, NULL}

static const struct constant c_fixes_mode[] = {
	{0,	"insert"},
	{1,	"delete"},
	EOC
};
#define ft_FIXES_MODE ft_ENUM8,c_fixes_mode
static const struct constant c_fixes_target[] = {
	{0,	"nearest"},
	{1,	"root"},
	EOC
};
#define ft_FIXES_TARGET ft_ENUM8,c_fixes_target
static const struct constant c_fixes_map[] = {
	{0,	"set"},
	{1,	"unset"},
	EOC
};
#define ft_FIXES_MAP ft_ENUM8,c_fixes_map
static const struct constant c_fixes_region_kind[] = {
	{0,	"bounding"},
	{1,	"clip"},
	EOC
};
#define ft_FIXES_REGION_KIND ft_ENUM8,c_fixes_region_kind

static const struct constant c_fixes_mask[] = {
	{0x00000001,	"owner notify"},
	{0x00000002,	"destroy notify"},
	{0x00000004,	"client close notify"},
	EOC
};
#define ft_FIXES_MASK ft_BITMASK32,c_fixes_mask

static const struct constant c_fixes_subtype[] = {
	{0,	"set owner"},
	{1,	"destroy"},
	{2,	"client close"},
	EOC
};
#define ft_FIXES_SUBTYPE ft_ENUM8,c_fixes_subtype

static const struct constant c_fixes_cursor_mask[] = {
	{0x00000001,	"display cursor notify"},
	EOC
};
#define ft_FIXES_CURSOR_MASK ft_BITMASK32,c_fixes_cursor_mask
static const struct constant c_fixes_cursor_subtype[] = {
	{0,	"display cursor"},
	EOC
};
#define ft_FIXES_CURSOR_SUBTYPE ft_ENUM8,c_fixes_cursor_subtype

#undef EOC
#define EOP {0,NULL,0,NULL}
#define LC(len) {len,NULL,0,NULL}

static const struct parameter parameterFixesQueryVersion[] = {
	{	4,	"major version",	ft_UINT32,	NULL},
	{	8,	"minor version",	ft_UINT32,	NULL},
	EOP
};
static const struct parameter returnFixesQueryVersion[] = {
	{	8,	"major version",	ft_UINT32,	NULL},
	{	12,	"minor version",	ft_UINT32,	NULL},
	EOP
};
static const struct parameter parameterFixesChangeSaveSet[] = {
	{	4,	"mode",			ft_FIXES_MODE},
	{	5,	"target",		ft_FIXES_TARGET},
	{	6,	"map",			ft_FIXES_MAP},
	{	8,	"window",		ft_WINDOW,	NULL},
	EOP
};
static const struct parameter parameterFixesSelectSelectionInput[] = {
	{	4,	"window",		ft_WINDOW,	NULL},
	{	8,	"selection",		ft_ATOM,	NULL},
	{	12,	"eventMask",		ft_FIXES_MASK},
	EOP
};
static const struct parameter parameterFixesSelectCursorInput[] = {
	{	4,	"window",		ft_WINDOW,	NULL},
	{	8,	"eventMask",		ft_FIXES_CURSOR_MASK},
	EOP
};
#define parameterFixesGetCursorImage parameterEmpty
static const struct parameter returnFixesGetCursorImage[] = {
	{	8,	"x",			ft_INT16,	NULL},
	{	10,	"y",			ft_INT16,	NULL},
	{	12,	"width",		ft_UINT16,	NULL},
	{	14,	"height",		ft_UINT16,	NULL},
	{	16,	"xhot",			ft_UINT16,	NULL},
	{	18,	"yhot",			ft_UINT16,	NULL},
	{	20,	"cursor serial",	ft_CARD32,	NULL},
	EOP
};
static const struct parameter parameterFixesCreateRegion[] = {
	{	4,	"region",		ft_CARD32,	NULL},
	{	8,	"rectangles",		ft_LISTofRECTANGLE},
	EOP
};
static const struct parameter parameterFixesCreateRegionFromBitmap[] = {
	{	4,	"region",		ft_CARD32,	NULL},
	{	8,	"bitmap",		ft_PIXMAP,	NULL},
	EOP
};
static const struct parameter parameterFixesCreateRegionFromWindow[] = {
	{	4,	"region",		ft_CARD32,	NULL},
	{	8,	"window",		ft_WINDOW,	NULL},
	{	12,	"kind",			ft_FIXES_REGION_KIND},
	EOP
};
static const struct parameter parameterFixesCreateRegionFromGC[] = {
	{	4,	"region",		ft_CARD32,	NULL},
	{	8,	"gc",			ft_GCONTEXT,	NULL},
	EOP
};
static const struct parameter parameterFixesCreateRegionFromPicture[] = {
	{	4,	"region",		ft_CARD32,	NULL},
	{	8,	"picture",		ft_PICTURE,	NULL},
	EOP
};
static const struct parameter parameterFixesRegion[] = {
	{	4,	"region",		ft_CARD32,	NULL},
	EOP
};
#define parameterFixesDestroyRegion parameterFixesRegion
#define parameterFixesSetRegion parameterFixesCreateRegion
static const struct parameter parameterFixesCopyRegion[] = {
	{	4,	"src-region",		ft_CARD32,	NULL},
	{	8,	"dst-region",		ft_CARD32,	NULL},
	EOP
};

static const struct parameter parameterFixesCombineRegion[] = {
	{	4,	"region1",		ft_CARD32,	NULL},
	{	8,	"region2",		ft_CARD32,	NULL},
	{	12,	"dst-region",		ft_CARD32,	NULL},
	EOP
};
#define parameterFixesUnionRegion parameterFixesCombineRegion
#define parameterFixesIntersectRegion parameterFixesCombineRegion
#define parameterFixesSubtractRegion parameterFixesCombineRegion

static const struct parameter parameterFixesInvertRegion[] = {
	{	4,	"src-region",		ft_CARD32,	NULL},
	{	8,	"x",			ft_INT16,	NULL},
	{	10,	"y",			ft_INT16,	NULL},
	{	12,	"width",		ft_UINT16,	NULL},
	{	14,	"height",		ft_UINT16,	NULL},
	{	16,	"dst-region",		ft_CARD32,	NULL},
	EOP
};

static const struct parameter parameterFixesTranslateRegion[] = {
	{	4,	"region",		ft_CARD32,	NULL},
	{	8,	"delta-x",			ft_INT16,	NULL},
	{	10,	"delta-y",	ft_INT16,	NULL},
	EOP
};

#define parameterFixesRegionExtents parameterFixesCopyRegion
#define parameterFixesFetchRegion parameterFixesRegion

static const struct parameter returnFixesFetchRegion[] = {
	{	8,	"x",			ft_INT16,	NULL},
	{	10,	"y",			ft_INT16,	NULL},
	{	12,	"width",		ft_UINT16,	NULL},
	{	14,	"height",		ft_UINT16,	NULL},
	EOP
};

static const struct parameter parameterFixesSetGCClipRegion[] = {
	{	4,	"gc",			ft_GCONTEXT,	NULL},
	{	8,	"region",		ft_CARD32,	NULL},
	{	12,	"x origin",		ft_INT16,	NULL},
	{	14,	"y origin",		ft_INT16,	NULL},
	EOP
};

static const struct parameter parameterFixesSetWindowShapeRegion[] = {
	{	4,	"window",		ft_WINDOW,	NULL},
	{	8,	"kind",			ft_FIXES_REGION_KIND},
	{	12,	"x offset",		ft_INT16,	NULL},
	{	14,	"y offset",		ft_INT16,	NULL},
	{	16,	"region",		ft_CARD32,	NULL},
	EOP
};

static const struct parameter parameterFixesSetPictureClipRegion[] = {
	{	4,	"picture",		ft_PICTURE,	NULL},
	{	8,	"region",		ft_CARD32,	NULL},
	{	12,	"x origin",		ft_INT16,	NULL},
	{	14,	"y origin",		ft_INT16,	NULL},
	EOP
};

static const struct parameter parameterFixesSetCursorName[] = {
	{	4,	"cursor",		ft_CARD32,	NULL},
	{	8,	"",			ft_COUNT16,	NULL},
	{	12,	"name",			ft_STRING8,	NULL},
	EOP
};
static const struct parameter parameterFixesGetCursorName[] = {
	{	4,	"cursor",		ft_CARD32,	NULL},
	EOP
};
static const struct parameter returnFixesGetCursorName[] = {
	{	8,	"atom",			ft_ATOM,	NULL},
	{	12,	"",			ft_COUNT16,	NULL},
	{	32,	"name",			ft_STRING8,	NULL},
	EOP
};
#define parameterFixesGetCursorImageAndName parameterEmpty
static const struct parameter returnFixesGetCursorImageAndName[] = {
	{	 8,	"x",			ft_INT16,	NULL},
	{	10,	"y",			ft_INT16,	NULL},
	{	12,	"width",		ft_UINT16,	NULL},
	{	14,	"height",		ft_UINT16,	NULL},
	{	16,	"xhot",			ft_UINT16,	NULL},
	{	18,	"yhot",			ft_UINT16,	NULL},
	{	20,	"cursor serial",	ft_CARD32,	NULL},
	{	24,	"cursor name",		ft_ATOM,	NULL},
	{	28,	"",			ft_COUNT16,	NULL},
	{	32,	"name",			ft_STRING8,	NULL},
	EOP
};
static const struct parameter parameterFixesChangeCursor[] = {
	{	4,	"src-cursor",		ft_CARD32,	NULL},
	{	8,	"dst-cursor",		ft_CARD32,	NULL},
	EOP
};
static const struct parameter parameterFixesChangeCursorByName[] = {
	{	 4,	"src-cursor",		ft_CARD32,	NULL},
	{	 8,	"",			ft_COUNT16,	NULL},
	{	12,	"name",			ft_STRING8,	NULL},
	EOP
};
static const struct parameter parameterFixesExpandRegion[] = {
	{	 4,	"src-region",		ft_CARD32,	NULL},
	{	 8,	"dst-region",		ft_CARD32,	NULL},
	{	12,	"left",			ft_UINT16,	NULL},
	{	14,	"right",		ft_UINT16,	NULL},
	{	16,	"top",			ft_UINT16,	NULL},
	{	18,	"bottom",		ft_UINT16,	NULL},
	EOP
};
#define parameterFixesHideCursor parameterWINDOW
#define parameterFixesShowCursor parameterWINDOW

#undef EOV
#define ra(a) { #a , parameterFixes ## a , NULL,NULL,NULL}
#define rb(a) { #a , parameterFixes ## a , returnFixes ## a ,NULL,NULL}
static const struct request extensionFIXES[] = {
	rb(QueryVersion),
	ra(ChangeSaveSet),
	ra(SelectSelectionInput),
	ra(SelectCursorInput),
	rb(GetCursorImage),
	ra(CreateRegion),
	ra(CreateRegionFromBitmap),
	ra(CreateRegionFromWindow),
	ra(CreateRegionFromGC),
	ra(CreateRegionFromPicture),
	ra(DestroyRegion),
	ra(SetRegion),
	ra(CopyRegion),
	ra(UnionRegion),
	ra(IntersectRegion),
	ra(SubtractRegion),
	ra(InvertRegion),
	ra(TranslateRegion),
	ra(RegionExtents),
	rb(FetchRegion),
	ra(SetGCClipRegion),
	ra(SetWindowShapeRegion),
	ra(SetPictureClipRegion),
	ra(SetCursorName),
	rb(GetCursorName),
	rb(GetCursorImageAndName),
	ra(ChangeCursor),
	ra(ChangeCursorByName),
	ra(ExpandRegion),
	ra(HideCursor),
	ra(ShowCursor)
};

#undef ra
#undef rb

static const struct parameter eparamFixesSelectionNotify[] = {
	{	 1,	"subtype",		ft_FIXES_SUBTYPE},
	{	 4,	"window",		ft_WINDOW,	NULL},
	{	 8,	"owner",		ft_WINDOW,	NULL},
	{	12,	"selection",		ft_ATOM,	NULL},
	{	16,	"timestamp",		ft_TIMESTAMP,	NULL},
	{	20,	"selectionTimestamp",	ft_TIMESTAMP,	NULL},
	EOP
};
static const struct parameter eparamFixesCursorNotify[] = {
	{	 1,	"subtype",		ft_FIXES_CURSOR_SUBTYPE},
	{	 4,	"window",		ft_WINDOW,	NULL},
	{	 8,	"cursor serial",	ft_CARD32,	NULL},
	{	12,	"timestamp",		ft_TIMESTAMP,	NULL},
	{	16,	"name",			ft_ATOM,	NULL},
	EOP
};

#define ev(name) { "XFIXES " #name , eparamFixes ## name }
static const struct event eventsFIXES[] = {
	ev(SelectionNotify),
	ev(CursorNotify),
};
#undef ev
static const char *errorsFIXES[] = { "BadRegion" };

#undef EOP
