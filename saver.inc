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

static const struct constant c_saver_level[] = {
	{0,	"on"},
	{1,	"standby"},
	{2,	"suspend"},
	{3,	"off"},
	EOC
};
#define ft_Saver_LEVEL ft_ENUM16,c_saver_level

static const struct constant c_saver_state[] = {
	{0,	"off"},
	{1,	"on"},
	{2,	"cycle"},
	{3,	"disable"},
	EOC
};
#define ft_Saver_STATE ft_ENUM8,c_saver_state
static const struct constant c_saver_kind[] = {
	{0,	"blanked"},
	{1,	"internal"},
	{2,	"external"},
	EOC
};
#define ft_Saver_KIND ft_ENUM8,c_saver_kind

static const struct constant c_saver_mask[] = {
	{0x00000001,	"notify"},
	{0x00000002,	"cycle"},
	EOC
};
#define ft_Saver_MASK ft_BITMASK32,c_saver_mask

#undef EOC
#define EOP {0,NULL,0,NULL}
#define LC(len) {len,NULL,0,NULL}

static const struct parameter parameterSaverQueryVersion[] = {
	{	4,	"major version",	ft_UINT8,	NULL},
	{	5,	"minor version",	ft_UINT8,	NULL},
	EOP
};
static const struct parameter returnSaverQueryVersion[] = {
	{	8,	"major version",	ft_UINT16,	NULL},
	{	10,	"minor version",	ft_UINT16,	NULL},
	EOP
};

static const struct parameter parameterDRAWABLE[] = {
	{	4,	"drawable",	ft_DRAWABLE,	NULL	},
	EOP
};
#define parameterSaverQueryInfo parameterDRAWABLE
static const struct parameter returnSaverQueryInfo[] = {
	{	 1,	"state",		ft_Saver_STATE},
	{	 8,	"window",		ft_WINDOW,	NULL},
	{	 12,	"til or since",		ft_UINT32,	NULL},
	{	 16,	"idle",			ft_UINT32,	NULL},
	{	 20,	"event mask",		ft_Saver_MASK},
	{	 24,	"kind",			ft_Saver_KIND},
	EOP
};

static const struct parameter parameterSaverSelectInput[] = {
	{	 4,	"drawable",		ft_DRAWABLE,	NULL},
	{	 8,	"mask",			ft_Saver_MASK},
	EOP
};

static const struct parameter parameterSaverSetAttributes[] = {
	{	  4,	"drawable",		ft_DRAWABLE,	NULL},
	{	  8,	"x",			ft_INT16,	NULL},
	{	 10,	"y",			ft_INT16,	NULL},
	{	 12,	"width",		ft_UINT16,	NULL},
	{	 14,	"height",		ft_UINT16,	NULL},
	{	 16,	"border-height",	ft_UINT16,	NULL},
	{	 18,	"c_class",		ft_CARD8,	NULL},
	{	 19,	"depth",		ft_UINT8,	NULL},
	{	 20,	"visual-id",		ft_CARD32,	NULL},
	{	 24,	"mask",			ft_Saver_MASK},
	EOP
};
#define parameterSaverUnsetAttributes parameterDRAWABLE

static const struct parameter parameterSaverSuspend[] = {
	{	 4,	"suspend",		ft_BOOL},
	EOP
};

#undef EOV
#define ra(a) { #a , parameter ## a , NULL,NULL,NULL}
#define rb(a) { #a , parameter ## a , return ## a ,NULL,NULL}
static const struct request extensionSaver[] = {
	rb(SaverQueryVersion),
	rb(SaverQueryInfo),
	ra(SaverSelectInput),
	ra(SaverSetAttributes),
	ra(SaverUnsetAttributes),
	ra(SaverSuspend)
};

#undef ra
#undef rb

static const struct parameter eparamSaverNotify[] = {
	{	 1,	"state",		ft_Saver_STATE},
	{	 8,	"root",			ft_WINDOW,	NULL},
	{	12,	"window",		ft_WINDOW,	NULL},
	{	16,	"kind",			ft_Saver_KIND},
	{	17,	"forced",		ft_BOOL},
	EOP
};

#define ev(name) { #name , eparam ## name }
static const struct event eventsSaver[] = {
	ev(SaverNotify),
};
#undef ev
static const char *errorsSaver[] = { };

#undef EOP
