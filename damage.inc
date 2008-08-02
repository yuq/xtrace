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

static const struct constant c_damage_level[] = {
	{0,	"report raw rectangles"},
	{1,	"report delta rectangles"},
	{2,	"report bounding box"},
	{3,	"report non-empty"},
	EOC
};
#define ft_DAMAGE_LEVEL ft_ENUM8,c_damage_level

static const struct constant c_damage_state[] = {
	{0,	"off"},
	{1,	"on"},
	{2,	"cycle"},
	{3,	"disable"},
	EOC
};
#define ft_DAMAGE_STATE ft_ENUM8,c_damage_state
static const struct constant c_damage_kind[] = {
	{0,	"blanked"},
	{1,	"internal"},
	{2,	"external"},
	EOC
};
#define ft_DAMAGE_KIND ft_ENUM8,c_damage_kind

static const struct constant c_damage_mask[] = {
	{0x00000001,	"notify"},
	{0x00000002,	"cycle"},
	EOC
};
#define ft_DAMAGE_MASK ft_BITMASK32,c_damage_mask

#undef EOC
#define EOP {0,NULL,0,NULL}
#define LC(len) {len,NULL,0,NULL}

static const struct parameter parameterDamageQueryVersion[] = {
	{	4,	"major version",	ft_UINT32,	NULL},
	{	8,	"minor version",	ft_UINT32,	NULL},
	EOP
};
static const struct parameter returnDamageQueryVersion[] = {
	{	8,	"major version",	ft_UINT32,	NULL},
	{	12,	"minor version",	ft_UINT32,	NULL},
	EOP
};

static const struct parameter parameterDamageCreate[] = {
	{	 4,	"damage",		ft_CARD32,	NULL},
	{	 8,	"drawable",		ft_DRAWABLE,	NULL},
	{	12,	"level",		ft_DAMAGE_LEVEL},
	EOP
};

static const struct parameter parameterDamageDestroy[] = {
	{	 4,	"damage",		ft_CARD32,	NULL},
	EOP
};

static const struct parameter parameterDamageSubtract[] = {
	{	 4,	"damage",		ft_CARD32,	NULL},
	{	 8,	"repair-region",	ft_CARD32,	NULL},
	{	12,	"parts-region",		ft_CARD32,	NULL},
	EOP
};


#undef EOV
#define ra(a) { #a , parameterDamage ## a , NULL,NULL,NULL}
#define rb(a) { #a , parameterDamage ## a , returnDamage ## a ,NULL,NULL}
static const struct request extensionDAMAGE[] = {
	rb(QueryVersion),
	ra(Create),
	ra(Destroy),
	ra(Subtract)
};

#undef ra
#undef rb

static const struct parameter eparamDAMAGENotify[] = {
	{	 1,	"level",		ft_DAMAGE_LEVEL},
	{	 4,	"drawable",		ft_DRAWABLE,	NULL},
	{	 8,	"damage",		ft_CARD32,	NULL},
	{	12,	"timestamp",		ft_TIMESTAMP,	NULL},
	{	16,	"area",			ft_RECTANGLE},
	{	24,	"geometry",		ft_RECTANGLE},
	EOP
};

#define ev(name) { #name , eparam ## name }
static const struct event eventsDAMAGE[] = {
	ev(DAMAGENotify),
};
#undef ev
static const char *errorsDAMAGE[] = { "BadDamage" };

#undef EOP
