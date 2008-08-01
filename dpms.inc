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

static const struct constant c_dpms_level[] = {
	{0,	"on"},
	{1,	"standby"},
	{2,	"suspend"},
	{3,	"off"},
	EOC
};
#define ft_DPMS_LEVEL ft_ENUM16,c_dpms_level

#undef EOC
#define EOP {0,NULL,0,NULL}
#define LC(len) {len,NULL,0,NULL}

static const struct parameter parameterDpmsGetVersion[] = {
	{	4,	"major version",	ft_UINT16,	NULL},
	{	6,	"minor version",	ft_UINT16,	NULL},
	EOP
};
static const struct parameter returnDpmsGetVersion[] = {
	{	8,	"major version",	ft_UINT16,	NULL},
	{	10,	"minor version",	ft_UINT16,	NULL},
	EOP
};

#define parameterDpmsCapable parameterEmpty
static const struct parameter returnDpmsCapable[] = {
	{	 8,	"capable",		ft_BOOL},
	EOP
};
#define parameterDpmsGetTimeouts parameterEmpty
static const struct parameter returnDpmsGetTimeouts[] = {
	{	 8,	"standby",		ft_UINT16,	NULL},
	{	10,	"suspend",		ft_UINT16,	NULL},
	{	12,	"off",			ft_UINT16,	NULL},
	EOP
};

static const struct parameter parameterDpmsSetTimeouts[] = {
	{	 4,	"standby",		ft_UINT16,	NULL},
	{	 6,	"suspend",		ft_UINT16,	NULL},
	{	 8,	"off",			ft_UINT16,	NULL},
	EOP
};
#define parameterDpmsEnable parameterEmpty
#define parameterDpmsDisable parameterEmpty

static const struct parameter parameterDpmsForceLevel[] = {
	{	 4,	"level",		ft_DPMS_LEVEL},
	EOP
};

#define parameterDpmsInfo parameterEmpty
static const struct parameter returnDpmsInfo[] = {
	{	 8,	"power_level",		ft_DPMS_LEVEL},
	{	10,	"state",		ft_BOOL},
	EOP
};

#undef EOV
#define ra(a) { #a , parameter ## a , NULL,NULL,NULL}
#define rb(a) { #a , parameter ## a , return ## a ,NULL,NULL}
static const struct request extensionDPMS[] = {
	rb(DpmsGetVersion),
	rb(DpmsCapable),
	rb(DpmsGetTimeouts),
	ra(DpmsSetTimeouts),
	ra(DpmsEnable),
	ra(DpmsDisable),
	ra(DpmsForceLevel),
	rb(DpmsInfo),
};

#undef ra
#undef rb

static const struct event eventsDPMS[] = { };
static const char *errorsDPMS[] = { };

#undef EOP
