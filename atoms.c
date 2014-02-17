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
#include <config.h>

#include <assert.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "xtrace.h"

#define CONSTANT_ATOMS 68
static const char *constant_atoms[CONSTANT_ATOMS] = {
	"PRIMARY", "SECONDARY", "ARC", "ATOM",
	"BITMAP", "CARDINAL", "COLORMAP", "CURSOR",
	"CUT_BUFFER0", "CUT_BUFFER1", "CUT_BUFFER2", "CUT_BUFFER3",
	"CUT_BUFFER4", "CUT_BUFFER5", "CUT_BUFFER6", "CUT_BUFFER7",
	"DRAWABLE", "FONT", "INTEGER", "PIXMAP",
	"POINT", "RECTANGLE", "RESOURCE_MANAGER", "RGB_COLOR_MAP",
	"RGB_BEST_MAP", "RGB_BLUE_MAP", "RGB_DEFAULT_MAP", "RGB_GRAY_MAP",
	"RGB_GREEN_MAP", "RGB_RED_MAP", "STRING", "VISUALID",
	"WINDOW", "WM_COMMAND", "WM_HINTS", "WM_CLIENT_MACHINE",
	"WM_ICON_NAME", "WM_ICON_SIZE", "WM_NAME", "WM_NORMAL_HINTS",
	"WM_SIZE_HINTS", "WM_ZOOM_HINTS", "MIN_SPACE", "NORM_SPACE",
	"MAX_SPACE", "END_SPACE", "SUPERSCRIPT_X", "SUPERSCRIPT_Y",
	"SUBSCRIPT_X", "SUBSCRIPT_Y", "UNDERLINE_POSITION", "UNDERLINE_THICKNESS",
	"STRIKEOUT_ASCENT", "STRIKEOUT_DESCENT", "ITALIC_ANGLE", "X_HEIGHT",
	"QUAD_WIDTH", "WEIGHT", "POINT_SIZE", "RESOLUTION",
	"COPYRIGHT", "NOTICE", "FONT_NAME", "FAMILY_NAME",
	"FULL_NAME", "CAP_HEIGHT", "WM_CLASS", "WM_TRANSIENT_FOR"
};

struct atom {
	struct atom *left,*right;
	uint32_t atom;
	char name[];
};
/* TODO: add connection specific values, too, to be activated on mismatch */
struct atom *atom_root = NULL;

struct atom *newAtom(const char *name, size_t len) {
	struct atom *atom;
	atom = malloc(sizeof(struct atom)+len+1);
	if( atom == NULL )
		abort();
	memcpy(atom->name,name,len);
	atom->name[len] = '\0';
	return atom;
}

const char *getAtom(struct connection *c UNUSED, uint32_t atom) {
	struct atom *p;
	if( atom <= 0 )
		return NULL;
	if( atom <= CONSTANT_ATOMS )
		return constant_atoms[atom-1];
	atom -= CONSTANT_ATOMS;
	p = atom_root;
	while( p != NULL ) {
		if( p->atom == atom )
			return p->name;
		if( p->atom > atom )
			p = p->left;
		else
			p = p->right;
	}
	return NULL;
}
void internAtom(struct connection *c UNUSED, uint32_t atom, struct atom *data) {
	struct atom **p;

	if( atom <= CONSTANT_ATOMS ) {
		free(data);
		return;
	}
	assert( data != NULL );
	atom -= CONSTANT_ATOMS; /* still always > 0 */
	data->atom = atom;

	p = &atom_root;
	while( *p != NULL ) {
		uint32_t k;
		k = (*p)->atom;
		if( atom == k ) {
			if( strcmp((*p)->name, data->name) != 0 )
				fprintf(stderr,"Mismatch in InternAtom: Got %x = '%s', but remember = '%s'!\n",(unsigned int)atom,data->name,(*p)->name);
			free(data);
			return;
		} else if( atom > k ) {
			p = &(*p)->right;
		} else { /* atom < k */
			p = &(*p)->left;
		}
	}
	*p = data;
	data->left = NULL;
	data->right = NULL;
}
