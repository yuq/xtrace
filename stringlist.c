/*  This file is part of "xtrace"
 *  Copyright (C) 2009 Bernhard R. Link
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

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "stringlist.h"

static struct string_bucket {
	struct string_bucket *next;
	size_t ofs;
	char data[];
} *stringlist;

static struct bucket {
	struct bucket *next;
	size_t size, ofs;
	char data[];
} *buckets;

#define STRINGLIST_SIZE 16 * 1024
#define BUCKET_SIZE 32 * 1024

void stringlist_init(void) {
	stringlist = malloc(STRINGLIST_SIZE);
	if( stringlist == NULL ) {
		fputs("Out of memory!\n", stderr);
		return;
	}
	stringlist->ofs = STRINGLIST_SIZE -
		((char*)&stringlist->data-(char*)stringlist);
	stringlist->next = NULL;

	buckets = malloc(BUCKET_SIZE);
	if( buckets == NULL ) {
		fputs("Out of memory!\n", stderr);
		return;
	}
	buckets->size = BUCKET_SIZE;
	buckets->ofs = sizeof(struct bucket);
	buckets->next = NULL;
}

void stringlist_done(void) {
	while( stringlist != NULL ) {
		struct string_bucket *n = stringlist->next;
		free(stringlist);
		stringlist = n;
	}
	while( buckets != NULL ) {
		struct bucket *n = buckets->next;
		free(buckets);
		buckets = n;
	}
}

const void *finalize_data(const void *data, size_t len, size_t align) {
	void *p;
	size_t next_ofs;

	if( buckets == NULL )
		return NULL;

	next_ofs = ((buckets->ofs + align - 1)/align)*align;
	if( next_ofs >= buckets->size || len > buckets->size - next_ofs ) {
		struct bucket *n;
		size_t size;

		if( len >= BUCKET_SIZE/2 )
			size = len;
		else
			size = BUCKET_SIZE;
		next_ofs = ((sizeof(struct bucket) + align - 1)/align)*align;
		size += next_ofs;
		n = malloc(size);
		if( n == NULL ) {
			fputs("Out of memory!\n", stderr);
			stringlist_done();
			return NULL;
		}
		n->size = size;
		n->ofs = next_ofs;
		if( n->size - n->ofs == len ) {
			n->ofs = n->size;
			p = ((char*)buckets) + next_ofs;
			memcpy(p, data, len);
			n->next = buckets->next;
			buckets->next = n;
			return p;
		}
		n->next = buckets;
		buckets = n;
	}
	assert( len <= buckets->size - next_ofs );
	p = ((char*)buckets) + next_ofs;
	memcpy(p, data, len);
	buckets->ofs = next_ofs + len;
	return p;
}

const char *string_add_l(const char *string, size_t len) {
	char *p;

	if( stringlist == NULL )
		return NULL;

	if( stringlist->ofs <= len ) {
		struct string_bucket *n;
		size_t size;

		size = STRINGLIST_SIZE;
		if( len >= size )
			size = ((char*)&stringlist->data-(char*)stringlist)
				+ 1 + len;

		n = malloc(size);
		if( n == NULL ) {
			fputs("Out of memory!\n", stderr);
			stringlist_done();
			return NULL;
		}
		n->ofs = size -
			((char*)&n->data-(char*)n);
		assert( n->ofs > len );
		if( n->ofs == len + 1 ) {
			n->ofs = 0;
			memcpy(n->data, string, len);
			n->data[len] = '\0';
			n->next = stringlist->next;
			stringlist->next = n;
			return n->data;
		}
		n->next = stringlist;
		stringlist = n;
	}
	assert( stringlist->ofs > len );

	stringlist->ofs -= len + 1;
	p = stringlist->data + stringlist->ofs;
	memcpy(p, string, len);
	p[len] = '\0';
	return p;
}

const char *string_add(const char *string) {
	return string_add_l(string, strlen(string));
}
