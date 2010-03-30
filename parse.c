/*  This file is part of "xtrace"
 *  Copyright (C) 2005,2006,2009 Bernhard R. Link
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
#include <stdint.h>
#include <sys/types.h>
#include <sys/time.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/select.h>
#include <unistd.h>

#include "xtrace.h"
#include "parse.h"

enum package_direction { TO_SERVER, TO_CLIENT };

static void startline(struct connection *c, enum package_direction d, const char *format, ...) FORMAT(printf,3,4);

static const bool print_counts = false;
static const bool print_offsets = false;

static inline unsigned int padded(unsigned int s) {
	return (s+3)&(~3);
}

static void startline(struct connection *c, enum package_direction d, const char *format, ...) {
	va_list ap;
	struct timeval tv;

	if( (print_timestamps || print_reltimestamps)
			&& gettimeofday(&tv, NULL) == 0 ) {
		if( print_timestamps )
			fprintf(out, "%lu.%03u ", (unsigned long)tv.tv_sec,
					(unsigned int)(tv.tv_usec/1000));
		if( print_reltimestamps ) {
			unsigned long long tt = ((unsigned long long)1000)*tv.tv_sec +
						(tv.tv_usec/1000);
			fprintf(out, "%lu.%03u ",
				(unsigned long)((tt - c->starttime)/1000),
				(unsigned int)((tt - c->starttime)%1000));
		}
	}
	va_start(ap, format);
	fprintf(out, "%03d:%c:", c->id, (d == TO_SERVER)?'<':'>');
	vfprintf(out, format, ap);
	va_end(ap);
}

#define U256 ((unsigned int)256)
#define UL256 ((unsigned long)256)
#define CARD16(bigendian,buffer,ofs) ((bigendian)?(buffer[ofs]*U256+buffer[ofs+1]):(buffer[ofs+1]*U256+buffer[ofs]))
#define CARD32(bigendian,buffer,ofs) ((bigendian)?(((buffer[ofs]*U256+buffer[ofs+1])*UL256+buffer[ofs+2])*UL256+buffer[ofs+3]):(buffer[ofs]+UL256*(buffer[ofs+1]+UL256*(buffer[ofs+2]+U256*buffer[ofs+3]))))
#define clientCARD32(ofs) CARD32(c->bigendian,c->clientbuffer,ofs)
#define clientCARD16(ofs) CARD16(c->bigendian,c->clientbuffer,ofs)
#define clientCARD8(ofs) c->clientbuffer[ofs]
#define serverCARD32(ofs) CARD32(c->bigendian,c->serverbuffer,ofs)
#define serverCARD16(ofs) CARD16(c->bigendian,c->serverbuffer,ofs)
#define serverCARD8(ofs) c->serverbuffer[ofs]
#define getCARD32(ofs) CARD32(c->bigendian,buffer,ofs)
#define getCARD16(ofs) CARD16(c->bigendian,buffer,ofs)
#define getCARD8(ofs) buffer[ofs]
#define getCARD32(ofs) CARD32(c->bigendian,buffer,ofs)

#define getBE32(ofs) (((buffer[ofs]*UL256+buffer[ofs+1])*UL256+buffer[ofs+2])*UL256+buffer[ofs+3])

struct usedextension {
	struct usedextension *next;
	const struct extension *extension;
	unsigned char major_opcode;
	unsigned char first_event;
	unsigned char first_error;
};

void free_usedextensions(struct usedextension *e) {
	while( e != NULL ) {
		struct usedextension *h = e->next;
		free(e);
		e = h;
	}
}

struct unknownextension {
	struct unknownextension *next;
	const char *name;
	size_t namelen;
	unsigned char major_opcode;
	unsigned char first_event;
	unsigned char first_error;
};

void free_unknownextensions(struct unknownextension *e) {
	while( e != NULL ) {
		struct unknownextension *h = e->next;
		free(e);
		e = h;
	}
}

static struct unknownextension *register_unknown_extension(struct connection *c, const unsigned char *name, size_t namelen) {
	const struct unknownextension *e;
	struct unknownextension *n;

	for( e = c->unknownextensions ; e != NULL ; e = e->next ) {
		if( e->namelen != namelen )
			continue;
		if( strncmp((char*)name, e->name, namelen) != 0 )
			continue;
		return NULL;
	}
	for( n = c->waiting ; n != NULL ; n = n->next ) {
		if( n->namelen != namelen )
			continue;
		if( strncmp((char*)name, n->name, namelen) != 0 )
			continue;
		return n;
	}
	n = malloc(sizeof(struct unknownextension));
	if( n == NULL )
		abort();
	n->name = strndup((char*)name, namelen);
	if( n->name == NULL )
		abort();
	n->namelen = namelen;
	n->next = c->waiting;
	c->waiting = n;
	return n;
}

struct expectedreply {
	struct expectedreply *next;
	uint64_t seq;
	const struct request *from;
	int datatype;
	void *data;
};

const struct extension *find_extension(const uint8_t *name,size_t len);

static void print_bitfield(const char *name,const struct constant *constants, unsigned long l){
	const struct constant *c;
	const char *zeroname = "0";
	bool first = true;

	/* bitmasks should have some */
	assert(constants != NULL);
	fprintf(out,"%s=",name);

	for( c = constants; c->name != NULL ; c++ ) {
		if( c->value == 0 )
			zeroname = c->name;
		else if( (l & c->value) != 0 ) {
			if( !first )
				putc(',',out);
			first = false;
			fputs(c->name,out);
		}
	}
	if( first )
		fputs(zeroname,out);
};

static const char *findConstant(const struct constant *constants, unsigned long l){
	const struct constant *c;

	if( constants == NULL )
		return NULL;

	for( c = constants; c->name != NULL ; c++ ) {
		if( c->value == l )
			return c->name;
	}
	return NULL;
};

#define OFS_LATER ((size_t)-1)
#define ROUND_32 ((size_t)-1)
#define ROUND { ROUND_32, "", ft_LASTMARKER, NULL}


static size_t printSTRING8(const uint8_t *buffer,size_t buflen,const struct parameter *p,size_t len,size_t ofs){
	size_t nr = 0;

	if( buflen < ofs )
		return ofs;
	if( buflen - ofs <= len )
		len = buflen - ofs;

	if( print_offsets )
		fprintf(out,"[%d]",(int)ofs);
	fprintf(out,"%s='",p->name);
	while( len > 0 ) {
		if( nr == maxshownlistlen ) {
			fputs("'...",out);
		} else if( nr < maxshownlistlen ) {
			unsigned char c = getCARD8(ofs);
			if( c == '\n' ) {
				putc('\\',out);putc('n',out);
			} else if( c == '\t' ) {
				putc('\\',out);putc('t',out);
			} else if( (c >= ' ' && c <= '~' ) )
				putc(c,out);
			else
				fprintf(out,"\\%03hho", c);
		}
		ofs++;len--;nr++;
	}
	if( nr <= maxshownlistlen )
		putc('\'',out);
	return ofs;
}

static size_t printLISTofCARD8(const uint8_t *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
	bool notfirst = false;
	size_t nr = 0;

	if( buflen < ofs )
		return ofs;
	if( buflen - ofs <= len )
		len = buflen - ofs;

	if( print_offsets )
		fprintf(out,"[%d]",(int)ofs);
	fprintf(out,"%s=",p->name);
	while( len > 0 ) {
		const char *value;
		unsigned char u8;

		if( nr == maxshownlistlen ) {
			fputs(",...",out);
		} else if( nr < maxshownlistlen ) {
			if( notfirst )
				putc(',',out);
			notfirst = true;
			u8 = getCARD8(ofs);
			value = findConstant(p->constants,u8);
			if( value )
				fprintf(out,"%s(0x%hhx)",value,u8);
			else
				fprintf(out,"0x%02hhx",u8);
		}
		len--;ofs++;nr++;
	}
	putc(';',out);
	return ofs;
}

static size_t printLISTofCARD16(struct connection *c,const uint8_t *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
	bool notfirst = false;
	size_t nr = 0;

	if( buflen < ofs )
		return ofs;
	if( (buflen - ofs)/2 <= len )
		len = (buflen - ofs)/2;

	if( print_offsets )
		fprintf(out,"[%d]",(int)ofs);
	fprintf(out,"%s=",p->name);
	while( len > 0 ) {
		const char *value;
		uint16_t u16;

		if( nr == maxshownlistlen ) {
			fputs(",...",out);
		} else if( nr < maxshownlistlen ) {
			if( notfirst )
				putc(',',out);
			notfirst = true;
			u16 = getCARD16(ofs);
			value = findConstant(p->constants,u16);
			if( value )
				fprintf(out,"%s(0x%hx)",value,(unsigned short int)u16);
			else
				fprintf(out,"0x%04hx",(unsigned short int)u16);
		}
		len--;ofs+=2;nr++;
	}
	putc(';',out);
	return ofs;
}

static size_t printLISTofCARD32(struct connection *c,const uint8_t *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
	bool notfirst = false;
	size_t nr = 0;

	if( buflen < ofs )
		return ofs;
	if( (buflen - ofs)/4 <= len )
		len = (buflen - ofs)/4;

	if( print_offsets )
		fprintf(out,"[%d]",(int)ofs);
	fprintf(out,"%s=",p->name);
	while( len > 0 ) {
		const char *value;
		uint32_t u32;

		if( nr == maxshownlistlen ) {
			fputs(",...",out);
		} else if( nr < maxshownlistlen ) {
			if( notfirst )
				putc(',',out);
			notfirst = true;
			u32 = getCARD32(ofs);
			value = findConstant(p->constants,u32);
			if( value )
				fprintf(out,"%s(0x%x)",value,(unsigned int)u32);
			else
				fprintf(out,"0x%08x",(unsigned int)u32);
		}
		len--;ofs+=4;nr++;
	}
	putc(';',out);
	return ofs;
}

static size_t printLISTofFIXED(struct connection *c,const uint8_t *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
	bool notfirst = false;
	size_t nr = 0;

	if( buflen < ofs )
		return ofs;
	if( (buflen - ofs)/4 <= len )
		len = (buflen - ofs)/4;

	if( print_offsets )
		fprintf(out,"[%d]",(int)ofs);
	fprintf(out,"%s=",p->name);
	while( len > 0 ) {
		int32_t i32;
		double d;

		if( nr == maxshownlistlen ) {
			fputs(",...",out);
		} else if( nr < maxshownlistlen ) {
			if( notfirst )
				putc(',',out);
			notfirst = true;
			i32 = getCARD32(ofs);
			d = i32 / 65536.0;
			fprintf(out,"%.6f", d);
		}
		len--;ofs+=4;nr++;
	}
	putc(';',out);
	return ofs;
}

static size_t printLISTofFLOAT32(struct connection *c, const uint8_t *buffer, size_t buflen, const struct parameter *p, size_t len, size_t ofs){
	bool notfirst = false;
	size_t nr = 0;

	if( buflen < ofs )
		return ofs;
	if( (buflen - ofs)/4 <= len )
		len = (buflen - ofs)/4;

	if( print_offsets )
		fprintf(out,"[%d]",(int)ofs);
	fprintf(out,"%s=",p->name);
	while( len > 0 ) {
		uint32_t u32;
		float f;

		if( nr == maxshownlistlen ) {
			fputs(",...",out);
		} else if( nr < maxshownlistlen ) {
			if( notfirst )
				putc(',',out);
			notfirst = true;
			u32 = getCARD32(ofs);
			memcpy(&f, &u32, 4);
			fprintf(out, "%f", f);
		}
		len--;ofs+=4;nr++;
	}
	putc(';',out);
	return ofs;
}

static size_t printLISTofATOM(struct connection *c,const uint8_t *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
	bool notfirst = false;
	size_t nr = 0;

	if( buflen < ofs )
		return ofs;
	if( (buflen - ofs)/4 <= len )
		len = (buflen - ofs)/4;

	if( print_offsets )
		fprintf(out,"[%d]",(int)ofs);
	fprintf(out,"%s=",p->name);
	while( len > 0 ) {
		const char *value;
		uint32_t u32;

		if( nr == maxshownlistlen ) {
			fputs(",...",out);
		} else if( nr < maxshownlistlen ) {
			if( notfirst )
				putc(',',out);
			notfirst = true;
			u32 = getCARD32(ofs);
			value = findConstant(p->constants,u32);
			if( value )
				fprintf(out,"%s(0x%x)",value,(unsigned int)u32);
			else if( (value = getAtom(c,u32)) == NULL )
				fprintf(out,"0x%x",(unsigned int)u32);
			else
				fprintf(out,"0x%x(\"%s\")",(unsigned int)u32,value);
		}
		len--;ofs+=4;nr++;
	}
	putc(';',out);
	return ofs;
}

static size_t printLISTofINT8(const uint8_t *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
	bool notfirst = false;
	size_t nr = 0;

	if( buflen < ofs )
		return ofs;
	if( buflen - ofs <= len )
		len = buflen - ofs;

	if( print_offsets )
		fprintf(out,"[%d]",(int)ofs);
	fprintf(out,"%s=",p->name);
	while( len > 0 ) {
		const char *value;
		signed char i8;

		if( nr == maxshownlistlen ) {
			fputs(",...",out);
		} else if( nr < maxshownlistlen ) {
			if( notfirst )
				putc(',',out);
			notfirst = true;
			i8 = getCARD8(ofs);
			value = findConstant(p->constants,i8);
			if( value )
				fprintf(out,"%s(%d)",value,(int)i8);
			else
				fprintf(out,"%d",(int)i8);
		}
		len--;ofs++;nr++;
	}
	putc(';',out);
	return ofs;
}

static size_t printLISTofINT16(struct connection *c,const uint8_t *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
	bool notfirst = false;
	size_t nr = 0;

	if( buflen < ofs )
		return ofs;
	if( (buflen - ofs)/2 <= len )
		len = (buflen - ofs)/2;

	if( print_offsets )
		fprintf(out,"[%d]",(int)ofs);
	fprintf(out,"%s=",p->name);
	while( len > 0 ) {
		const char *value;
		int16_t i16;

		if( nr == maxshownlistlen ) {
			fputs(",...",out);
		} else if( nr < maxshownlistlen ) {
			if( notfirst )
				putc(',',out);
			notfirst = true;
			i16 = getCARD16(ofs);
			value = findConstant(p->constants,i16);
			if( value )
				fprintf(out,"%s(%d)",value,(int)i16);
			else
				fprintf(out,"%d",(int)i16);
		}
		len--;ofs+=2;nr++;
	}
	putc(';',out);
	return ofs;
}

static size_t printLISTofINT32(struct connection *c,const uint8_t *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
	bool notfirst = false;
	size_t nr = 0;

	if( buflen < ofs )
		return ofs;
	if( (buflen - ofs)/4 <= len )
		len = (buflen - ofs)/4;

	if( print_offsets )
		fprintf(out,"[%d]",(int)ofs);
	fprintf(out,"%s=",p->name);
	while( len > 0 ) {
		const char *value;
		int32_t i32;

		if( nr == maxshownlistlen ) {
			fputs(",...",out);
		} else if( nr < maxshownlistlen ) {
			if( notfirst )
				putc(',',out);
			notfirst = true;
			i32 = getCARD32(ofs);
			value = findConstant(p->constants,i32);
			if( value )
				fprintf(out,"%s(%d)",value,(int)i32);
			else
				fprintf(out,"%d",(int)i32);
		}
		len--;ofs+=4;nr++;
	}
	putc(';',out);
	return ofs;
}

static size_t printLISTofUINT8(const uint8_t *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
	bool notfirst = false;
	size_t nr = 0;

	if( buflen < ofs )
		return ofs;
	if( buflen - ofs <= len )
		len = buflen - ofs;

	if( print_offsets )
		fprintf(out,"[%d]",(int)ofs);
	fprintf(out,"%s=",p->name);
	while( len > 0 ) {
		const char *value;
		unsigned char u8;

		if( nr == maxshownlistlen ) {
			fputs(",...",out);
		} else if( nr < maxshownlistlen ) {
			if( notfirst )
				putc(',',out);
			notfirst = true;
			u8 = getCARD8(ofs);
			value = findConstant(p->constants,u8);
			if( value )
				fprintf(out,"%s(%u)",value,(unsigned int)u8);
			else
				fprintf(out,"%u",(unsigned int)u8);
		}
		len--;ofs++;nr++;
	}
	putc(';',out);
	return ofs;
}

static size_t printLISTofUINT16(struct connection *c,const uint8_t *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
	bool notfirst = false;
	size_t nr = 0;

	if( buflen < ofs )
		return ofs;
	if( (buflen - ofs)/2 <= len )
		len = (buflen - ofs)/2;

	if( print_offsets )
		fprintf(out,"[%d]",(int)ofs);
	fprintf(out,"%s=",p->name);
	while( len > 0 ) {
		const char *value;
		uint16_t u16;

		if( nr == maxshownlistlen ) {
			fputs(",...",out);
		} else if( nr < maxshownlistlen ) {
			if( notfirst )
				putc(',',out);
			notfirst = true;
			u16 = getCARD16(ofs);
			value = findConstant(p->constants,u16);
			if( value )
				fprintf(out,"%s(%u)",value,(unsigned int)u16);
			else
				fprintf(out,"%u",(unsigned int)u16);
		}
		len--;ofs+=2;nr++;
	}
	putc(';',out);
	return ofs;
}

static size_t printLISTofUINT32(struct connection *c,const uint8_t *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
	bool notfirst = false;
	size_t nr = 0;

	if( buflen < ofs )
		return ofs;
	if( (buflen - ofs)/4 <= len )
		len = (buflen - ofs)/4;

	if( print_offsets )
		fprintf(out,"[%d]",(int)ofs);
	fprintf(out,"%s=",p->name);
	while( len > 0 ) {
		const char *value;
		uint32_t u32;

		if( nr == maxshownlistlen ) {
			fputs(",...",out);
		} else if( nr < maxshownlistlen ) {
			if( notfirst )
				putc(',',out);
			notfirst = true;
			u32 = getCARD32(ofs);
			value = findConstant(p->constants,u32);
			if( value )
				fprintf(out,"%s(%u)",value,(unsigned int)u32);
			else
				fprintf(out,"%u",(unsigned int)u32);
		}
		len--;ofs+=4;nr++;
	}
	putc(';',out);
	return ofs;
}

static size_t printLISTofVALUE(struct connection *c,const uint8_t *buffer,size_t buflen,const struct parameter *param,unsigned long valuemask, size_t ofs){

	const struct value *v = (const struct value*)param->constants;
	const char *atom;
	bool notfirst = false;

	assert( v != NULL );

	if( ofs > buflen )
		return ofs;
	if( print_offsets )
		fprintf(out,"[%d]",(int)ofs);
	fprintf(out,"%s={",param->name);
	while( buflen > ofs && buflen-ofs >= 4 ) {
		uint32_t u32; uint16_t u16; uint8_t u8;
		int32_t i32; int16_t i16; int8_t i8;
		const char *constant;

		if( v->name == NULL ) /* EOV */
			break;
		if( (valuemask & v->flag) == 0 ) {
			v++;
			continue;
		}
		if( notfirst )
			putc(' ',out);
		notfirst = true;
		/* this is funny, but that is the protocol... */
		u32 = getCARD32(ofs); i32 = u32;
		u16 = u32 & 65535; i16 = u16;
		u8 = u32 & 255; i8 = u8;
		if( v->type >= ft_BITMASK8 ) {
			assert(v->type <= ft_BITMASK32 );
			print_bitfield(v->name,v->constants,u32);
			ofs += 4;v++;
			continue;
		}
		assert( v->type < ft_STORE8 || v->type == ft_ATOM );
		switch( (v->type==ft_ATOM)?2:(v->type % 3) ) {
		 case 0:
			constant = findConstant(v->constants,u8);
			break;
		 case 1:
			constant = findConstant(v->constants,u16);
			break;
		 default:
			constant = findConstant(v->constants,u32);
			break;
		}
		fputs(v->name,out);putc('=',out);
		if( constant != NULL ) {
			fputs(constant,out);
			putc('(',out);
		}
		switch( v->type ) {
		 case ft_INT8:
			 fprintf(out,"%d",(int)i8);
			 break;
		 case ft_INT16:
			 fprintf(out,"%d",(int)i16);
			 break;
		 case ft_INT32:
			 fprintf(out,"%d",(int)i32);
			 break;
		 case ft_UINT8:
			 fprintf(out,"%u",(unsigned int)u8);
			 break;
		 case ft_UINT16:
			 fprintf(out,"%u",(unsigned int)u16);
			 break;
		 case ft_UINT32:
			 fprintf(out,"%u",(unsigned int)u32);
			 break;
		 case ft_ENUM8:
			 if( constant == NULL )
				 fputs("unknown:",out);
		 case ft_CARD8:
			 fprintf(out,"0x%02x",(unsigned int)u8);
			 break;
		 case ft_ENUM16:
			 if( constant == NULL )
				 fputs("unknown:",out);
		 case ft_CARD16:
			 fprintf(out,"0x%04x",(unsigned int)u16);
			 break;
		 case ft_ATOM:
			 fprintf(out,"0x%x",(unsigned int)u32);
			 atom = getAtom(c, u32);
			 if( atom != NULL )
				 fprintf(out,"(\"%s\")", atom);
			 break;
		 case ft_ENUM32:
			 if( constant == NULL )
				 fputs("unknown:",out);
		 case ft_CARD32:
			 fprintf(out,"0x%08x",(unsigned int)u32);
			 break;
		 default:
			 assert(0);
		}
		if( constant != NULL ) {
			putc(')',out);
		}
		ofs += 4; v++;
	}
	putc('}',out);
	/* TODO: print error if flags left or v!=EOV? */
	return ofs;
}

struct stack {
	unsigned long *base;
	int num;
	int ofs;
};

static unsigned long getFromStack(struct stack *stack, size_t depth) {
	assert(stack != NULL && stack->ofs > (int)depth );
	return stack->base[stack->ofs - 1 - depth];
}

static void push(struct stack *stack, unsigned long value) {
	stack->base[stack->ofs] = value;
	stack->ofs++;
	assert(stack->ofs<stack->num);
}
static void pop(struct stack *stack UNUSED, struct stack *oldstack UNUSED) {
}

static size_t print_parameters(struct connection *c,const unsigned char *buffer,unsigned int len, const struct parameter *parameters, bool bigrequest, struct stack *oldstack);

static size_t printLISTofStruct(struct connection *c,const uint8_t *buffer,size_t buflen,const struct parameter *p,size_t count, size_t ofs, struct stack *stack){
	bool notfirst = false;
	/* This is a gross hack: the constants for ft_LISTofStruct are
	 * in reality a parameter structure */
	const struct parameter *substruct = (const void*)p->constants;
	size_t len;
	size_t nr = 0;

	/* and the first item includes the length of an item */
	assert( substruct != NULL && substruct->name == NULL && substruct->offse > 0);
	len = substruct->offse;
	substruct++;

	if( print_offsets )
		fprintf(out,"[%d]",(int)ofs);
	fprintf(out,"%s=",p->name);
	while( buflen > ofs && buflen-ofs >= len && count > 0) {

		if( nr == maxshownlistlen ) {
			fputs(",...",out);
			if( len == 0 )
				ofs = SIZE_MAX;
			break;
		} else if( nr < maxshownlistlen ) {
			if( notfirst )
				putc(',',out);
			notfirst = true;
			putc('{',out);

			print_parameters(c,buffer+ofs,len,substruct,false,stack);

			putc('}',out);
		}
		ofs += len; count--; nr++;
	}
	putc(';',out);
	return ofs;
}
static size_t printLISTofVarStruct(struct connection *c,const uint8_t *buffer,size_t buflen,const struct parameter *p,size_t count, size_t ofs, struct stack *stack){
	bool notfirst = false;
//	size_t ofs = (p->offset<0)?lastofs:p->offset;
	const struct parameter *substruct = (const void*)p->constants;
	size_t len;
	size_t nr = 0;

	/* in this case this is only the minimum value */
	assert( substruct != NULL && substruct->name == NULL && substruct->offse > 0);
	len = substruct->offse;
	substruct++;

	if( print_offsets )
		fprintf(out,"[%d]",(int)ofs);
	fprintf(out,"%s=",p->name);
	while( buflen > ofs && buflen-ofs >= len && count > 0) {
		size_t lentoadd;

		if( nr >= maxshownlistlen ) {
			fputs(",...;",out);
			/* there is nothing here to calculate the rest,
			 * so just return the unreachable */
			return SIZE_MAX;
		}
		if( notfirst ) {
			putc(',',out);
			if( print_offsets )
				fprintf(out,"[%d]",(int)ofs);
		}
		notfirst = true;
		putc('{',out);

		lentoadd = print_parameters(c,buffer+ofs,buflen-ofs,substruct,false,stack);

		putc('}',out);
		ofs += lentoadd; count--; nr++;
	}
	putc(';',out);
	return ofs;
}

/* buffer must have at least 32 valid bytes */
static void print_event(struct connection *c,const unsigned char *buffer);

static size_t print_parameters(struct connection *c,const unsigned char *buffer,unsigned int len, const struct parameter *parameters,bool bigrequest, struct stack *oldstack) {
	const struct parameter *p;
	unsigned long stored = INT_MAX;
	unsigned char format = 0;
	bool printspace = false;
	size_t lastofs = 0;
	struct stack newstack = *oldstack;

	for( p = parameters; p->name != NULL; p++ ) {
		int8_t i8; int16_t i16; int32_t i32;
#ifdef STUPIDCC
		uint8_t u8=0; uint16_t u16=0; uint32_t u32=0;
		unsigned long l=0;
#else
		uint8_t u8; uint16_t u16; uint32_t u32;
		unsigned long l;
#endif
		size_t ofs;
		const char *value;
		const char *atom;
		double d;
		float f;

		if( p->offse == OFS_LATER )
			ofs = lastofs;
		else if( bigrequest && p->offse >= 4 )
			/* jump over 32 bit extended length */
			ofs = p->offse+4;
		else
			ofs = p->offse;

		if( printspace )
			putc(' ',out);
		printspace = true;

		if( p->type == ft_IF8 ) {
			if( ofs < len &&
			  /* some more overloading: */
			  getCARD8(ofs) == (unsigned char)(p->name[0]) )
				p = ((struct parameter *)p->constants)-1;
			printspace = false;
			continue;
		} else if( p->type == ft_IF16 ) {
			if( ofs+1 < len &&
			  getCARD16(ofs) == (unsigned char)(p->name[1])
			  + (unsigned int)0x100*(unsigned char)(p->name[0]))
				p = ((struct parameter *)p->constants)-1;
			printspace = false;
			continue;
		} else if( p->type == ft_IF32 ) {
			if( ofs+3 < len &&
			  getCARD32(ofs) == (unsigned char)(p->name[3])
			  + (((unsigned long)((unsigned char)(p->name[2])))<<8)
			  + (((unsigned long)((unsigned char)(p->name[1])))<<16)
			  + (((unsigned long)((unsigned char)(p->name[0])))<<24) )
				p = ((struct parameter *)p->constants)-1;
			printspace = false;
			continue;
		} else if( p->type == ft_IFATOM ) {
			const char *atomname;
			if( ofs+4 >= len )
				continue;
			atomname = getAtom(c, getCARD32(ofs));
			if( atomname == NULL )
				continue;
			if( strcmp(atomname, p->name) == 0 )
				p = ((struct parameter *)p->constants)-1;
			printspace = false;
			continue;
		}

		switch( p->type ) {
		 case ft_LASTMARKER:
			 if( p->offse == ROUND_32 )
				 lastofs = (lastofs+3)& ~3;
			 else
				 lastofs = ofs;
			 printspace = false;
			 continue;
		 case ft_FORMAT8:
			 if( ofs < len )
				 format = getCARD8(ofs);
			printspace = false;
			 continue;
		 case ft_STRING8:
			lastofs = printSTRING8(buffer,len,p,stored,ofs);
			continue;
		 case ft_LISTofCARD8:
			lastofs = printLISTofCARD8(buffer,len,p,stored,ofs);
			continue;
		 case ft_LISTofCARD16:
			lastofs = printLISTofCARD16(c,buffer,len,p,stored,ofs);
			continue;
		 case ft_LISTofCARD32:
			lastofs = printLISTofCARD32(c,buffer,len,p,stored,ofs);
			continue;
		 case ft_LISTofATOM:
			lastofs = printLISTofATOM(c,buffer,len,p,stored,ofs);
			continue;
		 case ft_LISTofUINT8:
			lastofs = printLISTofUINT8(buffer,len,p,stored,ofs);
			continue;
		 case ft_LISTofUINT16:
			lastofs = printLISTofUINT16(c,buffer,len,p,stored,ofs);
			continue;
		 case ft_LISTofUINT32:
			lastofs = printLISTofUINT32(c,buffer,len,p,stored,ofs);
			continue;
		 case ft_LISTofINT8:
			lastofs = printLISTofINT8(buffer,len,p,stored,ofs);
			continue;
		 case ft_LISTofINT16:
			lastofs = printLISTofINT16(c,buffer,len,p,stored,ofs);
			continue;
		 case ft_LISTofINT32:
			lastofs = printLISTofINT32(c,buffer,len,p,stored,ofs);
			continue;
		 case ft_LISTofFormat:
			switch( format ) {
			 case 8:
				lastofs = printLISTofCARD8(buffer,len,p,stored,ofs);
				break;
			 case 16:
				lastofs = printLISTofCARD16(c,buffer,len,p,stored,ofs);
				break;
			 case 32:
				lastofs = printLISTofCARD32(c,buffer,len,p,stored,ofs);
				break;
			 default:
				lastofs = ofs;
				break;
			}
			continue;
		 case ft_Struct:
			printLISTofStruct(c,buffer,len,p,1,ofs,&newstack);
			continue;
		 case ft_LISTofStruct:
			lastofs = printLISTofStruct(c,buffer,len,p,stored,ofs,&newstack);
			continue;
		 case ft_LISTofVarStruct:
			lastofs = printLISTofVarStruct(c,buffer,len,p,stored,ofs,&newstack);
			continue;
		 case ft_LISTofVALUE:
			lastofs = printLISTofVALUE(c,buffer,len,p,stored,ofs);
			continue;
		 case ft_FIXED:
			if( ofs + 4 > len )
				continue;
			if( print_offsets )
				fprintf(out,"[%d]",(int)ofs);
			fputs(p->name,out);putc('=',out);
			i32 = getCARD32(ofs);
			d = i32 / 65536.0;
			fprintf(out,"%.6f", d);
			continue;
		 case ft_LISTofFIXED:
			lastofs = printLISTofFIXED(c,buffer,len,p,stored,ofs);
			continue;
		 case ft_FLOAT32:
			if( ofs + 4 > len )
				continue;
			if( print_offsets )
				fprintf(out,"[%d]",(int)ofs);
			fputs(p->name,out);putc('=',out);
			/* how exactly is this float transfered? */
			u32 = getCARD32(ofs);
			memcpy(&f, &u32, 4);
			fprintf(out,"%f", f);
			continue;
		 case ft_LISTofFLOAT32:
			lastofs = printLISTofFLOAT32(c,buffer,len,p,stored,ofs);
			continue;
		 case ft_FRACTION16_16:
			if( ofs + 4 > len )
				continue;
			if( print_offsets )
				fprintf(out,"[%d]",(int)ofs);
			fputs(p->name,out);putc('=',out);
			i16 = getCARD16(ofs);
			u16 = getCARD16(ofs + 2);
			fprintf(out,"%hd/%hu", i16, u16);
			continue;
		 case ft_FRACTION32_32:
			if( ofs + 8 > len )
				continue;
			if( print_offsets )
				fprintf(out,"[%d]",(int)ofs);
			fputs(p->name,out);putc('=',out);
			i32 = getCARD32(ofs);
			u32 = getCARD32(ofs + 4);
			fprintf(out,"%d/%u", i32, u32);
			continue;
		 case ft_EVENT:
			if( len >= ofs + 32 )
				print_event(c,buffer+ofs);
			continue;
		 case ft_ATOM:
			if( ofs + 4 > len )
				continue;
			if( print_offsets )
				fprintf(out,"[%d]",(int)ofs);
			fputs(p->name,out);putc('=',out);
			u32 = getCARD32(ofs);
			value = findConstant(p->constants,u32);
			atom = getAtom(c, u32);
			if( value != NULL )
				fprintf(out,"%s(0x%x)",value, (unsigned int)u32);
			else if( atom == NULL )
				fprintf(out,"0x%x(unrecognized atom)",(unsigned int)u32);
			else
				fprintf(out,"0x%x(\"%s\")",(unsigned int)u32, atom);
			continue;
		 case ft_BE32:
			if( ofs + 4 > len )
				continue;
			fputs(p->name,out);putc('=',out);
			fprintf(out,"0x%08x",(unsigned int)getBE32(ofs));
			continue;
		 case ft_GET:
			stored = getFromStack(&newstack,p->offse);
			printspace = false;
			continue;
		 case ft_DECREMENT_STORED:
			if( stored < p->offse )
				stored = 0;
			else
				stored -= p->offse;
			printspace = false;
			continue;
		 case ft_SET:
			stored = p->offse;
			printspace = false;
			continue;
		 default:
			break;
		}
		assert( p->type <= ft_BITMASK32);

		switch( p->type % 3) {
		 case 0:
			 if( (ofs+1) > len )
				 /* this field is missing */
				 continue;
			 u8 = getCARD8(ofs);
			 l = u8;
			 break;
		 case 1:
			 if( (ofs+2) > len )
				 /* this field is missing */
				 continue;
			 u16 = getCARD16(ofs);
			 l = u16;
			 break;
		 case 2:
			 if( (ofs+4) > len )
				 /* this field is missing */
				 continue;
			 u32 = getCARD32(ofs);
			 l = u32;
			 break;
		}
		if( p->type >= ft_BITMASK8 ) {
			assert(p->type <= ft_BITMASK32 );
			print_bitfield(p->name,p->constants,l);
			continue;
		}
		if( p->type >= ft_PUSH8 ) {
			assert(p->type <= ft_PUSH32 );
			push(&newstack,l);
			if( !print_counts) {
				printspace = false;
				continue;
			}
		} else if( p->type >= ft_STORE8 ) {
			assert(p->type <= ft_STORE32);
			stored = l;
			if( !print_counts) {
				printspace = false;
				continue;
			}
		}
		value = findConstant(p->constants,l);
		if( print_offsets )
			fprintf(out,"[%d]",(int)ofs);
		fputs(p->name,out);putc('=',out);
		if( value != NULL ) {
			fputs(value,out);
			putc('(',out);
		}
		switch( p->type ) {
		 case ft_INT8:
			 i8 = u8;
			 fprintf(out,"%d",(int)i8);
			 break;
		 case ft_INT16:
			 i16 = u16;
			 fprintf(out,"%d",(int)i16);
			 break;
		 case ft_INT32:
			 i32 = u32;
			 fprintf(out,"%d",(int)i32);
			 break;
		 case ft_PUSH8:
		 case ft_STORE8:
		 case ft_UINT8:
			 fprintf(out,"%u",(unsigned int)u8);
			 break;
		 case ft_PUSH16:
		 case ft_STORE16:
		 case ft_UINT16:
			 fprintf(out,"%u",(unsigned int)u16);
			 break;
		 case ft_PUSH32:
		 case ft_STORE32:
		 case ft_UINT32:
			 fprintf(out,"%u",(unsigned int)u32);
			 break;
		 case ft_ENUM8:
			 if( value == NULL )
				 fputs("unknown:",out);
		 case ft_CARD8:
			 fprintf(out,"0x%02x",(unsigned int)u8);
			 break;
		 case ft_ENUM16:
			 if( value == NULL )
				 fputs("unknown:",out);
		 case ft_CARD16:
			 fprintf(out,"0x%04x",(unsigned int)u16);
			 break;
		 case ft_ENUM32:
			 if( value == NULL )
				 fputs("unknown:",out);
		 case ft_CARD32:
			 fprintf(out,"0x%08x",(unsigned int)u32);
			 break;
		 case ft_BITMASK8:
		 case ft_BITMASK16:
		 case ft_BITMASK32:
		 case ft_STRING8:
		 case ft_FORMAT8:
		 case ft_LISTofCARD8:
		 case ft_LISTofCARD16:
		 case ft_LISTofCARD32:
		 case ft_LISTofATOM:
		 case ft_LISTofUINT8:
		 case ft_LISTofUINT16:
		 case ft_LISTofUINT32:
		 case ft_LISTofINT8:
		 case ft_LISTofINT16:
		 case ft_LISTofINT32:
		 case ft_LISTofFormat:
		 case ft_LISTofVALUE:
		 case ft_Struct:
		 case ft_LISTofStruct:
		 case ft_LISTofVarStruct:
		 case ft_IF8:
		 case ft_IF16:
		 case ft_IF32:
		 case ft_IFATOM:
		 case ft_BE32:
		 case ft_ATOM:
		 case ft_LASTMARKER:
		 case ft_GET:
		 case ft_DECREMENT_STORED:
		 case ft_SET:
		 case ft_EVENT:
		 case ft_FRACTION16_16:
		 case ft_FRACTION32_32:
		 case ft_FIXED:
		 case ft_LISTofFIXED:
		 case ft_FLOAT32:
		 case ft_LISTofFLOAT32:
			 assert(0);
		}
		if( value != NULL ) {
			putc(')',out);
		}
	}
	pop(&newstack,oldstack);
	return lastofs;
}

/* replace ra(GrabButton) in requests.inc by ra2(GrabButton)
 * and add this function and all
 * GrabButton requests will have an AnyModifier set before
 * being forwarded to the server... >:-]
 *
static bool requestGrabButton(struct connection *c, bool pre, bool bigrequest,struct expectedreply *reply) {
	if( !pre )
		return false;
	if( c->bigendian )
		c->clientbuffer[22] |= 0x80;
	else
		c->clientbuffer[23] |= 0x80;
	return false;
}

*/

bool requestQueryExtension(struct connection *c, bool pre, bool bigrequest UNUSED, struct expectedreply *reply) {
	if( pre )
		return false;
	if( reply == NULL)
		return false;
	if( c->clientignore <= 8 )
		return false;
	reply->datatype = 0;
	reply->data = (void*)find_extension(c->clientbuffer+8,c->clientignore-8);
	if( reply->data == NULL ) {
		size_t len = c->clientignore-8;
		if( len > clientCARD16(4) )
			len = clientCARD16(4);
		reply->data = register_unknown_extension(c, c->clientbuffer+8, len);
		reply->datatype = 1;
	}
	return false;
}

bool requestInternAtom(struct connection *c, bool pre, bool bigrequest UNUSED, struct expectedreply *reply) {
	uint16_t len;
	if( pre )
		return false;
	if( reply == NULL)
		return false;
	if( c->clientignore <= 8 )
		return false;
	len = clientCARD16(4);
	if( c->clientignore < (unsigned int)8 + len)
		return false;
	reply->data = newAtom((const char*)c->clientbuffer+8,len);
	return false;
}

/* Reactions to some replies */

void replyListFontsWithInfo(struct connection *c,bool *ignore,bool *dontremove,int datatype UNUSED,void *data UNUSED) {
	unsigned int seq = serverCARD16(2);
	if( serverCARD8(1) == 0 ) {

		startline(c, TO_CLIENT, "%04x:%u: Reply to ListFontsWithInfo: end of list\n", seq, c->serverignore);
		*ignore = true;
	} else
		*dontremove = true;
}
void replyQueryExtension(struct connection *c,bool *ignore UNUSED,bool *dontremove UNUSED,int datatype,void *data) {
	/* nothing to do if the extension is not available */
	if( serverCARD8(8) == 0)
		return;

	if( datatype == 1 && data != NULL ) {
		struct unknownextension *n, **e = &c->waiting;
		while( *e != NULL && *e != data )
			e = &(*e)->next;
		if( *e != NULL ) {
			data = NULL;
			n = *e; *e = n->next;
			n->next = c->unknownextensions;
			c->unknownextensions = n;
			n->major_opcode = serverCARD8(9);
			n->first_event = serverCARD8(10);
			n->first_error = serverCARD8(11);
		}
	}
	if( datatype == 0 && data != NULL ) {
		struct usedextension *u;
		u = malloc(sizeof(struct usedextension));
		if( u == NULL )
			abort();
		u->next = c->usedextensions;
		u->extension = data;
		u->major_opcode = serverCARD8(9);
		u->first_event = serverCARD8(10);
		u->first_error = serverCARD8(11);
		c->usedextensions = u;
	}
	if( denyallextensions ) {
		/* disable all extensions */
		c->serverbuffer[8] = 0;
	}
}

void replyInternAtom(struct connection *c,bool *ignore UNUSED,bool *dontremove UNUSED,int datatype UNUSED,void *data) {
	uint32_t atom;
	if( data == NULL )
		return;
	atom = serverCARD32(8);
	internAtom(c, atom, data);
}

#define ft_COUNT8 ft_STORE8
#define ft_COUNT16 ft_STORE16
#define ft_COUNT32 ft_STORE32
#define RESET_COUNTER	{ INT_MAX,	"",		ft_SET,		NULL}
#define SET_COUNTER(cnt)	{ cnt,	"",		ft_SET,		NULL}

const struct request *requests;
size_t num_requests;
const struct parameter *unexpected_reply;

static inline void free_expectedreplylist(struct expectedreply *r) {

	while( r != NULL ) {
		struct expectedreply *n = r->next;
		free(r);
		r = n;
	}
}

static inline const struct extension *find_extension_by_opcode(struct connection *c, unsigned char req) {
	struct usedextension *u;

	for( u = c->usedextensions; u != NULL ; u = u->next ) {
		if( req != u->major_opcode )
			continue;
		return u->extension;
	}
	return NULL;
}

static inline const char *find_unknown_extension(struct connection *c, unsigned char req) {
	struct unknownextension *e;

	for( e = c->unknownextensions ; e != NULL ; e = e->next ) {
		if( req == e->major_opcode ) {
			return e->name;
		}
	}
	return NULL;
}

static inline const struct request *find_extension_request(struct connection *c,unsigned char req,unsigned char subreq,const char **extension) {
	const struct extension *e;
	const char *name;

	e = find_extension_by_opcode(c, req);
	if( e != NULL ) {
		*extension = e->name;
		if( subreq < e->numsubrequests )
			return e->subrequests + subreq;
		else
			return NULL;
	}
	name = find_unknown_extension(c, req);
	if( name != NULL )
		*extension = name;
	return NULL;
}

static inline void print_client_request(struct connection *c,bool bigrequest) {
	unsigned char req = clientCARD8(0);
	unsigned char subreq = clientCARD8(1);
	const struct request *r;
	const char *extensionname = "";
	bool ignore;
	size_t len;
	unsigned long stackvalues[30];
	struct stack stack;
	stack.base = stackvalues;
	stack.num = 30;
	stack.ofs = 0;

	len = c->clientignore;
	if( len > c->clientcount )
		len = c->clientcount;

	r = find_extension_request(c,req,subreq,&extensionname);
	if( r == NULL ) {
		if( req < num_requests )
			r = &requests[req];
		else r = &requests[0];
	}
	c->seq++;
	if( r->request_func == NULL )
		ignore = false;
	else
		ignore = r->request_func(c,true,bigrequest,NULL);
	if( !ignore ) {
		const char *name;

		name = r->name;
		if( name == NULL )
			name = "UNKNOWN";
		assert( r->parameters != NULL);
		if( extensionname[0] == '\0' )
			startline(c, TO_SERVER, "%04x:%3u: Request(%hhu): %s ",
				(unsigned int)(c->seq),c->clientignore,
				req, name
		      );
		else
			startline(c, TO_SERVER, "%04x:%3u: %s-Request(%hhu,%hhu): %s ",
				(unsigned int)(c->seq),
				c->clientignore,
				extensionname, req, subreq,
				name
		      );
		if( r->parameters != NULL )
			print_parameters(c, c->clientbuffer, len,
					r->parameters, bigrequest, &stack);
		if( r->request_func != NULL )
			(void)r->request_func(c,false,bigrequest,NULL);
		putc('\n',out);
	}
	if( r->answers != NULL ) {
		/* register an awaited response */
		struct expectedreply *a = malloc(sizeof(struct expectedreply));
		if( a == NULL )
			abort();
		a->next = c->expectedreplies;
		a->seq = c->seq;
		a->from = r;
		if( r->request_func != NULL )
			(void)r->request_func(c,false,bigrequest,a);
		c->expectedreplies = a;
	}
}

static inline void print_server_event(struct connection *c) {

	startline(c, TO_CLIENT, "%04llx: Event ", (unsigned long long)c->seq);
	print_event(c,c->serverbuffer);
	putc('\n',out);
}


static inline void print_server_reply(struct connection *c) {
	unsigned int cmd,seq;
	struct expectedreply *replyto,**lastp;
	size_t len;
	unsigned long stackvalues[30];
	struct stack stack;
	stack.base = stackvalues;
	stack.num = 30;
	stack.ofs = 0;

	len = c->serverignore;
	if( len > c->servercount )
		len = c->servercount;

	cmd = serverCARD8(1);
	seq = serverCARD16(2);
	for( lastp = &c->expectedreplies ;
			(replyto=*lastp) != NULL ; lastp=&replyto->next){
		if( (replyto->seq & 0xFFFF ) == seq ) {
			bool ignore = false, dontremove = false;

			assert( replyto->from != NULL);
			if( replyto->from->reply_func != NULL )
				replyto->from->reply_func(c,&ignore,&dontremove,replyto->datatype,replyto->data);

			if( !ignore ) {
				const char *name = replyto->from->name;

				if( name == NULL )
					name = "UNKNOWN";
				startline(c, TO_CLIENT, "%04x:%u: Reply to %s: ",
						seq,
						(unsigned int)c->serverignore,
						name);
				print_parameters(c, c->serverbuffer, len,
					replyto->from->answers, false, &stack);
				putc('\n',out);
			}
			if( !dontremove ) {
				*lastp = replyto->next;
				if( replyto->next != NULL ) {
					startline(c, TO_CLIENT, " still waiting for reply to seq=%04llx\n", (unsigned long long)replyto->next->seq);
				}
				free(replyto);
			}
			return;
		}
	}
	startline(c, TO_CLIENT, "%04x:%u: unexpected Reply: ",
			seq, (unsigned int)c->serverignore);
	print_parameters(c, c->serverbuffer, len,
			unexpected_reply, false, &stack);
	putc('\n',out);
}

const char * const *errors;
size_t num_errors;

static inline void print_server_error(struct connection *c) {
	unsigned int cmd = serverCARD8(1);
	struct usedextension *u;
	const char *errorname;
	uint16_t seq;
	struct expectedreply *replyto,**lastp;
	if( cmd < num_errors )
		errorname = errors[cmd];
	else {
		errorname = "unknown";
		for( u = c->usedextensions; u != NULL ; u = u->next ) {
			unsigned int i;
			if( cmd < u->first_error )
				continue;
			i = cmd-u->first_error;
			if( i >= u->extension->numerrors )
				continue;
			errorname = u->extension->errors[i];
			break;
		}

	}
	seq = (unsigned int)serverCARD16(2);
	startline(c, TO_CLIENT, "%04x:Error %hhu=%s: major=%u, minor=%u, bad=%u\n",
			seq,
			cmd,
			errorname,
			(int)serverCARD8(10),
			(int)serverCARD16(8),
			(int)serverCARD32(4));
	/* don't wait for any answer */
	for( lastp = &c->expectedreplies ;
			(replyto=*lastp) != NULL ; lastp=&replyto->next){
		if( (replyto->seq & 0xFFFF ) == seq ) {
			*lastp = replyto->next;
			free(replyto);
			return;
		}
	}
}

const struct parameter *setup_parameters;

void parse_client(struct connection *c) {
	size_t l;
	bool bigrequest;

	switch( c->clientstate ) {
	 case c_start:
		 if( c->clientcount < 12 ) {
			 return;
		 }
		 if( c->clientbuffer[0] == 'B' )
			 c->bigendian = true;
		 else if( c->clientbuffer[0] == 'l' )
			 c->bigendian = false;
		 else  {
			startline(c, TO_SERVER, " Byteorder (%d='%c') is neither 'B' nor 'l', ignoring all further data!", (int)c->clientbuffer[0],c->clientbuffer[0]);
			c->clientstate = c_amlost;
			c->serverstate = s_amlost;
			return;
		 }
		 l = 12 + padded(clientCARD16(6)) + padded(clientCARD16(8));
		 if( c->clientcount < l ) {
			 /* wait for auth data first */
			 return;
		 }
		 c->clientignore =  l;

		 startline(c, TO_SERVER, " am %s want %d:%d authorising with '%*s' of length %d\n",
				 c->bigendian?"msb-first":"lsb-first",
				 (int)clientCARD16(2),
				 (int)clientCARD16(4),
				 (int)clientCARD16(6),
				 &c->clientbuffer[12],
				 (int)clientCARD16(8));
		 c->clientstate = c_normal;
		 return;
	 case c_normal:
		 if( c->clientcount < 4 ) {
			 startline(c, TO_SERVER, " Warning: Waiting for rest of package (yet only got %u)!\n", c->clientcount);
			 return;
		 }
		 l = 4*clientCARD16(2);
		 if( l == 0 ) {
			 if( c->clientcount < 8 ) {
				 startline(c, TO_SERVER, " Warning: Waiting for rest of package (yet only got %u)!\n", c->clientcount);
				 return;
			 }
			 l = 4*clientCARD32(4);
			 bigrequest = true;
		 } else
			 bigrequest = false;
		 if( c->clientcount == sizeof(c->clientbuffer) )
			 startline(c, TO_SERVER, " Warning: buffer filled!\n");
		 else if( c->clientcount < l ) {
			 startline(c, TO_SERVER, " Warning: Waiting for rest of package (yet got %u of %u)!\n", c->clientcount,(unsigned int)l);
			 return;
		 }
		 c->clientignore = l;
		 print_client_request(c,bigrequest);
		 return;
	 case c_amlost:
		 c->clientignore = c->clientcount;
		 return;
	}
	assert(false);
}

void parse_server(struct connection *c) {
	/* additional len in multiple of 4 */
	unsigned int len,cmd;

	if( c->serverstate == s_amlost ) {
		c->serverignore = c->servercount;
		return;
	}
	if( c->servercount < 8 )
		return;
	switch( c->serverstate ) {
	 case s_start:
		 len = serverCARD16(6);
		 if( c->servercount/4 < 2+len )
			 return;
		 c->serverignore = 8+4*len;
		 cmd = serverCARD8(0);
		 switch( cmd ) {
		  case 0:
			  startline(c, TO_CLIENT, " Failed, version is %d:%d reason is '%*s'.\n",
					 (int)serverCARD16(2),
					 (int)serverCARD16(4),
					 (int)(4*len),
					 &c->serverbuffer[8]);
			  break;
		  case 2:
			  startline(c, TO_CLIENT, " More authentication needed, reason is '%*s'.\n",
					 (int)(4*len),
					 &c->serverbuffer[8]);
			  break;
		  case 1:
			  startline(c, TO_CLIENT, " Success, version is %d:%d ",
					 (int)serverCARD16(2),
					 (int)serverCARD16(4));
			  {
				  unsigned long stackvalues[30];
				  struct stack stack;
				  stack.base = stackvalues;
				  stack.num = 30;
				  stack.ofs = 0;

				  print_parameters(c, c->serverbuffer,
						  c->serverignore,
						  setup_parameters,
						  false, &stack);
				  putc('\n',out);
			  }
			  c->serverstate = s_normal;
			  break;
		 }
		 return;
	 case s_normal:
		if( c->servercount < 32 )
			return;
		switch( c->serverbuffer[0] ) {
		 case 0: /* Error */
			 c->serverignore = 32;
			 print_server_error(c);
			 break;
		 case 1: /* Reply */
			 c->serverignore = 32 + 4*serverCARD32(4);
			 print_server_reply(c);
			 break;
		 default:
			c->serverignore = 32;
			print_server_event(c);
		}
		return;
	 case s_amlost:
		break;
	}
	assert(false);
}

const struct event *events;
size_t num_events;

void print_generic_event(struct connection *c, const unsigned char *buffer, const struct event *event) {
	unsigned long stackvalues[30];
	struct stack stack;
	stack.base = stackvalues;
	stack.num = 30;
	stack.ofs = 0;
	uint8_t opcode = getCARD8(1);
	const struct extension *extension;

	extension = find_extension_by_opcode(c, opcode);
	if( extension != NULL ) {
		fprintf(out, "%s(%hhu) ", extension->name, opcode);
		// TODO: get description from format...
		print_parameters(c, buffer, 32, event->parameters, false, &stack);
	} else {
		const char *name = find_unknown_extension(c, opcode);
		if( name != NULL ) {
			fprintf(out, "%s(%hhu) ", name, opcode);
		} else {
			fprintf(out, "unknown extension %hhu ", opcode);
		}
		print_parameters(c, buffer, 32, event->parameters, false, &stack);
	}
}

static void print_event(struct connection *c,const unsigned char *buffer) {
	const struct event *event;
	uint8_t code = getCARD8(0);
	unsigned long stackvalues[30];
	struct stack stack;
	stack.base = stackvalues;
	stack.num = 30;
	stack.ofs = 0;

	if( (code & 0x80) != 0 )
		fputs("(generated) ",out);
	code &= 0x7F;
	if( code <= 1 || code > num_events ) {
		struct usedextension *u = c->usedextensions;
		while( u != NULL ) {
			if( code >= u->first_event &&
			    code-u->first_event < u->extension->numevents) {
				event = u->extension->events +
						(code-u->first_event);
				break;
			}
			u = u->next;
		}
		if( u == NULL ) {
			fprintf(out,"unknown code %hhu",code);
			return;
		} else {
			fputs(u->extension->name, out);
			putc('-', out);
		}
	} else
		event = &events[code];
	fprintf(out,"%s(%hhu) ",event->name,code);
	if( event->handler == NULL ) {
		print_parameters(c,buffer,32,event->parameters,false,&stack);
	} else {
		event->handler(c, buffer, event);
	}
}

const struct extension *extensions;
size_t num_extensions;

const struct extension *find_extension(const uint8_t *name,size_t len) {
	unsigned int i;
	for( i = 0 ; i < num_extensions ; i++ ) {
		if( len < extensions[i].namelen )
			continue;
// TODO: why only compare up the length here?
		if( strncmp((const char*)extensions[i].name,(const char*)name,len) == 0 )
			return extensions + i;
	}

	return NULL;
}
