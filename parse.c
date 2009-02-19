/*  This file is part of "xtrace"
 *  Copyright (C) 2005,2006 Bernhard R. Link
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
#include <values.h>
#include <stdint.h>
#include <sys/types.h>
#include <limits.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/select.h>
#include <unistd.h>

#include "xtrace.h"

static const bool print_counts = false;
static const bool print_offsets = false;

static inline unsigned int padded(unsigned int s) {
	return (s+3)&(~3);
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

#define getBE32(ofs) (((buffer[ofs]*256+buffer[ofs+1])*256+buffer[ofs+2])*256+buffer[ofs+4])

#define NUM(array) (sizeof(array)/sizeof(array[0]))

typedef const unsigned char u8;

struct constant {
	unsigned long value;
	const char *name;
};

typedef bool request_func(struct connection*,bool,bool,struct expectedreply *);
typedef void reply_func(struct connection*,bool*,bool*,int,void*);

struct request {
	const char *name;
	const struct parameter *parameters;
	const struct parameter *answers;

	request_func *request_func;
	reply_func *reply_func;
};
struct event {
	const char *name;
	const struct parameter *parameters;
};

struct extension {
	const char *name;
	size_t namelen;
	const struct request *subrequests;
	unsigned char numsubrequests;
	const struct event *events;
	unsigned char numevents;
	const char **errors;
	unsigned char numerrors;
};

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

struct extension *find_extension(u8 *name,size_t len);

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

struct parameter {
	/* The offset within the event, request, reply or Struct this
	 * applies to. If OFS_LATER it is after the last list item
	 * in this parameter-list. */
	size_t offse;
	const char *name;
	enum fieldtype {
		/* signed endian specific: */
		ft_INT8, ft_INT16, ft_INT32,
		/* unsigned decimal endian specific: */
		ft_UINT8, ft_UINT16, ft_UINT32,
		/* unsigned hex endian specific: */
		ft_CARD8, ft_CARD16, ft_CARD32,
		/* enums (not in constant list is error): */
		ft_ENUM8, ft_ENUM16, ft_ENUM32,
		/* counts for following strings, lists, ...
		 * value-mask for LISTofFormat */
		ft_STORE8, ft_STORE16, ft_STORE32,
		/* to be ft_GET later into the store register */
		ft_PUSH8, ft_PUSH16, ft_PUSH32,
		/* bitfields: multiple values are possible */
		ft_BITMASK8, ft_BITMASK16, ft_BITMASK32,
		/* Different forms of lists: */
		/*	- boring ones */
		ft_STRING8, ft_LISTofCARD32, ft_LISTofATOM,
		ft_LISTofCARD8, ft_LISTofCARD16,
		ft_LISTofUINT8, ft_LISTofUINT16,
		ft_LISTofUINT32,
		/*	- one of the above depening on last FORMAT */
		ft_LISTofFormat,
		/*	- iterate of list description in constants field */
		ft_LISTofStruct,
		/*	- same but length is mininum length and
		 *	  actual length is taken from end of last list
		 *	  or LASTMARKER */
		ft_LISTofVarStruct,
		/*	- like ENUM for last STORE, but constants
		 *	  are of type (struct value*) interpreteted at this
		 *	  offset */
		ft_LISTofVALUE,
		/* an LISTofStruct with count = 1 */
		ft_Struct,
		/* specify bits per item for LISTofFormat */
		ft_FORMAT8,
		/* an event
		 * (would have also been possible with Struct and many IF)*/
		ft_EVENT,
		/* jump to other parameter list if matches */
		ft_IF8,
		/* jump to other parameter list if matches atom name */
		ft_IFATOM,
		/* set end of last list manually, (for LISTofVarStruct) */
		ft_LASTMARKER,
		/* a ft_CARD32 looking into the ATOM list */
		ft_ATOM,
		/* always big endian */
		ft_BE32,
		/* get the #ofs value from the stack. (0 is the last pushed) */
		ft_GET,
		/* a fixed-point number 16+16 bit */
		ft_FIXED,
		/* a list of those */
		ft_LISTofFIXED
		} type;
	const struct constant *constants;
};

static size_t printSTRING8(u8 *buffer,size_t buflen,const struct parameter *p,size_t len,size_t ofs){
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

static size_t printLISTofCARD8(u8 *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
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

static size_t printLISTofCARD16(struct connection *c,u8 *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
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

static size_t printLISTofCARD32(struct connection *c,u8 *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
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

static size_t printLISTofFIXED(struct connection *c,u8 *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
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
		double d;

		if( nr == maxshownlistlen ) {
			fputs(",...",out);
		} else if( nr < maxshownlistlen ) {
			if( notfirst )
				putc(',',out);
			notfirst = true;
			u32 = getCARD32(ofs);
			d = u32 / 65536.0;
			fprintf(out,"%.6f", d);
		}
		len--;ofs+=4;nr++;
	}
	putc(';',out);
	return ofs;
}

static size_t printLISTofATOM(struct connection *c,u8 *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
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

static size_t printLISTofUINT8(u8 *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
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
				fprintf(out,"%s(%d)",value,(unsigned int)u8);
			else
				fprintf(out,"%d",(unsigned int)u8);
		}
		len--;ofs++;nr++;
	}
	putc(';',out);
	return ofs;
}

static size_t printLISTofUINT16(struct connection *c,u8 *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
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
				fprintf(out,"%s(%d)",value,(unsigned int)u16);
			else
				fprintf(out,"%d",(unsigned int)u16);
		}
		len--;ofs+=2;nr++;
	}
	putc(';',out);
	return ofs;
}

static size_t printLISTofUINT32(struct connection *c,u8 *buffer,size_t buflen,const struct parameter *p,size_t len, size_t ofs){
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
				fprintf(out,"%s(%x)",value,(unsigned int)u32);
			else
				fprintf(out,"%x",(unsigned int)u32);
		}
		len--;ofs+=4;nr++;
	}
	putc(';',out);
	return ofs;
}

struct value {
	unsigned long flag;
	/* NULL means EndOfValues */
	const char *name;
	/* only elementary type (<= ft_BITMASK32 are allowed ), */
	enum fieldtype type;
	const struct constant *constants;
};

static size_t printLISTofVALUE(struct connection *c,u8 *buffer,size_t buflen,const struct parameter *param,unsigned long valuemask, size_t ofs){

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

static size_t printLISTofStruct(struct connection *c,u8 *buffer,size_t buflen,const struct parameter *p,size_t count, size_t ofs, struct stack *stack){
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
static size_t printLISTofVarStruct(struct connection *c,u8 *buffer,size_t buflen,const struct parameter *p,size_t count, size_t ofs, struct stack *stack){
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
		if( notfirst )
			putc(',',out);
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
	bool notfirst = false;
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

		if( p->offse == OFS_LATER )
			ofs = lastofs;
		else if( bigrequest && p->offse >= 4 )
			/* jump over 32 bit extended length */
			ofs = p->offse+4;
		else
			ofs = p->offse;

		if( notfirst )
			putc(' ',out);
		notfirst = true;

		if( p->type == ft_IF8 ) {
			if( ofs < len &&
			  /* some more overloading: */
			  getCARD8(ofs) == (unsigned char)(p->name[0]) )
				p = ((struct parameter *)p->constants)-1;
			continue;
		} else if( p->type == ft_IFATOM ) {
			const char *atom;
			if( ofs+4 >= len )
				continue;
			atom = getAtom(c, getCARD32(ofs));
			if( atom == NULL )
				continue;
			if( strcmp(atom, p->name) == 0 )
				p = ((struct parameter *)p->constants)-1;
			continue;
		}

		switch( p->type ) {
		 case ft_LASTMARKER:
			 if( p->offse == ROUND_32 )
				 lastofs = (lastofs+3)& ~3;
			 else
				 lastofs = ofs;
			 continue;
		 case ft_FORMAT8:
			 if( ofs < len )
				 format = getCARD8(ofs);
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
			u32 = getCARD32(ofs);
			d = u32 / 65536.0;
			fprintf(out,"%.6f", d);
			continue;
		 case ft_LISTofFIXED:
			lastofs = printLISTofFIXED(c,buffer,len,p,stored,ofs);
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
			continue;
		 default:
			break;
		}
		assert( p->type <= ft_BITMASK32);

		if( ((ofs+4)&~3) > len )
			/* this field is missing */
			continue;
		switch( p->type % 3) {
		 case 0:
			 u8 = getCARD8(ofs);
			 l = u8;
			 break;
		 case 1:
			 u16 = getCARD16(ofs);
			 l = u16;
			 break;
		 case 2:
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
			if( !print_counts)
				continue;
		} else if( p->type >= ft_STORE8 ) {
			assert(p->type <= ft_STORE32);
			stored = l;
			if( !print_counts)
				continue;
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
		 case ft_LISTofFormat:
		 case ft_LISTofVALUE:
		 case ft_Struct:
		 case ft_LISTofStruct:
		 case ft_LISTofVarStruct:
		 case ft_IF8:
		 case ft_IFATOM:
		 case ft_BE32:
		 case ft_ATOM:
		 case ft_LASTMARKER:
		 case ft_GET:
		 case ft_EVENT:
		 case ft_FIXED:
		 case ft_LISTofFIXED:
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

static bool requestQueryExtension(struct connection *c, bool pre, bool bigrequest UNUSED, struct expectedreply *reply) {
	if( pre )
		return false;
	if( reply == NULL)
		return false;
	if( c->clientignore <= 8 )
		return false;
	reply->datatype = 0;
	reply->data = find_extension(c->clientbuffer+8,c->clientignore-8);
	if( reply->data == NULL ) {
		size_t len = c->clientignore-8;
		if( len > clientCARD16(4) )
			len = clientCARD16(4);
		reply->data = register_unknown_extension(c, c->clientbuffer+8, len);
		reply->datatype = 1;
	}
	return false;
}

static bool requestInternAtom(struct connection *c, bool pre, bool bigrequest UNUSED, struct expectedreply *reply) {
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

static void replyListFontsWithInfo(struct connection *c,bool *ignore,bool *dontremove,int datatype UNUSED,void *data UNUSED) {
	unsigned int seq = serverCARD16(2);
	if( serverCARD8(1) == 0 ) {

		fprintf(out,"%03d:>:0x%04x:%u: Reply to ListFontsWithInfo: end of list\n", c->id, seq, c->serverignore);
		*ignore = true;
	} else
		*dontremove = true;
}
static void replyQueryExtension(struct connection *c,bool *ignore UNUSED,bool *dontremove UNUSED,int datatype,void *data) {
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

static void replyInternAtom(struct connection *c,bool *ignore UNUSED,bool *dontremove UNUSED,int datatype UNUSED,void *data) {
	uint32_t atom;
	if( data == NULL )
		return;
	atom = serverCARD32(8);
	internAtom(c, atom, data);
}

#define ft_COUNT8 ft_STORE8
#define ft_COUNT16 ft_STORE16
#define ft_COUNT32 ft_STORE32
#include "requests.inc"

static inline void free_expectedreplylist(struct expectedreply *r) {

	while( r != NULL ) {
		struct expectedreply *n = r->next;
		free(r);
		r = n;
	}
}

static inline const struct request *find_extension_request(struct connection *c,unsigned char req,unsigned char subreq,const char **extension) {
	struct usedextension *u;
	struct unknownextension *e;

	for( u = c->usedextensions; u != NULL ; u = u->next ) {
		if( req != u->major_opcode )
			continue;
		*extension = u->extension->name;
		if( subreq < u->extension->numsubrequests )
			return u->extension->subrequests + subreq;
		else
			return NULL;
	}
	for( e = c->unknownextensions ; e != NULL ; e = e->next ) {
		if( req == e->major_opcode ) {
			*extension = e->name;
			break;
		}
	}

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
		if( req < NUM(requests) )
			r = &requests[req];
		else r = &requests[0];
	}
	c->seq++;
	if( r->request_func == NULL )
		ignore = false;
	else
		ignore = r->request_func(c,true,bigrequest,NULL);
	if( !ignore ) {
		if( extensionname[0] == '\0' )
			fprintf(out,"%03d:<:%04x:%3u: Request(%hhu): %s ",
				c->id,(unsigned int)(c->seq),c->clientignore,
				req, r->name
		      );
		else
			fprintf(out,"%03d:<:%04x:%3u: %s-Request(%hhu,%hhu): %s ",
				c->id, (unsigned int)(c->seq),
				c->clientignore,
				extensionname, req, subreq,
				r->name
		      );
		if( r->parameters != NULL )
			print_parameters(c,c->clientbuffer,len,r->parameters, bigrequest, &stack);
		else
			fputs("obsolete without parameter description\n",out);
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

	fprintf(out,"%03d:>:%04llx: Event ",c->id,(unsigned long long)c->seq);
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
				fprintf(out,"%03d:>:0x%04x:%u: Reply to %s: ", c->id, seq, (unsigned int)c->serverignore,replyto->from->name);
				print_parameters(c,
					c->serverbuffer,len,replyto->from->answers,false,&stack);
				putc('\n',out);
			}
			if( !dontremove ) {
				*lastp = replyto->next;
				if( replyto->next != NULL ) {
					fprintf(stderr,"%03d:>: still waiting for reply to seq=%04llx\n",c->id,(unsigned long long)replyto->next->seq);
				}
				free(replyto);
			}
			return;
		}
	}
	fprintf(out,"%03d:>:%04x:%u: unexpected reply\n",
			c->id, seq, c->serverignore);
}

const char *errors[] = {
	"no error","Request","Value","Window",
	"Pixmap","Atom","Cursor","Font",
	"Match","Drawable","Access","Alloc",
	"Colormap","GContext","IDChoice","Name",
	"Length","Implementation"
};

static inline void print_server_error(struct connection *c) {
	unsigned int cmd = serverCARD8(1);
	struct usedextension *u;
	const char *errorname;
	uint16_t seq;
	struct expectedreply *replyto,**lastp;

	if( cmd < NUM(errors) )
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
	fprintf(out,"%03d:>:%x:Error %hhu=%s: major=%u, minor=%u, bad=%u\n",
			c->id,
			seq,
			cmd,
			errorname,
			(int)serverCARD16(8),
			(int)serverCARD8(10),
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
			fprintf(stderr,"%03d:<: Byteorder (%d='%c') is neighter 'B' nor 'l', ignoring all further data!",c->id,(int)c->clientbuffer[0],c->clientbuffer[0]);
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

		 fprintf(out,"%03d:<: am %s want %d:%d authorising with '%*s' of length %d\n",
				 c->id,
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
			 fprintf(out,"%03d:<: Warning: Waiting for rest of package (yet only got %u)!\n",c->id,c->clientcount);
			 return;
		 }
		 l = 4*clientCARD16(2);
		 if( l == 0 ) {
			 if( c->clientcount < 8 ) {
				 fprintf(out,"%03d:<: Warning: Waiting for rest of package (yet only got %u)!\n",c->id,c->clientcount);
				 return;
			 }
			 l = 4*clientCARD32(4);
			 bigrequest = true;
		 } else
			 bigrequest = false;
		 if( c->clientcount == sizeof(c->clientbuffer) )
			 fprintf(out,"%03d:<: Warning: buffer filled!\n",c->id);
		 else if( c->clientcount < l ) {
			 fprintf(out,"%03d:<: Warning: Waiting for rest of package (yet got %u of %u)!\n",c->id,c->clientcount,(unsigned int)l);
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
	len = serverCARD16(6);
	switch( c->serverstate ) {
	 case s_start:
		 if( c->servercount/4 < 2+len )
			 return;
		 c->serverstate = s_normal;
		 c->serverignore = 8+4*len;
		 cmd = serverCARD16(0);
		 switch( cmd ) {
		  case 0:
			  fprintf(out,"%03d:>: Failed, version is %d:%d reason is '%*s'.\n",
					 c->id,
					 (int)serverCARD16(2),
					 (int)serverCARD16(4),
					 (int)(4*len),
					 &c->serverbuffer[8]);
		  case 2:
			  fprintf(out,"%03d:>: More authentication needed, reason is '%*s'.\n",
					 c->id,
					 (int)(4*len),
					 &c->serverbuffer[8]);
		  case 1:
			  fprintf(out,"%03d:>: Success, version is %d:%d-%d.\n",
					 c->id,
					 (int)serverCARD16(2),
					 (int)serverCARD16(4),
					 (int)serverCARD16(8));
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

#include "events.inc"

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
	if( code <= 1 || code > NUM(events) ) {
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
		}
	} else
		event = &events[code];
	fprintf(out,"%s(%hhu) ",event->name,code);
	print_parameters(c,buffer,32,event->parameters,false,&stack);
}

#include "shape.inc"
#include "bigrequest.inc"
#include "render.inc"
#include "randr.inc"
#include "xinerama.inc"
#include "mitshm.inc"
#include "xf86vidmode.inc"
#include "xf86bigfont.inc"
#include "dpms.inc"
#include "saver.inc"
#include "fixes.inc"
#include "damage.inc"

#define EXT(a,b) { a , sizeof(a)-1, \
	extension ## b, NUM(extension ## b), \
	events ## b, NUM(events ## b), \
	errors ## b, NUM(errors ## b)}
struct extension extensions[] = {
	EXT("MIT-SHM",MITSHM),
	EXT("RANDR",RANDR),
	EXT("XINERAMA",XINERAMA),
	EXT("RENDER",RENDER),
	EXT("SHAPE",SHAPE),
	EXT("BIG-REQUESTS",BIGREQUEST),
	EXT("XFree86-VidModeExtension",XF86VidMode),
	EXT("XFree86-Bigfont",XF86Bigfont),
	EXT("DPMS",DPMS),
	EXT("XFIXES",FIXES),
	EXT("DAMAGE",DAMAGE),
	EXT("MIT-SCREEN-SAVER",Saver)
};
#undef EXT

struct extension *find_extension(u8 *name,size_t len) {
	unsigned int i;
	for( i = 0 ; i < NUM(extensions) ; i++ ) {
		if( len < extensions[i].namelen )
			continue;
// TODO: why only compare up the length here?
		if( strncmp((const char*)extensions[i].name,(const char*)name,len) == 0 )
			return extensions + i;
	}

	return NULL;
}

