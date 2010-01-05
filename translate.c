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
#include <errno.h>
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
#include <search.h>

#include "xtrace.h"
#include "parse.h"
#include "stringlist.h"
#include "translate.h"

/* This parses an file to generate the description how packets look like.
*/

enum variable_type { vt_namespace = 0, vt_request, vt_response, vt_event, vt_setup, vt_type, vt_constants, vt_values, vt_struct, vt_COUNT };
static const char * const typename[vt_COUNT] = {
		"namespace", "request", "response", "event", "type", "constants", "values", "struct"};

static const struct base_type {
	const char *name;
	enum fieldtype type;
	unsigned int flags;
	int size;
#define NEEDS_CONSTANTS 1
#define NEEDS_BITMASK 3
#define ALLOWS_CONSTANTS 4
#define USES_STORE 8
#define SETS_STORE 0x10
#define USES_FORMAT 0x20
#define SETS_FORMAT 0x40
#define ELEMENTARY 0x80
#define PUSHES 0x100
#define SETS_NEXT 0x200
#define NEEDS_STORE 0x400
} base_types [] = {
	{ "BITMASK8",		ft_BITMASK8,	NEEDS_BITMASK|ELEMENTARY,	1},
	{ "BITMASK16",		ft_BITMASK16,	NEEDS_BITMASK|ELEMENTARY,	2},
	{ "BITMASK32",		ft_BITMASK32,	NEEDS_BITMASK|ELEMENTARY,	4},
	{ "ENUM8",		ft_ENUM8,	NEEDS_CONSTANTS|ELEMENTARY,	1},
	{ "ENUM16",		ft_ENUM16,	NEEDS_CONSTANTS|ELEMENTARY,	2},
	{ "ENUM32",		ft_ENUM32,	NEEDS_CONSTANTS|ELEMENTARY,	4},
	{ "CARD8",		ft_CARD8,	ALLOWS_CONSTANTS|ELEMENTARY,	1},
	{ "CARD16",		ft_CARD16,	ALLOWS_CONSTANTS|ELEMENTARY,	2},
	{ "CARD32",		ft_CARD32,	ALLOWS_CONSTANTS|ELEMENTARY,	4},
	{ "INT8",		ft_INT8,	ALLOWS_CONSTANTS|ELEMENTARY,	1},
	{ "INT16",		ft_INT16,	ALLOWS_CONSTANTS|ELEMENTARY,	2},
	{ "INT32",		ft_INT32,	ALLOWS_CONSTANTS|ELEMENTARY,	4},
	{ "UINT8",		ft_UINT8,	ALLOWS_CONSTANTS|ELEMENTARY,	1},
	{ "UINT16",		ft_UINT16,	ALLOWS_CONSTANTS|ELEMENTARY,	2},
	{ "UINT32",		ft_UINT32,	ALLOWS_CONSTANTS|ELEMENTARY,	4},
	{ "STRING8",		ft_STRING8,	USES_STORE|SETS_NEXT,	0},
	{ "LISTofCARD8",	ft_LISTofCARD8,	ALLOWS_CONSTANTS|USES_STORE|SETS_NEXT,	0},
	{ "LISTofCARD16",	ft_LISTofCARD16,	ALLOWS_CONSTANTS|USES_STORE|SETS_NEXT,	0},
	{ "LISTofCARD32",	ft_LISTofCARD32,	ALLOWS_CONSTANTS|USES_STORE|SETS_NEXT,	0},
	{ "LISTofUINT8",	ft_LISTofUINT8, ALLOWS_CONSTANTS|USES_STORE|SETS_NEXT,	0},
	{ "LISTofUINT16",	ft_LISTofUINT16,	ALLOWS_CONSTANTS|USES_STORE|SETS_NEXT,	0},
	{ "LISTofUINT32",	ft_LISTofUINT32,	ALLOWS_CONSTANTS|USES_STORE|SETS_NEXT,	0},
	{ "LISTofINT8", 	ft_LISTofINT8, ALLOWS_CONSTANTS|USES_STORE|SETS_NEXT,	0},
	{ "LISTofINT16",	ft_LISTofINT16,	ALLOWS_CONSTANTS|USES_STORE|SETS_NEXT,	0},
	{ "LISTofINT32",	ft_LISTofINT32,	ALLOWS_CONSTANTS|USES_STORE|SETS_NEXT,	0},
	{ "EVENT",		ft_EVENT,	0, 0},
	{ "ATOM",		ft_ATOM,	ALLOWS_CONSTANTS|ELEMENTARY,	4},
	{ "LISTofFormat",	ft_LISTofFormat,	USES_FORMAT|USES_STORE|SETS_NEXT,	0},
	{ "LISTofATOM",		ft_LISTofATOM,		ALLOWS_CONSTANTS|USES_STORE|SETS_NEXT,	0},
	{ "FORMAT8",		ft_FORMAT8,		SETS_FORMAT,	1},
	{ "BE32",		ft_BE32,		ALLOWS_CONSTANTS,	4},
	{ "FRACTION16_16",	ft_FRACTION16_16,	0,	4},
	{ "FIXED",		ft_FIXED,		0,	4},
	{ "LISTofFIXED",	ft_LISTofFIXED,		USES_STORE|SETS_NEXT,	0},
	{ "FLOAT32",		ft_FLOAT32,		0,	4},
	{ "LISTofFLOAT32",    	ft_LISTofFLOAT32,	USES_STORE|SETS_NEXT,	0},
	{ "PUSH8",		ft_PUSH8,		PUSHES,	1},
	{ "PUSH16",		ft_PUSH16,		PUSHES,	2},
	{ "PUSH32",		ft_PUSH16,		PUSHES,	4},
	{ "STORE8",		ft_STORE8,		SETS_STORE,	1},
	{ "STORE16",		ft_STORE16,		SETS_STORE,	2},
	{ "STORE32",		ft_STORE32,		SETS_STORE,	4},
	{ NULL,			0,			0,	0}
};
/* some types are only implicitable buildable: */
static const struct base_type base_type_list_of_value =
	{ "LISTofVALUE",	ft_LISTofVALUE,	NEEDS_STORE,	0};
static const struct base_type base_type_list_of_struct =
	{ "LISTofStruct",	ft_LISTofStruct,	USES_STORE|SETS_NEXT,	0};
static const struct base_type base_type_list_of_varstruct =
	{ "LISTofVarStruct",	ft_LISTofVarStruct,	USES_STORE|SETS_NEXT,	0};
static const struct base_type base_type_struct =
	{ "Struct",		ft_Struct,	0,	-1};
//static const struct base_type base_type_varstruct =
//	{ "VarStruct",		ft_VarStruct,	SETS_NEXT,	0};
#define C(td, f) ((td->flags & f) == f)

struct typespec {
	const struct base_type *base_type;
	/* constants for most, unless values for LISTofVALUE,
	   or struct for Struct and List */
	struct variable *data;
};

struct variable {
	enum variable_type type;
	int refcount;
	union {
		struct unfinished_parameter {
			struct unfinished_parameter *next;
			bool isspecial;
			union {
				struct {
					size_t offse;
					const char *name;
					struct typespec type;
				} regular;
				struct {
					enum fieldtype type;
					size_t offse;
					const char *condition;
					bool isjunction;
					struct unfinished_parameter *iftrue;
					const void *finalized;
				} special;
			};
		} *parameter;
		struct {
			struct constant *constants;
			size_t size;
			bool bitmask;
		} c;
		struct unfinished_value {
			struct unfinished_value *next;
			unsigned long flag;
			const char *name;
			struct typespec type;
		} *values;
		struct typespec t;
	};
	const void *finalized;
};

struct namespace {
	struct namespace *next;
	char *name;
	int refcount;
	char *extension;
	int num_requests;
	struct request_data {
		const char *name;
		int number;
		bool has_response;
		bool unsupported;
		bool special;
		struct variable *request, *response;
	} *requests;
	int num_events;
	struct event_data {
		const char *name;
		int number;
		bool unsupported;
		struct variable *event;
	} *events;
	int num_errors;
	const char **errors;
	struct variable *setup;
	void *variables[vt_COUNT];
	/* namespaces that can be used without prefix: */
	int used_count;
	struct namespace **used;
};

struct varname {
	struct variable *variable;
	char name[];
};

static int compare_variables(const void *a, const void *b) {
	const char *v1 = a, *v2 = b;

	return strcmp(v1 + sizeof(struct varname),
		v2 + sizeof(struct varname));
}

static void variable_unref(struct variable *v);

static inline void typespec_done(struct typespec *t) {
	variable_unref(t->data);
}
static void typespec_copy(struct typespec *dst, const struct typespec *src) {
	*dst = *src;
	if( dst->data != NULL )
		dst->data->refcount++;
}

static void parameter_free(struct unfinished_parameter *parameter) {
	while( parameter != NULL ) {
		struct unfinished_parameter *p = parameter;
		parameter = p->next;
		if( p->isspecial ) {
			parameter_free(p->special.iftrue);
		} else {
			typespec_done(&p->regular.type);
		}
		free(p);
	}
}

static void variable_unref(struct variable *v) {
	if( v == NULL )
		return;
	assert( v->refcount > 0 );
	if( -- (v->refcount) > 0 )
		return;
	if( v->type == vt_values ) {
		while( v->values != NULL ) {
			struct unfinished_value *n = v->values->next;
			typespec_done(&v->values->type);
			free(v->values);
			v->values = n;
		}
	} else if( v->type == vt_constants ) {
		free(v->c.constants);
	} else if( v->type == vt_type ) {
		typespec_done(&v->t);
	} else if( v->type == vt_struct || v->type == vt_request
			|| v->type == vt_setup
			|| v->type == vt_response || v->type == vt_event ) {
		parameter_free(v->parameter);
	} else
		assert( v->type != v->type );
	free(v);
}

#define namespace_unlock(n) do {if(n != NULL ){(n)->refcount--;}} while(0)

struct parser {
	char buffer[300], *position, *last;
	struct namespace *namespaces;
	struct source_file {
		struct source_file *next;
		char *name;
		char *filename;
		FILE *file;
		long lineno;
		struct namespace *namespace;
	} *current;
	struct searchpath_entry {
		struct searchpath_entry *next;
		const char *dir;
		size_t len;
	} *searchpath;
	bool error;
};

static void file_free(struct source_file *current) {
	while( current != NULL ) {
		struct source_file *n = current->next;

		free(current->name);
		free(current->filename);
		if( current->file != NULL )
			(void)fclose(current->file);
		namespace_unlock(current->namespace);
		free(current);
		current = n;
	}
}

static void error(struct parser *parser, const char *fmt, ...) FORMAT(printf,2,3);

static bool get_next_line(struct parser *parser, long firstline) {
	char *p;

	do {
		if( parser->error )
			return false;

		parser->position = parser->buffer;
		parser->last = parser->buffer;
		if( fgets(parser->buffer, sizeof(parser->buffer),
					parser->current->file) == NULL ) {
			int e = ferror(parser->current->file);
			if( e != 0 ) {
				fprintf(stderr,
"Error %d reading from file '%s': %s\n",
						e, parser->current->filename,
						strerror(e));
			} else {
				if( firstline > 0 ) {
					error(parser,
"Unexpected end of file (forgot END (awaited since %ld) and EOF?)", firstline+1);
				}
				error(parser,
"Unexpected end of file (forgot EOF?)");
			}
			parser->error = true;
			return false;
		}
		parser->current->lineno++;
		p = strchr(parser->buffer, '\0');
		while( p-- > parser->buffer &&
				( *p == '\n' || *p == '\r' ||
				  *p == '\t' || *p == ' ' ) )
			*p = '\0';
	} while ( parser->buffer[0] == '#' || parser->buffer[0] == '\0' );
	return true;
}

static bool file_done(struct parser *parser) {
	struct source_file *last_done, *first_unfinished;
	int i, e;

	if( parser->error )
		return false;
	e = ferror(parser->current->file);
	if( e != 0 ) {
		fprintf(stderr,
"Error %d reading from file '%s': %s\n",
				e, parser->current->filename, strerror(e));
		parser->error = true;
		return false;
	}
	i = fclose(parser->current->file);
	parser->current->file = NULL;
	if( i != 0 ) {
		e = errno;
		fprintf(stderr,
"Error %d reading from file '%s': %s\n",
				e, parser->current->filename, strerror(e));
		parser->error = true;
		return false;
	}
	/* check if there is more to do: */
	last_done = parser->current;
	while( last_done->next != NULL && last_done->next->file == NULL )
		last_done = last_done->next;
	first_unfinished = last_done->next;
	if( first_unfinished == NULL )
		return true;
	/* move the first not yet processed file to here: */
	last_done->next = first_unfinished->next;
	first_unfinished->next = parser->current;
	parser->current = first_unfinished;
	return false;
}

static const char *get_const_token(struct parser *parser, bool optional) {
	char *p, *q;

	if( parser->error )
		return NULL;

	p = parser->position;
	while( *p != '\0' && (*p == ' ' || *p == '\t') )
		p++;
	parser->last = p;
	if( *p == '\0' ) {
		if( !optional )
			error(parser, "unexpected end of line");
		return NULL;
	}
	if( *p == '"' ) {
		q = p;
		p++;
		while( *p != '\0' && *p != '"' ) {
			if( *p == '\\' && p[1] != '\0' ) {
				p++;
				if( *p < '0' || *p > '7' )
					*q++ = *p++;
				else {
					*q = *(p++) - '0';
					if( *p >= '0' || *p <= '7' )
						*q = *q * 8 +  *(p++) - '0';
					if( *p >= '0' || *p <= '7' )
						*q = *q * 8 +  *(p++) - '0';
					q++;
				}
			} else {
				*q++ = *p++;
			}
		}
		if( *p != '"' ) {
			error(parser, "Unterminated string!");
			return NULL;
		}
		*q = '\0';
		p++;
	} else {
		while( *p != '\0' && *p != ' ' && *p != '\t' ) {
			if( *p == '#' ) {
				error(parser, "Unescaped '#'");
				return NULL;
			}
			p++;
		}
	}
	while( *p != '\0' && (*p == ' ' || *p == '\t') )
		*(p++) = '\0';
	parser->position = p;
	return parser->last;
}

static void oom(struct parser *parser) {
	if( parser->error )
		return;
	fputs("Out of memory!", stderr);
	parser->error = true;
}

static char *get_token(struct parser *parser, bool optional) {
	const char *v;
	char *p;

       	v = get_const_token(parser, optional);
	if( v == NULL )
		return NULL;

	p = strdup(v);
	if( p == NULL ) {
		oom(parser);
	}
	return p;
}

static char *get_token_with_len(struct parser *parser, size_t *l) {
	char *p;

	if( parser->error )
		return NULL;

	p = parser->position;
	parser->last = p;
	if( *p == '\0' ) {
		error(parser, "unespected end of line");
		return NULL;
	}
	while( *p != '\0' && *p != ' ' && *p != '\t' )
		p++;
	*l = p - parser->last;
	while( *p != '\0' && (*p == ' ' || *p == '\t') )
		*(p++) = '\0';
	parser->position = p;
	return parser->last;
}

static void error(struct parser *parser, const char *fmt, ...) {
	va_list ap;

	if( parser->error )
		return;
	parser->error = true;

	if( parser->last != NULL )
		fprintf(stderr, "%s:%ld:%d: ", parser->current->filename,
				parser->current->lineno,
				(int)(1 + (parser->last - parser->buffer)));
	else
		fprintf(stderr, "%s:%ld: ", parser->current->filename,
				parser->current->lineno);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fputc('\n', stderr);
}

static void no_more_arguments(struct parser *parser) {
	if( parser->position[0] != '\0' ) {
		parser->last = parser->position;
		error(parser, "End of line expected!");
	}
}

void add_searchpath(struct parser *parser, const char *dir) {
	struct searchpath_entry **last;

	last = &parser->searchpath;
	while( *last != NULL )
		last = &(*last)->next;
	*last = malloc(sizeof(struct searchpath_entry));
	if( *last == NULL ) {
		oom(parser);
		return;
	}
	(*last)->next = NULL;
	(*last)->dir = dir;
	(*last)->len = strlen(dir);
}

static FILE *find_file(struct parser *parser, const char *name, char **filename_p) {
	size_t l = strlen(name);
	struct searchpath_entry *r;

	assert( parser->searchpath != NULL );

	for( r = parser->searchpath ; r != NULL ; r = r->next ) {
		char *filename = NULL;
		FILE *f;

		filename = malloc(l + r->len + 2);
		if( filename == NULL ) {
			oom(parser);
			return NULL;
		}
		memcpy(filename, r->dir, r->len);
		filename[r->len] = '/';
		memcpy(filename + r->len + 1, name, l + 1);

		 f = fopen(filename, "r");
		 if( f != NULL ) {
			 *filename_p = filename;
			 return f;
		 }
		 free(filename);
	}
	fprintf(stderr, "Unable to find '%s' in search path!\n", name);
	parser->error = true;
	*filename_p = NULL;
	return NULL;
}

static void open_next_file(struct parser *parser, char *name) {
	struct source_file *current;

	if( name == NULL )
		oom(parser);
	if( parser->error ) {
		free(name);
		return;
	}

	current = parser->current;
	while( current != NULL && strcmp(current->name, name) != 0 )
		current = current->next;
	if( current != NULL ) {
		if( current->file != NULL )
			error(parser,
"Circular dependency! '%s' requested while parsing it!", name);
		free(name);
		return;
	}
	current = calloc(1, sizeof(*current));
	if( current == NULL ) {
		oom(parser);
		free(name);
		return;
	}
	current->name = name;
	current->file = find_file(parser, name, &current->filename);
	if( current->file == NULL ) {
		int e = errno;
		error(parser, "Error %d opening '%s': %s",
				e, current->filename, strerror(e));
		file_free(current);
		return;
	}
	current->lineno = 0;
	current->namespace = NULL;
	parser->position = NULL;
	parser->last = NULL;
	current->next = parser->current;
	parser->current = current;
}

static bool add_variable(struct parser *parser, const char *prefix, const char *name, const char **varname, struct variable *variable) {
	struct varname *v, **vv;
	size_t pl = strlen(prefix), l = strlen(name);
	struct namespace *namespace = parser->current->namespace;

	v = malloc(sizeof(struct varname) + l + pl + 1);
	if( v == NULL ) {
		oom(parser);
		return false;
	}
	memcpy(v->name, prefix, pl);
	memcpy(v->name + pl, name, l + 1);
	v->variable = NULL;

	vv = tsearch(v, &namespace->variables[variable->type], compare_variables);
	if( vv == NULL ) {
		free(v);
		oom(parser);
		return false;
	}
	if( *vv != v ) {
	//	free(v);
		/* already defined */
		return false;
	}
	if( varname != NULL )
		*varname = v->name;
	v->variable = variable;
	variable->refcount ++;
	return true;
}

static struct variable *add_var(struct parser *parser, const char *prefix, const char *name, const char **varname, enum variable_type vt) {
	struct variable *variable;

	if( name == NULL )
		return NULL;

	variable = calloc(1, sizeof(struct variable));
	if( variable == NULL ) {
		oom(parser);
		return NULL;
	}
	variable->type = vt;
	if( add_variable(parser, prefix, name, varname, variable) )
		return variable;
	error(parser, "%s '%s%s' already defined!", typename[vt], prefix, name);
	free(variable);
	return NULL;
}

static struct variable *find_variable(struct parser *parser, enum variable_type vt, const char *name) {
	struct varname **v;
	const char *e;
	int i;

	if( name == NULL )
		return NULL;

	e = strchr(name, ':');
	if( e != NULL ) {
		struct namespace *n;

		if( e[1] != ':' ) {
			error(parser, "Unexpected colon (':') in '%s'!", name);
			return NULL;
		}
		for( n = parser->namespaces ; n != NULL ; n = n->next ) {
			if( strncmp(n->name, name, e - name) != 0 )
				continue;
			if( n->name[e-name] != '\0' )
				continue;
			v = tfind(e + 2 - sizeof(struct varname),
					&n->variables[vt],
					compare_variables);
			if( v == NULL || *v == NULL ) {
				error(parser, "Unknown %s '%s' ('%s')!", typename[vt], name, e+2);
				return NULL;
			} else
				return (*v)->variable;
		}
		error(parser, "Unknown namespace '%.*s'", (int)(e-name), name);
		return NULL;
	}

	v = tfind(name - sizeof(struct varname), &parser->current->namespace->variables[vt],
			compare_variables);
	if( v != NULL && *v != NULL )
		return (*v)->variable;

	// check imported namespaces
	for( i = 0 ; i < parser->current->namespace->used_count ; i++ ) {
		struct namespace *n = parser->current->namespace->used[i];

		v = tfind(name - sizeof(struct varname), &n->variables[vt],
				compare_variables);
		if( v != NULL && *v != NULL )
			return (*v)->variable;
	}

	error(parser, "Unknown %s %s!", typename[vt], name);
	return NULL;
}

#define command_is(name) l == sizeof(name)-1 && memcmp(command, name, sizeof(name)-1) == 0

static void parse_errors(struct parser *parser) {
	long first_line = parser->current->lineno;
	struct namespace *ns = parser->current->namespace;

	if( ns->num_errors != 0 || ns->errors != NULL ) {
		error(parser, "second ERRORS for namespace '%s'!",
				ns->name);
		return;
	}

	while( get_next_line(parser, first_line) ) {
		const char *name = get_const_token(parser, false);
		const char **n;

		if( strcmp(name, "END") == 0 ) {
			no_more_arguments(parser);
			return;
		} else if( strcmp(name, "EOF") == 0 ) {
			no_more_arguments(parser);
			error(parser,
"Missing END (begining at line %ld)", first_line);
		}
		no_more_arguments(parser);
		name = string_add(name);
		if( name == NULL ) {
			parser->error = true;
			return;
		}
		ns->num_errors++;
		n = realloc(ns->errors, ns->num_errors * sizeof(const char*));
		if( n == NULL ) {
			oom(parser);
			return;
		}
		ns->errors = n;
		ns->errors[ns->num_errors - 1] = name;
	}
	error(parser, "missing END!");
}

static unsigned long parse_number(struct parser *parser, const char *value) {
	char *e;
	unsigned long number = 0;

	if( parser->error )
		return 0;
	assert( value != NULL );

	if( value[0] == '$' ) {
		char *v;
		struct variable *var;
		const struct constant *c;

		e = strrchr(value, ':');
		if( e == NULL || ( e > value && *(e-1) == ':' ) ) {
			error(parser, "Constants name and member must be separated with a single colon!");
			return 0;
		}
		v = strndup(value + 1, e - (value+1));
		if( v == NULL ) {
			oom(parser);
			return 0;
		}
		var = find_variable(parser, vt_constants, v);
		if( var == NULL ) {
			free(v);
			return 0;
		}
		for( c = var->c.constants ; c->name != NULL ; c++ ) {
			if( strcmp(c->name, e+1) == 0 ) {
				free(v);
				return c->value;
			}
		}
		error(parser, "Unable to find '%s' in constants %s!", e+1, v);
		free(v);
		return 0;
	}

	if( value[0] == '0' && value[1] == '\0' ) {
		e = (char*)value + 1;
	} else if( value[0] == '0' && value[1] == 'x' )
		number = strtoll(value+2, &e, 16);
	else if( value[0] == '0' && value[1] == 'o' )
		number = strtoll(value+2, &e, 8);
	else if( value[0] == '0' && value[1] == 'b' )
		number = strtoll(value+2, &e, 2);
	else if( value[0] != '0' )
		number = strtoll(value, &e, 10);
	else {
		error(parser, "Leading zeros in numbers are forbidden to avoid confusion!");
		e = (char*)value;
	}
	if( e[0] == '<' && e[1] == '<' ) {
		char *ee;
		long long shift = strtoll(e + 2, &ee, 10);
		if( ee > e + 2 && shift >= 0 && shift < 32 ) {
			number = number << (unsigned long)shift;
			e = ee;
		}
	}
	if( *e != '\0' ) {
		error(parser, "Error parsing number!");
		return 0;
	}
	return number;
}

static bool parse_typespec(struct parser *parser, struct typespec *t) {
	const char *type, *attribute;
	struct variable *tv;
	const struct base_type *td;

	memset(t, 0, sizeof(*t));
	type = get_const_token(parser, false);
	if( parser->error ) {
		return false;
	}
	td = base_types;
	while( td->name != NULL && strcmp(td->name, type) != 0 )
		td++;
	if( td->name != NULL ) {
		t->base_type = td;
		if( C(td, NEEDS_CONSTANTS) ) {
			struct variable *cv;

			attribute = get_const_token(parser, false);
			cv = find_variable(parser, vt_constants, attribute);
			if( cv == NULL )
				return false;
			if( C(td, NEEDS_BITMASK) && ! cv->c.bitmask ) {
				error(parser,
"Not-BITMASK constants %s used for bitmask!",
						attribute);
			}
			t->data = cv;
			cv->refcount++;
		}
	} else {
		tv = find_variable(parser, vt_type, type);
		if( tv == NULL )
			return false;
		assert( tv->type == vt_type );
		typespec_copy(t, &tv->t);
	}
	attribute = get_const_token(parser, true);
	if( attribute != NULL ) {
		if( strcmp(attribute, "constants") == 0 ) {
			if( !C(t->base_type, ALLOWS_CONSTANTS) ) {
				error(parser, "constants not allowed here!");
			} else if( t->data != NULL ) {
				error(parser, "multiple constants not allowed!");
			} else {
				struct variable *cv;

				attribute = get_const_token(parser, false);
				cv = find_variable(parser, vt_constants, attribute);
				if( cv == NULL )
					return false;
				t->data = cv;
				cv->refcount++;
			}
		} else
			error(parser, "unknown type attribute!");
	}
	no_more_arguments(parser);
	return !parser->error;
}

static struct unfinished_parameter *new_parameter_special(struct parser *parser, struct unfinished_parameter ***last_pp, enum fieldtype ft, size_t offse, const char *condition)  {
	struct unfinished_parameter *n;

	if( parser->error )
		return NULL;

	n = calloc(1, sizeof(struct unfinished_parameter));
	if( n == NULL ) {
		oom(parser);
		return NULL;
	}
	n->isspecial = true;
	n->special.offse = offse;
	n->special.type = ft;
	/* NULL is termination condition */
	if( condition == NULL )
		n->special.condition = "";
	else
		n->special.condition = condition;
	**last_pp = n;
	*last_pp = &n->next;
	return n;
}

/* here many things can still be checked:
   if nothing is accessed past the length in a struct,
   if things overlap, ...
*/
static bool parse_parameters(struct parser *parser, struct variable *variable, bool needsnextmarker) {
	long first_line = parser->current->lineno;
	struct parameter_state {
		struct parameter_state *parent;
		struct unfinished_parameter *junction;
		bool store_set,
		     store_used,
		     format_set,
		     nextmarker_set,
		     nextmarker_at_end_of_packet;
	} *state;
	struct unfinished_parameter *parameters = NULL, **last = &parameters;

	assert( variable->parameter == NULL );

	state = calloc(1, sizeof(struct parameter_state));
	if( state == NULL ) {
		oom(parser);
		return false;
	}

	while( get_next_line(parser, first_line) ) {
		const char *position, *name;
		unsigned long number;
		struct typespec type;

		position = get_const_token(parser, false);
		if( strcmp(position, "EOF") == 0 ) {
			error(parser,
"Missing 'END' (closing block opened at line %ld)!",
					first_line + 1);
			break;
		}
		if( strcmp(position, "END") == 0 ) {
			no_more_arguments(parser);
			if( state->parent != NULL )
				error(parser, "missing ELSE");
			if( needsnextmarker && !state->nextmarker_set )
				error(parser, "Missing NEXT (or LISTof...)!");
			free(state);
			variable->parameter = parameters;
			return true;
		}
		if( strcmp(position, "ALIAS") == 0 ) {
			error(parser, "ALIAS is no longer a valid keyword!");
			break;
		}
		if( strcmp(position, "ELSE") == 0 ) {
			struct parameter_state *s;

			if( state->parent == NULL )
				error(parser, "ELSE without IF");
			no_more_arguments(parser);
			if( needsnextmarker && !state->nextmarker_set )
				error(parser, "Missing NEXT (or LISTof...)!");
			last = &state->junction->next;
			s = state->parent;
			free(state);
			state = s;
			continue;
		}
		if( strcmp(position, "ELSEIF") == 0 ) {
			struct parameter_state *s;
			const char *v, *condition;
			struct unfinished_parameter *i;
			enum fieldtype ft;

			if( state->parent == NULL )
				error(parser, "ELSEIF without IF");
			if( needsnextmarker && !state->nextmarker_set )
				error(parser, "Missing NEXT (or LISTof...)!");
			v = get_const_token(parser, false);
			number = parse_number(parser, v);
			v = get_const_token(parser, false);
			if( v == NULL )
				break;
			if( strcmp(v, "ATOM") == 0 ) {
				ft = ft_IFATOM;
				v = get_const_token(parser, false);
				condition = string_add(v);
			} else if( strcmp(v, "CARD8") == 0 ) {
				unsigned char c;

				ft = ft_IF8;
				v = get_const_token(parser, false);
				c = parse_number(parser, v);
				condition = string_add_l((const char*)&c, 1);
			} else if( strcmp(v, "CARD16") == 0 ) {
				unsigned char c[2];
				unsigned long l;

				ft = ft_IF16;
				v = get_const_token(parser, false);
				l = parse_number(parser, v);
				c[1] = l & 0xFF;
				c[0] = l >> 8;
				condition = string_add_l((const char*)c, 2);
			} else if( strcmp(v, "CARD32") == 0 ) {
				unsigned char c[4];
				unsigned long l;

				ft = ft_IF32;
				v = get_const_token(parser, false);
				l = parse_number(parser, v);
				c[3] = l & 0xFF;
				c[2] = (l >> 8) & 0xFF;
				c[1] = (l >> 16) & 0xFF;
				c[0] = l >> 24;
				condition = string_add_l((const char*)c, 4);
			} else {
				error(parser, "unknown IF type '%s'!", v);
				break;
			}
			no_more_arguments(parser);
			last = &state->junction->next;
			i = new_parameter_special(parser, &last,
					ft, number, condition);
			s = state->parent;
			*state = *s;
			state->parent = s;
			state->junction = i;
			if( i != NULL ) {
				last = &i->special.iftrue;
				i->special.isjunction = true;
			}
			continue;
		}
		if( strcmp(position, "IF") == 0 ) {
			struct parameter_state *s;
			struct unfinished_parameter *i;
			const char *v, *condition;
			enum fieldtype ft;

			v = get_const_token(parser, false);
			number = parse_number(parser, v);
			v = get_const_token(parser, false);
			if( v == NULL )
				break;
			if( strcmp(v, "ATOM") == 0 ) {
				ft = ft_IFATOM;
				v = get_const_token(parser, false);
				condition = string_add(v);
			} else if( strcmp(v, "CARD8") == 0 ) {
				unsigned char c;

				ft = ft_IF8;
				v = get_const_token(parser, false);
				c = parse_number(parser, v);
				condition = string_add_l((const char*)&c, 1);
			} else if( strcmp(v, "CARD16") == 0 ) {
				unsigned char c[2];
				unsigned long l;

				ft = ft_IF16;
				v = get_const_token(parser, false);
				l = parse_number(parser, v);
				c[1] = l & 0xFF;
				c[0] = l >> 8;
				condition = string_add_l((const char*)c, 2);
			} else if( strcmp(v, "CARD32") == 0 ) {
				unsigned char c[4];
				unsigned long l;

				ft = ft_IF32;
				v = get_const_token(parser, false);
				l = parse_number(parser, v);
				c[3] = l & 0xFF;
				c[2] = (l >> 8) & 0xFF;
				c[1] = (l >> 16) & 0xFF;
				c[0] = l >> 24;
				condition = string_add_l((const char*)c, 4);
			} else {
				error(parser, "unknown IF type '%s'!", v);
				break;
			}
			no_more_arguments(parser);
			i = new_parameter_special(parser, &last,
					ft, number, condition);
			s = malloc(sizeof(*s));
			if( s == NULL ) {
				oom(parser);
				break;
			}
			*s = *state;
			s->parent = state;
			s->junction = i;
			state = s;
			if( i != NULL ) {
				last = &i->special.iftrue;
				i->special.isjunction = true;
			}
			continue;
		}
		if( strcmp(position, "ROUND") == 0 ) {
			if( !state->nextmarker_set )
				error(parser, "ROUND makes no sense if nextmarker not set!");
			no_more_arguments(parser);
			new_parameter_special(parser, &last, ft_LASTMARKER,
					(size_t)-1 /* ROUND32 */, NULL );
			continue;
		}
		if( strcmp(position, "GET") == 0 ) {
			const char *v;

			v = get_const_token(parser, false);
			number = parse_number(parser, v);
			no_more_arguments(parser);
			// TODO: remember what is needed for checking
			state->store_set = true;

			new_parameter_special(parser, &last,
					ft_GET, number, NULL);
			continue;
		}
		if( strcmp(position, "SET_COUNTER") == 0 ) {
			const char *v;

			v = get_const_token(parser, false);
			number = parse_number(parser, v);
			no_more_arguments(parser);
			state->store_set = true;

			new_parameter_special(parser, &last,
					ft_SET, number, NULL);
			continue;
		}
		if( strcmp(position, "DECREMENT_STORED") == 0
			|| strcmp(position, "DECREMENT_COUNT") == 0 ) {
			const char *v;

			if( !state->store_set ) {
				error(parser, "store variable must be set before it can be changed!");
			}
			v = get_const_token(parser, false);
			number = parse_number(parser, v);
			no_more_arguments(parser);

			new_parameter_special(parser, &last,
					ft_DECREMENT_STORED, number, NULL);
			continue;
		}
		if( strcmp(position, "RESET_COUNTER") == 0 ) {
			no_more_arguments(parser);
			state->store_set = false;
			state->store_used = false;

			new_parameter_special(parser, &last,
					ft_SET, INT_MAX, NULL);
			continue;
		}
		if( strcmp(position, "NEXT") == 0 ) {
			const char *v;

			v = get_const_token(parser, false);
			number = parse_number(parser, v);
			no_more_arguments(parser);
			state->nextmarker_set = true;
			state->nextmarker_at_end_of_packet = false;

			new_parameter_special(parser, &last,
					ft_LASTMARKER, number, NULL);
			continue;
		}
		if( strcmp(position, "LATER") == 0 ) {
			if( state->nextmarker_at_end_of_packet )
				error(parser, "LATER makes no sense after all-consuming LIST (i.e. list without limiting count)");
			if( !state->nextmarker_set )
				error(parser, "LATER needs a command setting nextmarker before!");
			number = (size_t)-1; //OFS_LATER;
		} else
			number = parse_number(parser, position);
		name = get_const_token(parser, false);
		parse_typespec(parser, &type);
		if( parser->error ) {
			typespec_done(&type);
			break;
		}
		assert( type.base_type != NULL );
		if( C(type.base_type, SETS_NEXT) )
			state->nextmarker_set = true;
		if( C(type.base_type, NEEDS_STORE) && !state->store_set ) {
			error(parser, "This commands needs store variable set, but this does not seem to be the case!");
		}
		if( C(type.base_type, USES_STORE) ) {
			if( !state->store_set ) {
				if( state->store_used )
					error(parser, "store variable consumed and not ready here!");
				state->nextmarker_at_end_of_packet = true;
			}
			state->store_set = false;
			state->store_used = true;
		}
		if( C(type.base_type, SETS_STORE) ) {
			state->store_set = true;
			state->store_used = false;
		}
		if( C(type.base_type, USES_FORMAT) && !state->format_set ) {
			error(parser, "Format variable not set!");
		}
		if( C(type.base_type, SETS_FORMAT) ) {
			state->format_set = true;
		}
		if( C(type.base_type, PUSHES) ) {
		}

		name = string_add(name);
		if( name == NULL )
			parser->error = true;

		*last = calloc(1, sizeof(struct unfinished_parameter));
		if( *last == NULL )
			oom(parser);
		if( parser->error ) {
			typespec_done(&type);
			break;
		}
		(*last)->isspecial = false;
		(*last)->regular.offse = number;
		(*last)->regular.name = string_add(name);;
		(*last)->regular.type = type;
		last = &(*last)->next;
	}
	error(parser, "missing END!");
	parameter_free(parameters);
	while( state != NULL ) {
		struct parameter_state *s = state->parent;
		free(state);
		state = s;
	}
	return false;
}

static struct request_data *find_request(struct parser *parser, const char *name) {
	struct namespace *n = parser->current->namespace;
	int i;

	if( parser->error )
		return NULL;
	if( n->requests == NULL || n->num_requests <= 0 )
		return NULL;
	for( i = 0 ; i < n->num_requests ; i++ ) {
		struct request_data *r = &n->requests[i];
		if( r->name == NULL )
			continue;
		if( strcmp(name, r->name) == 0 )
			return r;
	}
	return NULL;
}

static void parse_request(struct parser *parser, bool template) {
	const char *name, *attribute;
	struct variable *v = NULL;
	bool complete = false;
	struct request_data *request;

	name = get_const_token(parser, false);
	while( (attribute = get_const_token(parser, true)) != NULL ) {
		if( strcmp(attribute, "ALIASES") == 0 ) {
			const char *t = get_const_token(parser, false);
			v = find_variable(parser, vt_request, t);
			if( v == NULL )
				return;
		} else {
			error(parser, "Unknown REQUEST attribute '%s'!",
					attribute);
			return;
		}
	}
	if( v != NULL ) {
		complete = true;
		if( !add_variable(parser, "", name, &name, v) )
			return;
	} else {
		v = add_var(parser, "", name, &name, vt_request);
		if( v == NULL )
			return;
	}
	request = find_request(parser, name);
	if( template ) {
		if( request != NULL ) {
			error(parser, "'%s' is already listed in REQUESTS, thus cannot be a template!", name);
			return;
		}
	} else  {
		if( request == NULL ) {
			error(parser, "Unknow request '%s'! (Must be listed in REQUESTS or use templateREQUEST", name);
			return;
		}
		if( request->request != NULL ) {
			error(parser, "Multiple definition of request '%s::%s'!",
					parser->current->namespace->name,
					name);
		}
		if( request->unsupported ) {
			error(parser, "Unexpected definition of unsupported request '%s::%s'!",
					parser->current->namespace->name,
					name);
		}
		request->request = v;
		v->refcount ++;
	}
	if( !complete )
		parse_parameters(parser, v, false);
}

static void parse_setup(struct parser *parser) {
	const char *attribute;
	struct variable *v = NULL;
	struct namespace *n = parser->current->namespace;

	assert( n != NULL );
	if( n->extension != NULL || strcmp(n->name, "core") != 0 ) {
		error(parser, "'SETUP' only allowed in namespace 'core'!");
		return;
	}
	if( n->setup != NULL ) {
		error(parser, "multiple 'SETUP' in the same namespace!");
		return;
	}
	while( (attribute = get_const_token(parser, true)) != NULL ) {
		error(parser, "Unknown SETUP attribute '%s'!",
				attribute);
		return;
	}

	v = add_var(parser, "", "setup", NULL, vt_setup);
	if( v == NULL )
		return;
	n->setup = v;
	v->refcount ++;
	parse_parameters(parser, v, false);
}

static void parse_response(struct parser *parser, bool template) {
	const char *name, *attribute;
	struct variable *v = NULL;
	bool complete = false;

	name = get_const_token(parser, false);
	while( (attribute = get_const_token(parser, true)) != NULL ) {
		if( strcmp(attribute, "ALIASES") == 0 ) {
			const char *t = get_const_token(parser, false);
			v = find_variable(parser, vt_response, t);
			if( v == NULL )
				return;
		} else {
			error(parser, "Unknown RESPONSE attribute '%s'!",
					attribute);
			return;
		}
	}
	if( v != NULL ) {
		complete = true;
		if( !add_variable(parser, "", name, &name, v) )
			return;
	} else {
		v = add_var(parser, "", name, &name, vt_response);
		if( v == NULL )
			return;
	}

	if( ! template ) {
		struct request_data *request;
		request = find_request(parser, name);

		if( request == NULL )
			return;
		if( !request->has_response ) {
			error(parser, "Unexpected response '%s' (must be listed in REQUESTS with RESPONDS!)",
					name);
		}
		if( request->response != NULL ) {
			error(parser, "Multiple definition of response '%s::%s'!",
					parser->current->namespace->name,
					name);
		}
		if( request->unsupported ) {
			error(parser, "Unexpected definition of unsupported response '%s::%s'!",
					parser->current->namespace->name,
					name);
		}
		request->response = v;
		v->refcount ++;
	}
	if( !complete )
		parse_parameters(parser, v, false);
}

static struct event_data *find_event(struct parser *parser, const char *name) {
	struct namespace *n = parser->current->namespace;
	int i;

	if( parser->error )
		return NULL;
	if( n->requests == NULL || n->num_requests <= 0 ) {
		return NULL;
	}
	for( i = 0 ; i < n->num_events ; i++ ) {
		struct event_data *e = &n->events[i];
		if( e->name == NULL )
			continue;
		if( strcmp(name, e->name) == 0 )
			return e;
	}
	return NULL;
}

static void parse_events(struct parser *parser) {
	struct namespace *n = parser->current->namespace;
	long firstline = parser->current->lineno;

	assert( n != NULL );
	if( n->extension == NULL && strcmp(n->name, "core") != 0 ) {
		error(parser, "'EVENTS' only allowed in extension or namespace 'core'!");
		return;
	}
	if( n->events != NULL || n->num_events != 0 ) {
		error(parser, "multiple 'EVENTS' in the same namespace!");
		return;
	}

	while( get_next_line(parser, firstline) ) {
		const char *name;
		const char *attribute;
		struct event_data event, *newevents;

		memset(&event, 0, sizeof(event));
		/* TODO: allow excplicit setting */
		event.number = n->num_events;

		name = get_const_token(parser, false);
		if( name == NULL )
			break;
		if( strcmp(name, "EOF") == 0 ) {
			error(parser, "Missing 'END' (expected since line %ld)!",
					firstline + 1);
			return;
		}
		if( strcmp(name, "END") == 0 ) {
			return;
		}
		if( strcmp(name, "UNKNOWN") == 0 ) {
			event.unsupported = true;
			event.name = NULL;
		} else {
			event.name = string_add(name);
			if( event.name == NULL ) {
				parser->error = true;
				return;
			}
		}
		while( (attribute = get_const_token(parser, true)) != NULL ) {
			if( strcmp(attribute, "UNSUPPORTED") == 0 )
				event.unsupported = true;
			else if( attribute[0] == '/' && attribute[1]  == '*' ) {
				char *e;
				long l;

				if( attribute[2] == '\0' )
					attribute = get_const_token(parser, false);
				else
					attribute += 2;
				if( attribute == NULL )
					break;
				l = strtol(attribute, &e, 0);
				if( *e == '\0' )
					attribute = get_const_token(parser, false);
				else
					attribute = e;
				if( attribute == NULL || attribute[0] != '*'
						|| attribute[1] != '/' )
					error(parser, "Parse error, '/*' only allowed as '/* number */'!");
				else if( event.number != l )
					error(parser, "Event '%s' is %d but asserted to be %ld", name, event.number, l);

			} else {
				error(parser, "Unexpected response attribute '%s'!",
						attribute);
			}
		}
		newevents = realloc(n->events, sizeof(struct event_data)*(n->num_events+1));
		if( newevents == NULL ) {
			oom(parser);
			break;
		}
		n->events = newevents;
		newevents[n->num_events] = event;
		n->num_events++;
	}
}
static void parse_event(struct parser *parser, bool template) {
	const char *name, *attribute;
	struct variable *v = NULL;
	bool complete = false;
	struct event_data *event;

	name = get_const_token(parser, false);
	while( (attribute = get_const_token(parser, true)) != NULL ) {
		if( strcmp(attribute, "ALIASES") == 0 ) {
			const char *t = get_const_token(parser, false);
			v = find_variable(parser, vt_event, t);
			if( v == NULL )
				return;
		} else {
			error(parser, "Unknown EVENT attribute '%s'!",
					attribute);
			return;
		}
	}
	if( v != NULL ) {
		complete = true;
		if( !add_variable(parser, "", name, &name, v) )
			return;
	} else {
		v = add_var(parser, "", name, &name, vt_event);
		if( v == NULL )
			return;
	}
	event = find_event(parser, name);
	if( template ) {
		if( event != NULL ) {
			error(parser, "'%s' cannot be the name for a templateEvent as it is already the name for an event in EVENTS!\n", name);
			return;
		}
	} else {
		if( event == NULL ) {
			error(parser, "EVENT '%s' not listed in previous EVENTS!\n",
					name);
			return;
		}
		event->event = v;
		v->refcount ++;
	}
	if( !complete )
		parse_parameters(parser, v, false);
}

static void add_namespace(struct parser *parser, const char *namespace, const char *extension ) {
	struct namespace *n;

	if( parser->error )
		return;
	assert(parser->current != NULL );
	assert(parser->current->namespace == NULL );

	n = parser->namespaces;
	while( n != NULL && strcmp(n->name, namespace) != 0 )
		n = n->next;

	if( n != NULL ) {
		if( n->extension != NULL && extension != NULL ) {
			error(parser, "Redefinition of extension in namespace '%s'!",
					namespace);
			return;
		}
		if( extension != NULL ) {
			n->extension = strdup(extension);
			if( n->extension == NULL ) {
				oom(parser);
				return;
			}
		}
		n->refcount++;
		parser->current->namespace = n;
		return;
	}
	n = calloc(1, sizeof(struct namespace));
	if( n == NULL ) {
		oom(parser);
		return;
	}
	n->name = strdup(namespace);
	if( n->name == NULL ) {
		oom(parser);
		free(n);
		return;
	}
	if( extension != NULL ) {
		n->extension = strdup(extension);
		if( n->extension == NULL ) {
			oom(parser);
			free(n->name);
			free(n);
			return;
		}
	}
	n->refcount = 1;
	parser->current->namespace = n;
	n->next = parser->namespaces;
	parser->namespaces = n;
}

static void parse_struct(struct parser *parser, bool list) {
	const char *name, *modifier;
	bool have_length = false, isvariable = false;
	struct variable *v, *vl, *vt = NULL;
	struct unfinished_parameter *p;
	size_t length = 0;

	name = get_const_token(parser, false);
	v = add_var(parser, "", name, &name, vt_struct);
	vl = add_var(parser, "LISTof", name, NULL, vt_type);
	vl->t.data = v;
	v->refcount++;
	if( !list ) {
		vt = add_var(parser, "", name, NULL, vt_type);
		vt->t.data = v;
		v->refcount++;
	}

	while( (modifier = get_const_token(parser, have_length)) != NULL ) {
		if( strcmp(modifier, "variable") == 0 ) {
			if( have_length ) {
				error(parser, "variable keyword not allowed after length keyword!");
			}
			if( !list ) {
				error(parser, "variable keyword not yet allowed for STRUCT, only for LIST!");
			}
			isvariable = true;
		} else if( strcmp(modifier, "length") == 0 ) {
			if( isvariable )
				error(parser, "variable STRUCTs have no length, use min-length instead!");
			modifier = get_const_token(parser, false);
			length = parse_number(parser, modifier);
			have_length = true;
		} else if( strcmp(modifier, "min-length") == 0 ) {
			if( !isvariable )
				error(parser, "min-length only allowed after variable keyword!");
			modifier = get_const_token(parser, false);
			length = parse_number(parser, modifier);
			have_length = true;
		} else {
			error(parser, "Unknown attribute '%s'", modifier);
		}
	}
	if( !have_length ) {
		if( isvariable )
			error(parser, "Missing min-length statement!");
		else
			error(parser, "Missing length statement!");
	}
	if( isvariable ) {
		vl->t.base_type = &base_type_list_of_varstruct;
//		if( !list )
//			vt->t.base_type = &base_type_varstruct;
	} else {
		vl->t.base_type = &base_type_list_of_struct;
		if( !list )
			vt->t.base_type = &base_type_struct;
	}
	parse_parameters(parser, v, isvariable);
	/* add (min-)length information: */
	p = calloc(1, sizeof(*p));
	if( p == NULL ) {
		oom(parser);
		return;
	}
	p->next = v->parameter;
	v->parameter = p;
	p->isspecial = true;
	p->special.offse = length;
}

static void parse_type(struct parser *parser) {
	const char *name;
	struct variable *v;

	name = get_const_token(parser, false);

	v = add_var(parser, "", name, &name, vt_type);
	if( v == NULL )
		return;
	parse_typespec(parser, &v->t);
}

static void parse_requests(struct parser *parser) {
	struct namespace *n = parser->current->namespace;
	long firstline = parser->current->lineno;

	assert( n != NULL );
	if( n->extension == NULL && strcmp(n->name, "core") != 0 ) {
		error(parser, "'REQUESTS' only allowed in extension or namespace 'core'!");
		return;
	}
	if( n->requests != NULL || n->num_requests != 0 ) {
		error(parser, "multiple 'REQUESTS' in the same namespace!");
		return;
	}

	while( get_next_line(parser, firstline) ) {
		const char *name;
		const char *attribute;
		struct request_data request, *r;

		memset(&request, 0, sizeof(request));
		/* TODO: allow excplicit setting */
		request.number = n->num_requests;

		name = get_const_token(parser, false);
		if( name == NULL )
			break;
		if( strcmp(name, "EOF") == 0 ) {
			error(parser, "Missing 'END' (expected since line %ld)!",
					firstline + 1);
			return;
		}
		if( strcmp(name, "END") == 0 ) {
			return;
		}
		if( strcmp(name, "UNKNOWN") == 0 ) {
			request.unsupported = true;
			request.name = NULL;
		} else {
			request.name = string_add(name);
			if( request.name == NULL ) {
				parser->error = true;
				return;
			}
		}
		while( (attribute = get_const_token(parser, true)) != NULL ) {
			if( strcmp(attribute, "RESPONDS") == 0 )
				request.has_response = true;
			else if( strcmp(attribute, "SPECIAL") == 0 ) {
				if( request.name == NULL )
					error(parser, "SPECIAL not possible with UNKNOWN!");
				request.special = true;
			} else if( strcmp(attribute, "UNSUPPORTED") == 0 )
				request.unsupported = true;
			else if( attribute[0] == '/' && attribute[1]  == '*' ) {
				char *e;
				long l;

				if( attribute[2] == '\0' )
					attribute = get_const_token(parser, false);
				else
					attribute += 2;
				if( attribute == NULL )
					break;
				l = strtol(attribute, &e, 0);
				if( *e == '\0' )
					attribute = get_const_token(parser, false);
				else
					attribute = e;
				if( attribute == NULL || attribute[0] != '*'
						|| attribute[1] != '/' )
					error(parser, "Parse error, '/*' only allowed as '/* number */'!");
				else if( request.number != l )
					error(parser, "Request '%s' is %d but asserted to be %ld", name, request.number, l);

			} else {
				error(parser, "Unexpected response attribute '%s'!",
						attribute);
			}
		}
		r = realloc(n->requests, sizeof(struct request_data)*(n->num_requests+1));
		if( r == NULL ) {
			oom(parser);
			break;
		}
		n->requests = r;
		r[n->num_requests] = request;
		n->num_requests++;
	}
}

static void parse_constants(struct parser *parser, bool bitmasks) {
	struct namespace *n = parser->current->namespace;
	long firstline = parser->current->lineno;
	const char *valuesname;
	size_t count = 0;
	struct constant *constants;
	struct variable *v;

	assert( n != NULL );
	valuesname = get_const_token(parser, false);
	no_more_arguments(parser);

	v = add_var(parser, "", valuesname, &valuesname, vt_constants);
	if( v == NULL )
		return;

	constants = malloc(sizeof(struct constant)*8);
	if( constants == NULL ) {
		oom(parser);
		return;
	}

	while( get_next_line(parser, firstline) ) {
		const char *value;
		const char *text;
		unsigned long number;
		int j;

		value = get_const_token(parser, false);
		if( value == NULL )
			break;
		if( strcmp(value, "END") == 0 ) {
			struct constant *nc;

			nc = realloc(constants,
					sizeof(struct constant)*(count+1));
			if( nc == NULL ) {
				oom(parser);
				break;
			}
			constants = nc;
			constants[count].name = NULL;
			constants[count].value = 0;
			v->c.constants = constants;
			v->c.size = sizeof(struct constant)*(count+1);
			v->c.bitmask = bitmasks;
			return;
		}
		if( strcmp(value, "EOF") == 0 ) {
			error(parser, "Missing 'END' (for values opened at %ld)!",
					firstline + 1);
			break;
		}
		number = parse_number(parser, value);
		text = get_const_token(parser, false);
		constants[count].value = number;
		no_more_arguments(parser);
		constants[count].name = string_add(text);
		if( bitmasks && constants[count].value == 0 )
			error(parser, "Value 0 is not allowed in a BITMASK field!");
		for( j = 0 ; (size_t)j < count ; j++ ) {
			if( constants[count].value == constants[j].value ) {
				error(parser, "'%s' and '%s' have the same value in '%s'\n", constants[count].name, constants[j].name, valuesname);
			}
			if( bitmasks &&
				 	(constants[count].value
					 && ~constants[j].value) == 0 ) {
				error(parser, "'%s' shadowed by '%s' in BITMASK '%s'\n", constants[count].name, constants[j].name, valuesname);
			}
		}
		count++;
		if( (count & 7) == 0 ) {
			struct constant *nc;

			nc = realloc(constants,
					sizeof(struct constant)*(count+8));
			if( nc == NULL ) {
				oom(parser);
				break;
			}
			constants = nc;
		}
	}
	/* some error happened */
	free(constants);
}

static void parse_values(struct parser *parser) {
	struct namespace *n = parser->current->namespace;
	long first_line = parser->current->lineno;
	const char *valuesname;
	struct variable *v, *lv;
	struct unfinished_value *values = NULL, **last_val = &values;

	assert( n != NULL );
	valuesname = get_const_token(parser, false);
	no_more_arguments(parser);

	v = add_var(parser, "", valuesname, &valuesname, vt_values);
	lv = add_var(parser, "LISTof", valuesname, NULL, vt_type);
	if( v == NULL || lv == NULL )
		return;
	lv->t.base_type = &base_type_list_of_value;
	lv->t.data = v;
	v->refcount++;
	v->values = NULL;

	while( get_next_line(parser, first_line) ) {
		struct unfinished_value *nv;
		const char *mask, *name;
		unsigned long number;
		struct typespec type;

		mask = get_const_token(parser, false);
		if( strcmp(mask, "EOF") == 0 ) {
			error(parser,
"Missing 'END' (closing VALUES opened at line %ld)!",
					first_line + 1);
			break;
		}
		if( strcmp(mask, "END") == 0 ) {
			no_more_arguments(parser);
			if( values == NULL ) {
				error(parser, "Empty VALUES information!");
				return;
			}
			v->values = values;
			return;
		}
		number = parse_number(parser, mask);
		name = get_const_token(parser, false);
		if( name == NULL )
			break;
		name = string_add(name);
		if( name == NULL ) {
			parser->error = true;
			break;
		}
		memset(&type, 0, sizeof(type));
		parse_typespec(parser, &type);
		/* LISTofVALUES only supports some types */
		if( !C(type.base_type, ELEMENTARY) )
			error(parser, "Only elementary types allowed in VALUES (%s is not)!", type.base_type->name);
		nv = malloc(sizeof(struct unfinished_value));
		if( nv == NULL )
			oom(parser);
		if( parser->error ) {
			typespec_done(&type);
			break;
		}
		nv->flag = number;
		nv->name = name;
		nv->type = type;
		nv->next = NULL;
		*last_val = nv;
		last_val = &nv->next;
	}
	error(parser, "missing END!");
	while( values != NULL ) {
		struct unfinished_value *nv = values->next;
		typespec_done(&values->type);
		free(values);
		values = nv;
	}
}

static void parse_use(struct parser *parser) {
	const char *name;
	struct namespace *ns = parser->current->namespace;

	while( (name = get_const_token(parser, true)) != NULL ) {
		struct namespace *n, **nn = realloc(ns->used,
				sizeof(struct namespace*)
				* (ns->used_count+1));
		if( nn == NULL ) {
			oom(parser);
			return;
		}
		ns->used = nn;

		for( n = parser->namespaces ; n != NULL ; n = n->next ) {
			if( strcmp(n->name, name) == 0 )
				break;
		}
		// TODO: check if the used namespace is defined
		// in one of the needed files...
		ns->used[ns->used_count++] = n;
		if( n == NULL ) {
			error(parser, "Unknown namespace '%s'!",
					name);
			return;
		}
	}
}

static void check_namespace_complete(struct parser *parser) {
	struct namespace *n = parser->current->namespace;

	if( n->requests != NULL ) {
		int i;

		for( i = 0 ; i < n->num_requests ; i++ ) {
			const struct request_data *r = &n->requests[i];

			if( r->name == NULL )
				continue;
			if( !r->unsupported && r->request == NULL )
				error(parser, "Expected 'REQUEST %s'!", r->name);
			if( !r->unsupported && r->has_response && r->response == NULL )
				error(parser, "Expected 'RESPONSE %s'!", r->name);
		}
	}
	if( n->events != NULL ) {
		int i;

		for( i = 0 ; i < n->num_events ; i++ ) {
			const struct event_data *e = &n->events[i];

			if( e->name == NULL )
				continue;
			if( !e->unsupported && e->event == NULL )
				error(parser, "Missing 'EVENT %s'!", e->name);
		}
	}
}

struct parser *parser_init(void) {
	return calloc(1, sizeof(struct parser));
}

bool translate(struct parser *parser, const char *name) {

	open_next_file(parser, strdup(name));

	while( get_next_line(parser, -1) ) {
		size_t l; char *command;

		command = get_token_with_len(parser, &l);
		if( command == NULL )
			break;

		if( command_is("EOF") ) {
			no_more_arguments(parser);
			if( parser->current->namespace != NULL ) {
				check_namespace_complete(parser);
			}
			if( file_done(parser) )
				return true;
		} else if( command_is("NEEDS") ) {
			char *filename = get_token(parser, false);
			no_more_arguments(parser);
			open_next_file(parser, filename);
		} else if( command_is("EXTENSION") ) {
			if( parser->current->namespace != NULL )
				error(parser,
"Only one EXTENSION or NAMESPACE is allowed in each file!");
			else {
				const char *extension, *n;
				extension = get_const_token(parser, false);
				n = get_const_token(parser, false);
				no_more_arguments(parser);
				add_namespace(parser, n, extension);
			}
		} else if( command_is("NAMESPACE") ) {
			if( parser->current->namespace != NULL )
				error(parser,
"Only one EXTENSION or NAMESPACE is allowed in each file!");
			else {
				name = get_const_token(parser, false);
				no_more_arguments(parser);
				add_namespace(parser, name, NULL);
			}
		} else if( parser->current->namespace == NULL ) {
			error(parser, "First command must be EXTENSION or NAMESPACE!");
		} else if( command_is("USE") ) {
			parse_use(parser);
		} else if( command_is("SETUP") ) {
			parse_setup(parser);
		} else if( command_is("REQUESTS") ) {
			parse_requests(parser);
		} else if( command_is("EVENTS") ) {
			parse_events(parser);
		} else if( command_is("ERRORS") ) {
			parse_errors(parser);
		} else if( command_is("TYPE") ) {
			parse_type(parser);
		} else if( command_is("VALUES") ) {
			parse_values(parser);
		} else if( command_is("STRUCT") ) {
			parse_struct(parser, false);
		} else if( command_is("LIST") ) {
			parse_struct(parser, true);
		} else if( command_is("CONSTANTS") ) {
			parse_constants(parser, false);
		} else if( command_is("BITMASK") ) {
			parse_constants(parser, true);
		} else if( command_is("templateRESPONSE") ) {
			parse_response(parser, true);
		} else if( command_is("RESPONSE") ) {
			parse_response(parser, false);
		} else if( command_is("templateREQUEST") ) {
			parse_request(parser, true);
		} else if( command_is("REQUEST") ) {
			parse_request(parser, false);
		} else if( command_is("templateEVENT") ) {
			parse_event(parser, true);
		} else if( command_is("EVENT") ) {
			parse_event(parser, false);
		} else {
			error(parser, "Unknown command '%s'\n", command);
		}
	}
	return false;
}

static void free_varname(void *nodep) {
	struct varname *vn = nodep;
	variable_unref(vn->variable);
	free(vn);
}

bool parser_free(struct parser *parser) {
	bool success = !parser->error;

	file_free(parser->current);

	while( parser->namespaces != NULL ) {
		struct namespace *ns = parser->namespaces;
		parser->namespaces = ns->next;
		int i;
		enum variable_type vt;

		assert( ns->refcount == 0 );
		for( vt = 0 ; vt < vt_COUNT ; vt ++ ) {
			tdestroy(ns->variables[vt], free_varname);
		}
		free(ns->name);
		free(ns->extension);
		for( i = 0 ; i < ns->num_requests ; i++ ) {
			variable_unref(ns->requests[i].request);
			variable_unref(ns->requests[i].response);
		}
		free(ns->requests);
		for( i = 0 ; i < ns->num_events ; i++ ) {
			variable_unref(ns->events[i].event);
		}
		if( ns->setup != NULL )
			variable_unref(ns->setup);
		free(ns->events);
		free(ns->errors);
		free(ns->used);
		free(ns);
	}
	while( parser->searchpath != NULL ) {
		struct searchpath_entry *e = parser->searchpath;
		parser->searchpath = e->next;
		free(e);
	}
	parser->current = NULL;
	free(parser);
	return success;
}

static const void *variable_finalize(struct parser *, struct variable *);

static const void *parameter_finalize(struct parser *parser, struct unfinished_parameter *parameter) {
	struct unfinished_parameter *p;
	size_t count = 0;
	struct parameter *prepared, *f;
	const void *finalized;
	/* no need to do add empty ones all the time,
	   just take the last one... */
	static const struct parameter *empty = NULL;

	if( parameter == NULL && empty != NULL ) {
		return empty;
	}

	for( p = parameter ; p != NULL ; p = p->next ) {
		count++;
		assert( !p->isspecial || !p->special.isjunction ||
				p->special.finalized != NULL );
	}
	prepared = calloc(count + 1, sizeof(struct parameter));
	if( prepared == NULL ) {
		oom(parser);
		return NULL;
	}
	for( f = prepared, p = parameter ; p != NULL ; p = p->next, f++ ) {
		assert( (size_t)(f - prepared) < count );
		if( p->isspecial ) {
			f->offse = p->special.offse;
			f->name = p->special.condition;
			f->type = p->special.type;
			f->constants = p->special.finalized;
		} else {
			f->offse = p->regular.offse;
			f->name = p->regular.name;
			f->type = p->regular.type.base_type->type;
			f->constants = variable_finalize(parser,
					p->regular.type.data);
		}
	}
	assert( (size_t)(f - prepared) == count );
	finalized = finalize_data(prepared,
			(count + 1)*sizeof(struct parameter),
			__alignof__(struct parameter));
	free(prepared);
	/* remember last terminator as next empty jump target */
	empty = finalized;
	empty += count;
	return finalized;
}

static const void *variable_finalize(struct parser *parser, struct variable *v) {
	if( v == NULL )
		return NULL;
	if( v->finalized != NULL )
		return v->finalized;
	if( v->type == vt_values ) {
		struct value *values;
		struct unfinished_value *uv;
		size_t i = 0, count = 0;

		for( uv = v->values; uv != NULL ; uv = uv->next )
			count++;
		values = calloc(count + 1, sizeof(struct value));
		if( values == NULL ) {
			oom(parser);
			return NULL;
		}
		for( uv = v->values; uv != NULL ; uv = uv->next ) {
			assert( i < count);
			values[i].flag = uv->flag;
			values[i].name = uv->name;
			assert( C(uv->type.base_type, ELEMENTARY) );
			values[i].type = uv->type.base_type->type;
			values[i].constants = variable_finalize(
					parser, uv->type.data);
			i++;
		}
		v->finalized = finalize_data(values, (count+1)*sizeof(struct value),
				__alignof__(struct value));
		free(values);
		if( v->finalized == NULL )
			parser->error = true;
		return v->finalized;
	}
	if( v->type == vt_constants ) {
		v->finalized = finalize_data(v->c.constants,
				v->c.size, __alignof__(struct constant));
		if( v->finalized == NULL )
			parser->error = true;
		return v->finalized;
	}
	if( v->type == vt_struct || v->type == vt_response ||
			v->type == vt_setup ||
			v->type == vt_request || v->type == vt_event ) {
		struct unfinished_parameter *p, *todo, *startat;
		do {

			todo = NULL;
			startat = v->parameter;
			p = startat;

			while( p != NULL ) {
				if( !p->isspecial ) {
					p = p->next;
					continue;
				}
				if( p->special.finalized != NULL ) {
					p = p->next;
					continue;
				}
				if( !p->special.isjunction ) {
					p = p->next;
					continue;
				}
				if( p->special.iftrue == NULL ) {
					/* empty branch still needs
					   an end command, but no recursion
					   for that */
					p->special.finalized =
							parameter_finalize(
								parser,
								NULL);
					p = p->next;
					continue;
				}
				todo = p;
				startat = p->special.iftrue;
				p = startat;
			}
			if( todo != NULL ) {
				todo->special.finalized =
					parameter_finalize(parser, startat);
			} else {
				v->finalized =
					parameter_finalize(parser, startat);
			}
		} while( todo != NULL );
		return v->finalized;
	}
	assert( v->type != v->type );
}

static const struct request *finalize_requests(struct parser *parser, struct namespace *ns, const struct parameter *unknownrequest, const struct parameter *unknownresponse) {
	struct request *rs;
	const struct request *f;
	int i;

	rs = calloc(ns->num_requests, sizeof(struct request));
	if( rs == NULL ) {
		oom(parser);
		return NULL;
	}
	for( i = 0 ; i < ns->num_requests ; i++ ) {
		rs[i].name = ns->requests[i].name;
		if( ns->requests[i].unsupported ) {
			assert( ns->requests[i].request == NULL);
			rs[i].parameters = unknownrequest;
		} else {
			assert( ns->requests[i].request != NULL);
			rs[i].parameters = variable_finalize(parser,
					ns->requests[i].request);
		}
		if( ns->requests[i].has_response ) {
			if( ns->requests[i].unsupported ) {
				assert( ns->requests[i].response == NULL);
				rs[i].answers = unknownresponse;
			} else {
				assert( ns->requests[i].response != NULL);
				rs[i].answers = variable_finalize(parser,
						ns->requests[i].response);
			}
		} else
			assert( ns->requests[i].response == NULL);
		if( !ns->requests[i].special )
			continue;
		assert( rs[i].name != NULL );
		if( strcmp(ns->name, "core") != 0 )
			continue;
		if( strcmp(rs[i].name, "QueryExtension") == 0 ) {
			rs[i].request_func = requestQueryExtension;
			rs[i].reply_func = replyQueryExtension;
		} else if( strcmp(rs[i].name, "InternAtom") == 0 ) {
			/* atoms are not the only names, in the future that
			might be something general... */
			rs[i].request_func = requestInternAtom;
			rs[i].reply_func = replyInternAtom;
		} else if( strcmp(rs[i].name, "ListFontsWithInfo") == 0 ) {
			/* this should be changed to a general approach */
			rs[i].reply_func = replyListFontsWithInfo;
		} else {
			fprintf(stderr, "No specials available for '%s::%s'!\n",
					ns->name, rs[i].name);
			parser->error = true;
		}
	}
	f = finalize_data(rs, ns->num_requests * sizeof(struct request),
		       __alignof__(struct request));
	if( f == NULL )
		parser->error = true;
	free(rs);
	return f;
}

static const struct event *finalize_events(struct parser *parser, struct namespace *ns) {
	struct event *es;
	const struct event *f;
	int i;

	es = calloc(ns->num_events, sizeof(struct event));
	if( es == NULL ) {
		oom(parser);
		return NULL;
	}
	for( i = 0 ; i < ns->num_events ; i++ ) {
		es[i].name = ns->events[i].name;
		es[i].parameters = variable_finalize(parser,
				ns->events[i].event);
	}
	f = finalize_data(es, ns->num_events * sizeof(struct event),
		       __alignof__(struct event));
	if( f == NULL )
		parser->error = true;
	free(es);
	return f;
}

void finalize_everything(struct parser *parser) {
	struct extension *es, *e;
	size_t count = 0;
	struct namespace *ns, *core = NULL;
	struct variable *v;
	const struct parameter *unknownrequest, *unknownresponse;

	if( parser->error )
		return;

	assert( extensions == NULL /* only to be called one time */ );

	for( ns = parser->namespaces ; ns != NULL ; ns = ns->next ) {
		if( strcmp(ns->name, "core") == 0 )
			core = ns;
		if( ns->extension != NULL )
			count++;
	}
	if( core == NULL ) {
		fputs("No core namespace defined!\n", stderr);
		parser->error = true;
		return;
	}
	if( core->num_requests == 0 ) {
		fputs("No core requests defined!\n", stderr);
		parser->error = true;
		return;
	}
	if( core->num_events == 0 ) {
		fputs("No core events defined!\n", stderr);
		parser->error = true;
		return;
	}
	if( core->num_errors == 0 ) {
		fputs("No core errors defined!\n", stderr);
		parser->error = true;
		return;
	}
	if( core->setup == NULL ) {
		fputs("No setup parser defined!\n", stderr);
		parser->error = true;
		return;
	}
	v = find_variable(parser, vt_request, "core::unknown");
	unknownrequest = variable_finalize(parser, v);
	v = find_variable(parser, vt_response, "core::unknown");
	unknownresponse = variable_finalize(parser, v);
	unexpected_reply = unknownresponse;
	if( parser->error )
		return;
	if( count == 0 ) {
		num_extensions = count;
		extensions = NULL;
		return;
	} else {
		es = calloc(count, sizeof(struct extension));
		if( es == NULL ) {
			oom(parser);
			return;
		}
		e = es;
		for( ns = parser->namespaces ; ns != NULL ; ns = ns->next ) {
			if( ns->extension == NULL )
				continue;
			e->name = string_add(ns->extension);
			if( e->name == NULL )
				parser->error = true;
			e->namelen = strlen(ns->extension);
			e->numsubrequests = ns->num_requests;
			e->subrequests = finalize_requests(parser, ns,
					unknownrequest, unknownresponse);
			e->numevents = ns->num_events;
			e->events = finalize_events(parser, ns);
			e->numerrors = ns->num_errors;
			e->errors = finalize_data(ns->errors,
					ns->num_errors*sizeof(const char*),
					__alignof__(const char*));
			if( e->errors == NULL )
				parser->error = true;
			e++;
		}
		assert( (size_t)(e-es) == count );
		extensions = finalize_data(es, count*sizeof(struct extension),
				__alignof__(struct extension));
		free(es);
		if( extensions == NULL ) {
			oom(parser);
			return;
		}
		num_extensions = count;
	}
	requests = finalize_requests(parser, core, unknownrequest, unknownresponse);
	num_requests = core->num_requests;
	events = finalize_events(parser, core);
	num_events = core->num_events;
	errors = finalize_data(core->errors,
			core->num_errors*sizeof(const char*),
			__alignof__(const char*));
	if( errors == NULL )
		parser->error = true;
	num_errors = core->num_errors;
	setup_parameters = variable_finalize(parser, core->setup);
}

/*
int main() {
	bool success;
	struct parser *parser;

	stringlist_init();
	parser = parser_init(parser);
	if( parser == NULL )
		exit(EXIT_FAILURE);
	translate(&parser, "all.proto");
	finalize_everything(parser);
	success = parser_free(parser);
	stringlist_done();
	return success?EXIT_SUCCESS:EXIT_FAILURE;
}
*/
