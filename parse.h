#ifndef XTRACE_PARSE_H
#define XTRACE_PARSE_H

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
	const char * const *errors;
	unsigned char numerrors;
};

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
		ft_LISTofINT8, ft_LISTofINT16,
		ft_LISTofINT32,
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
		ft_IF16,
		ft_IF32,
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
		ft_LISTofFIXED,
		/* a 32 bit floating pointer number */
		ft_FLOAT32,
		/* a list of those */
		ft_LISTofFLOAT32,
		/* fraction with nominator and denominator 16 bit */
		ft_FRACTION16_16,
		/* set stored value to specific value */
		ft_DECREMENT_STORED,
		ft_SET
		} type;
	const struct constant *constants;
};
struct value {
	unsigned long flag;
	/* NULL means EndOfValues */
	const char *name;
	/* only elementary type (<= ft_BITMASK32 are allowed ), */
	enum fieldtype type;
	const struct constant *constants;
};

extern const struct request *requests;
extern size_t num_requests;
extern const struct event *events;
extern size_t num_events;
extern const const char * const *errors;
extern size_t num_errors;
extern const struct extension *extensions;
extern size_t num_extensions;
extern const struct parameter *unexpected_reply;
extern const struct parameter *setup_parameters;

bool requestQueryExtension(struct connection *c, bool pre, bool bigrequest UNUSED, struct expectedreply *reply);
bool requestInternAtom(struct connection *c, bool pre, bool bigrequest UNUSED, struct expectedreply *reply);
void replyListFontsWithInfo(struct connection *c,bool *ignore,bool *dontremove,int datatype UNUSED,void *data UNUSED);
void replyQueryExtension(struct connection *c,bool *ignore UNUSED,bool *dontremove UNUSED,int datatype,void *data);
void replyInternAtom(struct connection *c,bool *ignore UNUSED,bool *dontremove UNUSED,int datatype UNUSED,void *data);

#endif
