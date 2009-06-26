#ifndef XTRACE_TRANSLATE_H
#define XTRACE_TRANSLATE_H

struct parser;

void finalize_everything(struct parser *);
struct parser *parser_init(void);
bool translate(struct parser *, const char *);
bool parser_free(struct parser *);

#endif
