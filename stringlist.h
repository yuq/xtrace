#ifndef XTRACE_STRINGLIST_H
#define XTRACE_STRINGLIST_H
const char *string_add_l(const char *, size_t);
const char *string_add(const char *);
const void *finalize_data(const void *, size_t len, size_t align);
void stringlist_init(void);
void stringlist_done(void);
#endif

