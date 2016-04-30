

extern size_t authdata_len;
extern char *authdata;
extern FILE *out;

bool generateAuthorisation(const char *displayname);
const char *parseDisplay(const char *displayname,
		char **protocol, char **hostname,
		int *display, int *screen, int *family );
int connectToServer(const char *displayname,int family,const char *hostname,int display);
int listenForClients(const char *displayname,int family,int display);
struct sockaddr_un;
const char *generateSocketName(struct sockaddr_un *addr,int display);
uint16_t calculateTCPport(int display);
int acceptClient(int family,int listener, char **from);

#define FDQUEUE_MAX_FD 16
struct fdqueue {
	int fd[FDQUEUE_MAX_FD];
	int nfd;
};

extern struct connection {
	struct connection *next;
	int id; char *from;
	int client_fd,server_fd;
	bool bigendian;
	unsigned char clientbuffer[16*4096];
	unsigned int clientcount,clientignore;
	enum client_state { c_start=0, c_normal, c_amlost } clientstate;
	unsigned char serverbuffer[16*4096];
	unsigned int servercount,serverignore;
	enum server_state { s_start=0, s_normal, s_amlost} serverstate;
	struct fdqueue clientfdq;
	struct fdqueue serverfdq;
	struct expectedreply *expectedreplies;
	uint64_t seq;
	struct usedextension *usedextensions;
	struct unknownextension *waiting, *unknownextensions;
	unsigned long long starttime;
} *connections;
void parse_server(struct connection *c);
void parse_client(struct connection *c);
void free_usedextensions(struct usedextension *);
void free_unknownextensions(struct unknownextension *);
bool copy_authentication(const char *fakedisplay,const char *display, const char *infile, const char *outfile);
struct atom;
struct atom *newAtom(const char *name, size_t len);
const char *getAtom(struct connection *c, uint32_t atom);
void internAtom(struct connection *c, uint32_t atom, struct atom *data);

extern bool denyallextensions;
extern size_t maxshownlistlen;
extern bool print_timestamps;
extern bool print_reltimestamps;
extern bool print_uptimestamps;

#ifdef __GNUC__
#define UNUSED __attribute__ ((unused))
#define FORMAT(func,fmtarg,dotarg) __attribute__((format(func,fmtarg,dotarg)));
#else
#define UNUSED
#define FORMAT(func,fmtarg,dotarg)
#endif

#ifndef HAVE_STRNDUP
char *strndup(const char *,size_t);
#endif
