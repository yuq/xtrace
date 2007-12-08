#define EOP {0,NULL,0,NULL}
#define LC(len) {len,NULL,0,NULL}

static const struct parameter listScreenInfo[] = {
	LC(8),
	{	 0,	"x",			ft_INT16,	NULL},
	{	 2,	"y",			ft_INT16,	NULL},
	{	 4,	"width",		ft_UINT16,	NULL},
	{	 6,	"height",		ft_UINT16,	NULL},
	EOP
};
#define ft_LISTofScreenInfo	ft_LISTofStruct,(void*)listScreenInfo

static const struct parameter parameterPanoramiXQueryVersion[] = {
	{	 4,	"major-version",	ft_UINT8,	NULL},
	{	 5,	"minor-version",	ft_UINT8,	NULL},
	EOP
};
static const struct parameter returnPanoramiXQueryVersion[] = {
	{	 8,	"major-version",	ft_UINT16,	NULL},
	{	10,	"minor-version",	ft_UINT16,	NULL},
	EOP
};

static const struct parameter parameterPanoramiXGetState[] = {
	{	 4,	"window",		ft_Window},
	EOP
};
static const struct parameter returnPanoramiXGetState[] = {
	{	 1,	"state",		ft_CARD8,	c_bool},
	{	 8,	"window",		ft_Window},
	EOP
};

static const struct parameter parameterPanoramiXGetScreenCount[] = {
	{	 4,	"window",		ft_Window},
	EOP
};
static const struct parameter returnPanoramiXGetScreenCount[] = {
	{	 1,	"ScreenCount",		ft_INT8,	NULL},
	{	 8,	"window",		ft_Window},
	EOP
};

static const struct parameter parameterPanoramiXGetScreenSize[] = {
	{	 4,	"window",		ft_Window},
	{	 8,	"screen",		ft_UINT32,	NULL},
	EOP
};
static const struct parameter returnPanoramiXGetScreenSize[] = {
	{	 8,	"width",		ft_UINT32,	NULL},
	{	12,	"height",		ft_UINT32,	NULL},
	{	16,	"window",		ft_Window},
	{	20,	"screen",		ft_UINT32,	NULL},
	EOP
};

static const struct parameter parameterXineramaIsActive[] = {
	EOP
};
static const struct parameter returnXineramaIsActive[] = {
	{	 8,	"state",		ft_CARD32,	c_bool},
	EOP
};

static const struct parameter parameterXineramaQueryScreens[] = {
	EOP
};
static const struct parameter returnXineramaQueryScreens[] = {
	{	 8,	"number",		ft_COUNT32,	NULL},
	{	32,	"screens",		ft_LISTofScreenInfo},
	EOP
};

#define rb(a) { #a , parameter ## a , return ## a ,NULL,NULL}
static const struct request extensionXINERAMA[] = {
	rb(PanoramiXQueryVersion),
	rb(PanoramiXGetState),
	rb(PanoramiXGetScreenCount),
	rb(PanoramiXGetScreenSize),
	rb(XineramaIsActive),
	rb(XineramaQueryScreens)
};
#undef rb

static const struct event eventsXINERAMA[] = { };
static const char *errorsXINERAMA[] = { };

#undef EOP
