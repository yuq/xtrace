#define EOC {-1, NULL}

#undef EOC
#define EOP {0,NULL,0,NULL}
#define LC(len) {len,NULL,0,NULL}

static const struct parameter parameterXkbFake[] = {
	{	 0,	"unsupported",	ft_LISTofCARD8,	NULL},
	EOP
};
static const struct parameter returnXkbFake[] = {
	{	 0,	"unsupported",	ft_LISTofCARD8,	NULL},
	EOP
};

static const struct parameter parameterXkbUseExtension[] = {
	{	 4,	"major",	ft_UINT16,	NULL},
	{	 6,	"minor",	ft_UINT16,	NULL},
	EOP
};
static const struct parameter returnXkbUseExtension[] = {
	{	 8,	"major",	ft_UINT16,	NULL},
	{	10,	"minor",	ft_UINT16,	NULL},
	EOP
};

#define ra(a) { #a , parameterXkb ## a , NULL,NULL,NULL}
#define rb(a) { #a , parameterXkb ## a , returnXkb ## a ,NULL,NULL}
#define re(a) { #a , parameterXkbFake , NULL, NULL,NULL}
#define rf(a) { #a , parameterXkbFake , returnXkbFake, NULL,NULL}
static const struct request extensionXkb[] = {
// TODO:
	rb(UseExtension), /* 0 */
	re(SelectEvents), /* 1 */
	re(Unknown),
	re(Bell), /* 3 */
	rf(GetState), /* 4 */
	re(LatchLockState), /* 5 */
	rf(GetControls), /* 6 */
	re(SetControls), /* 7 */
	rf(GetMap), /* 8 */
	re(SetMap), /* 9 */
	rf(GetCompatMap), /* 10 */
	re(SetCompatMap), /* 11 */
	rf(GetIndicatorState), /* 12 */
	rf(GetIndicatorMap), /* 13 */
	re(SetIndicatorMap), /* 14 */
	rf(GetNamedIndicator), /* 15 */
	re(SetNamedIndicator), /* 16 */
	rf(GetNames), /* 17 */
	re(SetNames), /* 18 */
	rf(GetGeometry), /* 19 */
	re(SetGeometry), /* 20 */
	re(PerClientFlags), /* 21 */
	rf(ListComponents), /* 22 */
	rf(GetKbdByName), /* 23 */
	rf(GetDeviceInfo), /* 24 */
	re(SetDeviceInfo), /* 25 */
};
#undef ra
#undef rb
#undef re
#undef rf

/* Events */

static const struct parameter eparamXkbEvent[] = {
	/* all events packaged into one? WTF? */
	{	 1,	"type",	ft_ENUM8,	NULL},
	{	 4,	"time",	ft_TIMESTAMP,	NULL},
	{	 8,	"device",	ft_CARD8,	NULL},
// TODO:
	{	 9,	"not-yet-supported",	ft_LISTofCARD8,	NULL},
	EOP
};

#define ev(name) { "XKB " #name , eparamXkb ## name }
static const struct event eventsXkb[1] = {
	ev(Event)
};
#undef ev

static const char *errorsXkb[1] = {
	/* this also packs the type in subvalues,
	   to support this we need support of parsing error packets, too */
	"Keyboard",
};
#undef EOP
