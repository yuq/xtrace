#define EOC {-1, NULL}

static const struct constant c_device_change[] = {
	{0,	"Added"},
	{1,	"Removed"},
	{2,	"Enabled"},
	{3,	"Disabled"},
	{4,	"Unrecoverable"},
	EOC
};

static const struct constant c_syncmode[] = {
	{0,	"AsyncThisDevice"},
	{1,	"SyncThisDevice"},
	{2,	"ReplayThisDevice"},
	{3,	"AsyncOtherDevice"},
	{4,	"AsyncAll"},
	{5,	"SyncAll"},
	EOC
};

static const struct constant c_device_use[] = {
	{0,	"Pointer"},
	{1,	"Keyboard"},
	{2,	"ExtensionDevice"},
	{3,	"ExtensionKeyboard"},
	{4,	"ExtensionPointer"},
	EOC
};

static const struct constant c_usexkeyboard[] = {
	{0xFF,	"UseXKeyboard"},
	EOC
};

static const struct constant c_anykey[] = {
	{0x00,	"AnyKey"},
	EOC
};

static const struct constant c_anybutton[] = {
	{0x00,	"AnyButton"},
	EOC
};

/* there is only one set of constants in the header files for this,
   so I assume this are the correct values and what is described for most
   other status values in the XIproto.ps is just bogus */
static const struct constant c_device_status[] = {
	{0,	"Success"},
	{1,	"AlreadyGrabbed"},
	{2,	"InvalidTime"},
	{3,	"NotViewable"},
	{4,	"Frozen"},
	EOC
};

static const struct constant c_input_class_id[] = {
	{0,	"key"},
	{1,	"button"},
	{2,	"valuator"},
	{3,	"feedback"},
	{4,	"proximity"},
	{5,	"focus"},
	{6,	"other"},
	EOC
};

static const struct constant c_device_mode[] = {
	{0,	"relative"},
	{1,	"absolute"},
	EOC
};

static const struct constant c_device_mode_and_prox[] = {
	{0,	"relative, in proximity"},
	{1,	"absolute, in proximity"},
	{2,	"relative, out of proximity"},
	{3,	"absolute, out of proximity"},
	EOC
};

static const struct constant c_classes_reported[] = {
	{0x01,	"reporting keys"},
	{0x02,	"reporting buttons"},
	{0x04,	"reporting valuators"},
	{0x40,	"absolute"},
	{0x80,	"out of proximity"},
	EOC
};

static const struct constant c_feedback_class[] = {
	{0,	"Kbd"},
	{1,	"Ptr"},
	{2,	"String"},
	{3,	"Integer"},
	{4,	"Led"},
	{5,	"Bell"},
	EOC
};

static const struct constant c_auto_repeat_mode[] = {
	{0,	"Off"},
	{1,	"On"},
	{2,	"Default"},
	EOC
};

static const struct constant c_dv_pointer[] = {
	{(1L << 0),	"AccelNum"},
	{(1L << 1),	"AccelDenom"},
	{(1L << 2),	"Threshold"},
	EOC
};
static const struct constant c_dv_keyboardbellled[] = {
	{(1L<<0),	"KeyClickPercent"},
	{(1L<<1),	"Percent"},
	{(1L<<2),	"Pitch"},
	{(1L<<3),	"Duration"},
	{(1L<<4),	"Led"},
	{(1L<<5),	"LedMode"},
	{(1L<<6),	"Key"},
	{(1L<<7),	"AutoRepeatMode"},
	EOC
};
static const struct constant c_dv_string[] = {
	{(1L << 0),	"String"},
	EOC
};
static const struct constant c_dv_integer[] = {
	{(1L << 0),	"Integer"},
	EOC
};

#undef EOC
#define EOP {0,NULL,0,NULL}
#define LC(len) {len,NULL,0,NULL}

static const struct parameter parameterXInputFake[] = {
	{	 0,	"unsupported",	ft_LISTofCARD8,	NULL},
	EOP
};

static const struct parameter returnXInputFake[] = {
	{	 0,	"unsupported",	ft_LISTofCARD8,	NULL},
	EOP
};

static const struct parameter parameterXInputGet[] = {
	EOP
};

static const struct parameter parameterXInputGetExtensionVersion[] = {
	{	 4,	"len",	ft_COUNT16,	NULL},
	{	 8,	"name",	ft_STRING8,	NULL},
	EOP
};

static const struct parameter returnXInputGetExtensionVersion[] = {
	{	 8,	"major_version",	ft_UINT16,	NULL},
	{	10,	"minor_version",	ft_UINT16,	NULL},
	{	12,	"present",	ft_BOOL},
	EOP
};

#define parameterXInputListInputDevices parameterXInputGet

static const struct parameter structAXISINFO[] = {
	LC(12),
	{	0,	"resolution",	ft_UINT32,	0},
	{	4,	"min",	ft_UINT32,	0},
	{	8,	"max",	ft_UINT32,	0},
	EOP
};
#define ft_LISTofAXISINFO	ft_LISTofStruct, (void*)structAXISINFO

static const struct parameter structpartKEYINFO[] = {
	{	2,	"min keycode",	ft_CARD8,	NULL},
	{	3,	"max keycode",	ft_CARD8,	NULL},
	{	4,	"#keys",	ft_UINT16,	NULL},
	{ 	8,	"",	ft_LASTMARKER,	NULL},
	EOP
};
static const struct parameter structpartBUTTONINFO[] = {
	{	2,	"#buttons",	ft_CARD16,	NULL},
	{ 	4,	"",	ft_LASTMARKER,	NULL},
	EOP
};
static const struct parameter structpartVALUATORINFO[] = {
	{	2,	"#axes",	ft_CARD16,	NULL},
	{	3,	"mode",		ft_ENUM8,	c_device_mode},
	{ 	4,	"motion buffer size",	ft_UINT32,	NULL},
	{	2,	"#axes",	ft_COUNT16,	NULL},
	{	8,	"axes",	ft_LISTofAXISINFO},
	EOP
};

/* that's what xspecs says it would like:

static const struct parameter structINPUTINFO[] = {
	LC(4),
//	{	0,	"class id",	ft_ENUM8,	c_class_id},
	{	0,	"\0",	ft_IF8,	(void*)structpartKEYINFO},
	{	0,	"\1",	ft_IF8,	(void*)structpartBUTTONINFO},
	{	0,	"\2",	ft_IF8,	(void*)structpartVALUATORINFO},
	{	1,	"len",	ft_COUNT8,	NULL},
	{	0,	"unsupported",	ft_LISTofCARD8,	NULL},
	EOP
};
#define ft_LISTofINPUTINFO	ft_LISTofVarStruct, (void*)structINPUTINFO

static const struct parameter structSTR[] = {
	LC(1),
	{	0,	"len",	ft_COUNT8,	NULL},
	{	1,	"value",	ft_STRING8, NULL},
	{ ROUND_32,	"",	ft_LASTMARKER,	NULL},
	EOP
};
#define ft_STR	ft_Struct, (void*)structSTR

static const struct parameter structDEVICEINFO[] = {
	LC(8),
	{	0,	"type",	ft_CARD32,	NULL},
	{	4,	"id",	ft_CARD8,	NULL},
	{	6,	"use",	ft_ENUM8,	c_device_use},
	{	5,	"#classes",	ft_COUNT8,	NULL},
	{	8,	"classes",	ft_LISTofINPUTINFO},
	{ OFS_LATER,	"name",	ft_STR},
	EOP
};
#define ft_LISTofDEVICEINFO	ft_LISTofVarStruct, (void*)structDEVICEINFO

static const struct parameter returnXInputListInputDevices[] = {
	{	 8,	"#devices",	ft_COUNT8,	NULL},
	{	32,	"devices",	ft_LISTofDEVICEINFO},
	EOP
};

but the implementation in reality it is totally different:

first come all the device structs, then all the INPUTINFO structs,
then all the names. To know how many INPUTINFO structs there are,
one would need to sum the numbers from the devices, which we cannot
do yet. So we assume that none will have a name with at most 2 characters:
 */

static const struct parameter structINPUTINFO[] = {
	LC(4),
	{	0,	"\0",	ft_IF8,	(void*)structpartKEYINFO},
	{	0,	"\1",	ft_IF8,	(void*)structpartBUTTONINFO},
	{	0,	"\2",	ft_IF8,	(void*)structpartVALUATORINFO},
/* otherwise we assume that it is time for the strings */
	{	0,	"len",	ft_COUNT8,	NULL},
	{	1,	"name",	ft_STRING8, NULL},
	EOP
};
#define ft_LISTofINPUTINFO	ft_LISTofVarStruct, (void*)structINPUTINFO

static const struct parameter structDEVICEINFO[] = {
	LC(8),
	{	0,	"type",	ft_CARD32,	NULL},
	{	4,	"id",	ft_CARD8,	NULL},
	{	5,	"#classes",	ft_UINT8,	NULL},
	{	6,	"use",	ft_ENUM8,	c_device_use},
	EOP
};
#define ft_LISTofDEVICEINFO	ft_LISTofStruct, (void*)structDEVICEINFO

static const struct parameter returnXInputListInputDevices[] = {
	{	 8,	"#devices",	ft_COUNT8,	NULL},
	{	32,	"devices",	ft_LISTofDEVICEINFO},
	RESET_COUNTER,
	{ OFS_LATER,	"infos",	ft_LISTofINPUTINFO},
	EOP
};

/* The rest I had no program to test with. Judging from the problems
   above, that might mean the actual code is totally different, too */

static const struct parameter parameterXInputDevice[] = {
	{	 4,	"device",	ft_CARD8,	NULL},
	EOP
};
#define  parameterXInputOpenDevice parameterXInputDevice

static const struct parameter structINPUTCLASSINFO[] = {
	LC(2),
	{	0,	"class",	ft_ENUM8,	c_input_class_id},
	{	1,	"event type base",	ft_CARD8,	NULL},
	EOP
};
#define ft_LISTofINPUTCLASSINFO	ft_LISTofStruct, (void*)structINPUTCLASSINFO
static const struct parameter returnXInputOpenDevice[] = {
	{	 8,	"#classes",	ft_COUNT8,	NULL},
	{	32,	"classes",	ft_LISTofINPUTCLASSINFO},
	EOP
};

#define  parameterXInputCloseDevice parameterXInputDevice

static const struct parameter parameterXInputSetDeviceMode[] = {
	{	 4,	"device",	ft_CARD8,	NULL},
	{	 5,	"mode",	ft_ENUM8,	c_device_mode},
	EOP
};

static const struct parameter returnXInputStatus[] = {
	{	 8,	"status",	ft_CARD8,	c_device_status},
	EOP
};
#define returnXInputSetDeviceMode returnXInputStatus

#define ft_LISTofEVENTCLASS ft_LISTofCARD32, NULL

static const struct parameter parameterXInputSelectExtensionEvent[] = {
	{	 4,	"window",	ft_WINDOW,	NULL},
	{	 8,	"count",	ft_UINT16,	NULL},
	{	12,	"desired events", ft_LISTofEVENTCLASS},
	EOP
};

static const struct parameter parameterXInputGetSelectedExtensionEvents[] = {
	{	 4,	"window",	ft_WINDOW,	NULL},
	EOP
};
static const struct parameter returnXInputGetSelectedExtensionEvents[] = {
	{	 8,	"#this client",	ft_COUNT16,	NULL},
	{	32,	"this client",	ft_LISTofEVENTCLASS},
	{	10,	"#all clients",	ft_COUNT16,	NULL},
	{ OFS_LATER,	"all clients",	ft_LISTofEVENTCLASS},
	EOP
};

static const struct parameter parameterXInputChangeDeviceDontPropagateList[] = {
	{	 4,	"window",	ft_WINDOW,	NULL},
	{	 8,	"count",	ft_COUNT16,	NULL},
	{	10,	"mode",	ft_ENUM8,	c_device_mode},
	{	12,	"desired events", ft_LISTofEVENTCLASS},
	EOP
};

#define parameterXInputGetDeviceDontPropagateList parameterXInputGetSelectedExtensionEvents

static const struct parameter returnXInputGetDeviceDontPropagateList[] = {
	{	 8,	"count",	ft_COUNT16,	NULL},
	{	32,	"list",	ft_LISTofEVENTCLASS},
	EOP
};

static const struct parameter parameterXInputGetDeviceMotionEvents[] = {
	{	 4,	"start-time",	ft_TIMESTAMP,	c_curtime},
	{	 8,	"stop-time",	ft_TIMESTAMP,	c_curtime},
	{	10,	"device",	ft_CARD8,	NULL},
	EOP
};

static const struct parameter structDEVICETIMECOORD[] = {
	LC(4),
	{	 0,	"time",	ft_TIMESTAMP,	NULL},
	{	 0,	"axes",	ft_GET,	NULL},
	{	 0,	"valuators",	ft_LISTofUINT32,	NULL},
	EOP
};
#define ft_LISTofDEVICETIMECOORD ft_LISTofVarStruct, (void*)structDEVICETIMECOORD

static const struct parameter returnXInputGetDeviceMotionEvents[] = {
	{	 8,	"#events",	ft_UINT32,	NULL},
	{	12,	"axes",	ft_UINT8,	NULL},
	{	12,	"axes",	ft_PUSH8,	NULL},
	{	13,	"mode",	ft_ENUM8,	c_device_mode},
	{ 	32,	"events",	ft_LISTofDEVICETIMECOORD},
	EOP
};

#define parameterXInputChangeKeyboardDevice parameterXInputDevice
#define returnXInputChangeKeyboardDevice returnXInputStatus

static const struct parameter parameterXInputChangePointerDevice[] = {
	{	 4,	"xaxis",	ft_CARD8,	NULL},
	{	 5,	"yaxis",	ft_CARD8,	NULL},
	{	 6,	"device",	ft_CARD8,	NULL},
	EOP
};
#define returnXInputChangePointerDevice returnXInputStatus

static const struct parameter parameterXInputGrabDevice[] = {
	{	 4,	"window",	ft_WINDOW,	NULL},
	{	 8,	"time",	ft_TIMESTAMP,	c_curtime},
	{	12,	"#event",	ft_COUNT16,	NULL},
	{	14,	"this-device-mode",	ft_ENUM8,	c_synmode},
	{	15,	"other-device-mode",	ft_ENUM8,	c_synmode},
	{	16,	"owner-events",	ft_BOOL},
	{	17,	"device",	ft_CARD8,	NULL},
	{	20,	"events",	ft_LISTofEVENTCLASS},
	EOP
};
#define returnXInputGrabDevice returnXInputStatus

static const struct parameter parameterXInputUngrabDevice[] = {
	{	 4,	"time",	ft_TIMESTAMP,	c_curtime},
	{	 8,	"device",	ft_CARD8,	NULL},
	EOP
};

static const struct parameter parameterXInputGrabDeviceKey[] = {
	{	 4,	"window",	ft_WINDOW,	NULL},
	{	 8,	"#event",	ft_COUNT16,	NULL},
	{	10,	"modifiers",	ft_SETofKEYMASK},
	{	12,	"modifier_device",	ft_CARD8,	c_usexkeyboard},
	{	13,	"grabbed_device",	ft_CARD8,	NULL},
	{	14,	"key",	ft_CARD8,	c_anykey},
	{	15,	"this-device-mode",	ft_ENUM8,	c_synmode},
	{	16,	"other-device-mode",	ft_ENUM8,	c_synmode},
	{	17,	"owner-events",	ft_BOOL},
	{	20,	"events",	ft_LISTofEVENTCLASS},
	EOP
};

static const struct parameter parameterXInputUngrabDeviceKey[] = {
	{	 4,	"window",	ft_WINDOW,	NULL},
	{	 8,	"modifiers",	ft_SETofKEYMASK},
	{	10,	"modifier_device",	ft_CARD8,	c_usexkeyboard},
	{	11,	"key",	ft_CARD8,	c_anykey},
	{	12,	"grabbed_device",	ft_CARD8,	NULL},
	EOP
};


static const struct parameter parameterXInputGrabDeviceButton[] = {
	{	 4,	"window",	ft_WINDOW,	NULL},
	{	 8,	"grabbed_device",	ft_CARD8,	NULL},
	{	 9,	"modifier_device",	ft_CARD8,	c_usexkeyboard},
	{	10,	"#event",	ft_COUNT16,	NULL},
	{	12,	"modifiers",	ft_SETofKEYMASK},
	{	14,	"this-device-mode",	ft_ENUM8,	c_synmode},
	{	15,	"other-device-mode",	ft_ENUM8,	c_synmode},
	{	16,	"button",	ft_UINT8,	c_anybutton},
	{	17,	"owner-events",	ft_BOOL},
	{	20,	"events",	ft_LISTofEVENTCLASS},
	EOP
};

static const struct parameter parameterXInputUngrabDeviceButton[] = {
	{	 4,	"window",	ft_WINDOW,	NULL},
	{	 8,	"modifiers",	ft_SETofKEYMASK},
	{	10,	"modifier_device",	ft_CARD8,	c_usexkeyboard},
	{	11,	"button",	ft_UINT8,	c_anybutton},
	{	12,	"grabbed_device",	ft_CARD8,	NULL},
	EOP
};

static const struct parameter parameterXInputAllowDeviceEvents[] = {
	{	 4,	"time",	ft_TIMESTAMP,	c_curtime},
	{	 8,	"mode",	ft_ENUM8,	c_syncmode},
	{	 9,	"device",	ft_CARD8,	NULL},
	EOP
};

#define  parameterXInputGetDeviceFocus parameterXInputDevice
static const struct parameter returnXInputGetDeviceFocus[] = {
	{	 8,	"focus",	ft_WINDOW,	c_revertto},
	{	12,	"time",	ft_TIMESTAMP,	NULL},
	{	16,	"revert-to",	ft_ENUM8,	c_revertto},
	EOP
};

static const struct parameter parameterXInputSetDeviceFocus[] = {
	{	 4,	"focus",	ft_WINDOW,	c_revertto},
	{	 8,	"time",	ft_TIMESTAMP,	NULL},
	{	12,	"revert-to",	ft_ENUM8,	c_revertto},
	{	13,	"device",	ft_CARD8,	NULL},
	EOP
};

static const struct parameter structFRACTION[] = {
	LC(4),
	{	 0,	"numerator",	ft_UINT16,	NULL},
	{	 2,	"denominator",	ft_UINT16,	NULL},
	EOP
};
#define ft_FRACTION	ft_Struct, (void*)structFRACTION

static const struct parameter feedbackstateKBD[] = {
	{	 4,	"pitch",	ft_UINT16,	NULL},
	{	 6,	"duration",	ft_UINT16,	NULL},
	{	 8,	"led_mask",	ft_CARD32,	NULL},
	{	12,	"led_values",	ft_CARD32,	NULL},
	{	16,	"global-auto-repeat",	ft_BOOL},
	{	17,	"click",	ft_UINT8,	NULL},
	{	18,	"percent",	ft_UINT8,	NULL},
	SET_COUNTER(32),
	{	20,	"auto-repeats",	ft_LISTofCARD8,	NULL},
	EOP
};
static const struct parameter feedbackstatePTR[] = {
	{	 6,	"acceleration",	ft_FRACTION},
	{	10,	"treshold",	ft_UINT16,	NULL},
	{ 	12,	"",	ft_LASTMARKER,	NULL},
	EOP
};
static const struct parameter feedbackstateSTRING[] = {
	{	 4,	"max symbols",	ft_UINT16,	NULL},
	{	 6,	"#keysyms",	ft_COUNT16,	NULL},
	{	 8,	"keysyms",	ft_LISTofKEYSYM,	NULL},
	EOP
};
static const struct parameter feedbackstateINTEGER[] = {
	{	 4,	"resolution",	ft_UINT32,	NULL},
	{	 8,	"min",	ft_INT32,	NULL},
	{	12,	"max",	ft_INT32,	NULL},
	{ 	16,	"",	ft_LASTMARKER,	NULL},
	EOP
};
static const struct parameter feedbackstateLED[] = {
	{	 4,	"mask",	ft_CARD32,	NULL},
	{	 8,	"values",	ft_CARD32,	NULL},
	{ 	12,	"",	ft_LASTMARKER,	NULL},
	EOP
};
static const struct parameter feedbackstateBELL[] = {
	{	 4,	"percent",	ft_UINT8,	NULL},
	{	 8,	"pitch",	ft_UINT16,	NULL},
	{	10,	"duration",	ft_UINT16,	NULL},
	{ 	12,	"",	ft_LASTMARKER,	NULL},
	EOP
};
static const struct parameter structFEEDBACKSTATE[] = {
	LC(4),
	/* XIproto.ps has strange values here, XI.h looks more reasonable: */
	{	 0,	"feedback class",	ft_ENUM8,	c_feedback_class},
	{	 1,	"id",	ft_CARD8,	NULL},
	{	 0,	"\0",	ft_IF8,	(void*)feedbackstateKBD},
	{	 0,	"\1",	ft_IF8,	(void*)feedbackstatePTR},
	{	 0,	"\2",	ft_IF8,	(void*)feedbackstateSTRING},
	{	 0,	"\3",	ft_IF8,	(void*)feedbackstateINTEGER},
	{	 0,	"\4",	ft_IF8,	(void*)feedbackstateLED},
	{	 0,	"\5",	ft_IF8,	(void*)feedbackstateBELL},
	/* fallback in case of unsupported: */
	{	 2,	"length",		ft_COUNT16,	NULL},
	{	 0,	"sunsupported",		ft_LISTofCARD8,	NULL},
	EOP
};
#define ft_LISTofFEEDBACKSTATE ft_LISTofVarStruct, (void*)structFEEDBACKSTATE

#define  parameterXInputGetFeedbackControl parameterXInputDevice
static const struct parameter returnXInputGetFeedbackControl[] = {
	{	 8,	"#feedbacks",	ft_COUNT16,	NULL},
	{	32,	"feedbacks",	ft_LISTofFEEDBACKSTATE},
	EOP
};

static const struct parameter feedbackcontrolKBD[] = {
	{	 4,	"mask",	ft_BITMASK32,	c_dv_keyboardbellled},
	{	16,	"key",	ft_CARD8,	NULL},
	{	17,	"auto-repeat",	ft_ENUM8,	c_auto_repeat_mode},
	{	18,	"click-percent",	ft_UINT8,	NULL},
	{	19,	"bell-percent",	ft_UINT8,	NULL},
	{	20,	"bell-pitch",	ft_UINT16,	NULL},
	{	22,	"bell-duration",	ft_UINT16,	NULL},
	{	24,	"led_mask",	ft_CARD32,	NULL},
	{	28,	"led_values",	ft_CARD32,	NULL},
	EOP
};
static const struct parameter feedbackcontrolPTR[] = {
	{	 4,	"mask",	ft_BITMASK32,	c_dv_pointer},
	{	18,	"acceleration",	ft_FRACTION},
	{	22,	"treshold",	ft_UINT16,	NULL},
	EOP
};
static const struct parameter feedbackcontrolSTRING[] = {
	{	 4,	"mask",	ft_BITMASK32,	c_dv_string},
	{	18,	"#keysyms",	ft_COUNT16,	NULL},
	{	20,	"keysyms",	ft_LISTofCARD32,	NULL},
	EOP
};
static const struct parameter feedbackcontrolINTEGER[] = {
	{	 4,	"mask",	ft_BITMASK32,	c_dv_integer},
	{	16,	"integer",	ft_INT32,	NULL},
	EOP
};
static const struct parameter feedbackcontrolLED[] = {
	{	 4,	"mask",	ft_BITMASK32,	c_dv_keyboardbellled},
	{	16,	"led_mask",	ft_CARD32,	NULL},
	{	20,	"led_values",	ft_CARD32,	NULL},
	EOP
};
static const struct parameter feedbackcontrolBELL[] = {
	{	 4,	"mask",	ft_BITMASK32,	c_dv_keyboardbellled},
	{	16,	"percent",	ft_UINT8,	NULL},
	{	20,	"pitch",	ft_INT16,	NULL},
	{	22,	"duration",	ft_INT16,	NULL},
	EOP
};
static const struct parameter parameterXInputChangeFeedbackControl[] = {
	{	 8,	"device",	ft_CARD8,	NULL},
	{	 9,	"feedback id",	ft_CARD8,	NULL},
	{	12,	"feedback class",	ft_ENUM8, c_feedback_class},
	{	13,	"feedback id",	ft_CARD8,	NULL},
	{	12,	"\0",	ft_IF8,	(void*)feedbackcontrolKBD},
	{	12,	"\1",	ft_IF8,	(void*)feedbackcontrolPTR},
	{	12,	"\2",	ft_IF8,	(void*)feedbackcontrolSTRING},
	{	12,	"\3",	ft_IF8,	(void*)feedbackcontrolINTEGER},
	{	12,	"\4",	ft_IF8,	(void*)feedbackcontrolLED},
	{	12,	"\5",	ft_IF8,	(void*)feedbackcontrolBELL},
	{	14,	"length",	ft_COUNT16,	NULL},
	{	12,	"unsupported",	ft_LISTofCARD8,	NULL},
	EOP
};

static const struct parameter parameterXInputGetDeviceKeyMapping[] = {
	{	 4,	"device",	ft_CARD8,	NULL},
	{	 5,	"firstKeyCode",	ft_CARD8,	NULL},
	{	 6,	"count",	ft_UINT8,	NULL},
	EOP
};
static const struct parameter returnXInputGetDeviceKeyMapping[] = {
	{	 8,	"keysSyms/keyCode",	ft_UINT8,	NULL},
	{	32,	"keysyms",	ft_LISTofCARD32,	NULL},
	EOP
};

static const struct parameter parameterXInputChangeDeviceKeyMapping[] = {
	{	 4,	"device",	ft_CARD8,	NULL},
	{	 5,	"firstKeyCode",	ft_CARD8,	NULL},
	{	 6,	"#keycodes",	ft_UINT8,	NULL},
	{	 7,	"#keySyms/keyCode",	ft_UINT8,	NULL},
	{	 8,	"keysyms",	ft_LISTofCARD32,	NULL},
	EOP
};

#define  parameterXInputGetDeviceModifierMapping parameterXInputDevice
static const struct parameter returnXInputGetDeviceModifierMapping[] = {
	{	 8,	"keycodes/modifier",	ft_UINT8,	NULL},
	{	32,	"keycodes",	ft_LISTofCARD8,	NULL},
	EOP
};

static const struct parameter parameterXInputSetDeviceModifierMapping[] = {
	{	 4,	"device",	ft_CARD8,	NULL},
	{	 5,	"keycodes/modifier",	ft_UINT8,	NULL},
	{	 8,	"keycodes",	ft_LISTofCARD8,	NULL},
	EOP
};
#define returnXInputSetDeviceModifierMapping returnXInputStatus

#define  parameterXInputGetDeviceButtonMapping parameterXInputDevice
static const struct parameter returnXInputGetDeviceButtonMapping[] = {
	{	 8,	"l(map)",	ft_COUNT8,	NULL},
	{	32,	"map",	ft_LISTofCARD8,	NULL},
	EOP
};

static const struct parameter parameterXInputSetDeviceButtonMapping[] = {
	{	 4,	"device",	ft_CARD8,	NULL},
	{	 5,	"l(map)",	ft_COUNT8,	NULL},
	{	 8,	"map",	ft_LISTofCARD8,	NULL},
	EOP
};
#define returnXInputSetDeviceButtonMapping returnXInputStatus


static const struct parameter structpartKEYSTATE[] = {
	{	 2,	"#keys",	ft_UINT8,	NULL},
	SET_COUNTER(32),
	{	 4,	"key states",	ft_LISTofCARD8,	NULL},
	EOP
};
static const struct parameter structpartBUTTONSTATE[] = {
	{	 2,	"#buttons",	ft_UINT8,	NULL},
	SET_COUNTER(32),
	{	 4,	"button states",	ft_LISTofCARD8,	NULL},
	EOP
};
static const struct parameter structpartVALUATORSTATE[] = {
	{	 2,	"#valuators",	ft_COUNT8,	NULL},
	{	 3,	"mode",	ft_ENUM8,	c_device_mode_and_prox},
	{	 4,	"valuator states",	ft_LISTofCARD32,	NULL},
	EOP
};
static const struct parameter structINPUTSTATE[] = {
	LC(2),
	{	 0,	"class",	ft_ENUM8,	c_input_class_id},
	{	 0,	"\0",	ft_IF8,	(void*)structpartKEYSTATE},
	{	 0,	"\1",	ft_IF8,	(void*)structpartBUTTONSTATE},
	{	 0,	"\2",	ft_IF8,	(void*)structpartVALUATORSTATE},
	{	 1,	"length",	ft_COUNT8,	NULL},
	{	 0,	"unsupported",	ft_LISTofCARD8,	NULL},
	EOP
};
#define ft_LISTofINPUTSTATE ft_LISTofVarStruct,(void*)structINPUTSTATE
#define parameterXInputQueryDeviceState parameterXInputDevice
static const struct parameter returnXInputQueryDeviceState[] = {
	{	 8,	"#classes",	ft_COUNT8,	NULL},
	{	32,	"classes",	ft_LISTofINPUTSTATE},
	EOP
};

/*
static const struct parameter parameterXInputSendExtensionEvent[] = {
	EOP
};
*/

static const struct parameter parameterXInputDeviceBell[] = {
	{	 4,	"device",	ft_CARD8,	NULL},
	{	 5,	"feedback id",	ft_CARD8,	NULL},
	{	 6,	"feedback class",	ft_ENUM8, c_feedback_class},
	{	 7,	"percent",	ft_INT8,	NULL},
	EOP
};

/*
static const struct parameter parameterXInputSetDeviceValuators[] = {
	EOP
};
static const struct parameter returnXInputSetDeviceValuators[] = {
	EOP
};

static const struct parameter parameterXInputGetDeviceControl[] = {
	EOP
};
static const struct parameter returnXInputGetDeviceControl[] = {
	EOP
};

static const struct parameter parameterXInputChangeDeviceControl[] = {
	EOP
};
#define returnXInputChangeDeviceControl returnXInputStatus
*/

#define ra(a) { #a , parameterXInput ## a , NULL,NULL,NULL}
#define rb(a) { #a , parameterXInput ## a , returnXInput ## a ,NULL,NULL}
#define re(a) { #a , parameterXInputFake , NULL, NULL,NULL}
#define rf(a) { #a , parameterXInputFake , returnXInputFake, NULL,NULL}
static const struct request extensionXInput[] = {
	re(Nothing), /* 0 */
	rb(GetExtensionVersion), /* 1 */
	rb(ListInputDevices), /* 2 */
	rb(OpenDevice), /* 3 */
	ra(CloseDevice), /* 4 */
	rb(SetDeviceMode), /* 5 */
	ra(SelectExtensionEvent), /* 6 */
	rb(GetSelectedExtensionEvents), /* 7 */
	ra(ChangeDeviceDontPropagateList), /* 8 */
	rb(GetDeviceDontPropagateList), /* 9 */
	rb(GetDeviceMotionEvents), /* 10 */
	rb(ChangeKeyboardDevice), /* 11 */
	rb(ChangePointerDevice), /* 12 */
	rb(GrabDevice), /* 13 */
	ra(UngrabDevice), /* 14 */
	ra(GrabDeviceKey), /* 15 */
	ra(UngrabDeviceKey), /* 16 */
	ra(GrabDeviceButton), /* 17 */
	ra(UngrabDeviceButton), /* 18 */
	ra(AllowDeviceEvents), /* 19 */
	rb(GetDeviceFocus), /* 20 */
	ra(SetDeviceFocus), /* 21 */
	rb(GetFeedbackControl), /* 22 */
	ra(ChangeFeedbackControl), /* 23 */
	rb(GetDeviceKeyMapping), /* 24 */
	ra(ChangeDeviceKeyMapping), /* 25 */
	rb(GetDeviceModifierMapping), /* 26 */
	rb(SetDeviceModifierMapping), /* 27 */
	rb(GetDeviceButtonMapping), /* 28 */
	rb(SetDeviceButtonMapping), /* 29 */
	rb(QueryDeviceState), /* 30 */
	re(SendExtensionEvent), /* 31 */
	ra(DeviceBell), /* 32 */
	rf(SetDeviceValuators), /* 33 */
	rf(GetDeviceControl), /* 34 */
	rf(ChangeDeviceControl) /* 35 */
};
#undef ra
#undef rb
#undef re
#undef rf

/* Events */

/* the top-most bit of the device-id (0x80) always means more events to follow.
   how to express that? */

static const struct parameter eparamXInputDeviceValuator[] = {
	{	 1,	"device",	ft_CARD8,	NULL},
	{	 4,	"state",	ft_SETofKEYBUTMASK},
	{	 6,	"#valuators",	ft_COUNT8,	NULL},
	{	 7,	"first axis",	ft_CARD8,	NULL},
	/* should be LISTofINT32? */
	{	 8,	"valuators",	ft_LISTofUINT32,	NULL},
	EOP
};

static const struct parameter eparamXInputKeyButtonPointer[] = {
	/* keycode, button, ... depending on actual event */
	{	 1,	"detail",	ft_CARD8,	NULL},
	{        4,     "timestamp",    ft_TIMESTAMP,   NULL},
	{	 8,	"root window",	ft_WINDOW,	NULL},
	{	12,	"event window",	ft_WINDOW,	NULL},
	{	16,	"child window",	ft_WINDOW,	c_none},
	{	20,	"root-x",	ft_INT16,	NULL},
	{	22,	"root-y",	ft_INT16,	NULL},
	{	24,	"event-x",	ft_INT16,	NULL},
	{	26,	"event-y",	ft_INT16,	NULL},
	{	28,	"state",	ft_SETofKEYBUTMASK},
	{	30,	"same-screen",	ft_BOOL},
	{	31,	"device",	ft_CARD8,	NULL},
	EOP
};
#define eparamXInputDeviceKeyPress eparamXInputKeyButtonPointer
#define eparamXInputDeviceKeyRelease eparamXInputKeyButtonPointer
#define eparamXInputDeviceButtonPress eparamXInputKeyButtonPointer
#define eparamXInputDeviceButtonRelease eparamXInputKeyButtonPointer

static const struct parameter eparamXInputDeviceMotionNotify[] = {
	{	 1,	"detail",	ft_ENUM8,	c_normalhint},
	{        4,     "timestamp",    ft_TIMESTAMP,   NULL},
	{	 8,	"root window",	ft_WINDOW,	NULL},
	{	12,	"event window",	ft_WINDOW,	NULL},
	{	16,	"child window",	ft_WINDOW,	c_none},
	{	20,	"root-x",	ft_INT16,	NULL},
	{	22,	"root-y",	ft_INT16,	NULL},
	{	24,	"event-x",	ft_INT16,	NULL},
	{	26,	"event-y",	ft_INT16,	NULL},
	{	28,	"state",	ft_SETofKEYBUTMASK},
	{	30,	"same-screen",	ft_BOOL},
	{	31,	"device",	ft_CARD8,	NULL},
	EOP
};

static const struct parameter eparamXInputProximity[] = {
	{        4,     "timestamp",    ft_TIMESTAMP,   NULL},
	{	 8,	"root window",	ft_WINDOW,	NULL},
	{	12,	"event window",	ft_WINDOW,	NULL},
	{	16,	"child window",	ft_WINDOW,	c_none},
	{	20,	"root-x",	ft_INT16,	NULL},
	{	22,	"root-y",	ft_INT16,	NULL},
	{	24,	"event-x",	ft_INT16,	NULL},
	{	26,	"event-y",	ft_INT16,	NULL},
	{	28,	"state",	ft_SETofKEYBUTMASK},
	{	30,	"same-screen",	ft_BOOL},
	{	31,	"device",	ft_CARD8,	NULL},
	EOP
};
#define eparamXInputProximityIn eparamXInputProximity
#define eparamXInputProximityOut eparamXInputProximity

static const struct parameter eparamXInputDeviceFocus[] = {
	{	 1,	"detail",	ft_ENUM8,	c_enterdetail},
	{        4,     "timestamp",    ft_TIMESTAMP,   NULL},
	{	 8,	"event window",	ft_WINDOW,	NULL},
	{	12,	"mode",		ft_ENUM8,	c_grabmode},
	{	13,	"device",	ft_CARD8,	NULL},
	EOP
};
#define eparamXInputDeviceFocusOut eparamXInputDeviceFocus
#define eparamXInputDeviceFocusIn eparamXInputDeviceFocus

static const struct parameter eparamXInputDeviceStateNotify[] = {
	{	 1,	"device",	ft_CARD8,	NULL},
	{        4,     "timestamp",    ft_TIMESTAMP,   NULL},
	{	11,	"reported",	ft_BITMASK8,	c_classes_reported},
	{	 8,	"#keys",	ft_COUNT8,	NULL},
	{	12,	"keys",		ft_LISTofCARD8,	NULL},
	{	 9,	"#buttons",	ft_COUNT8,	NULL},
	{ OFS_LATER,	"buttons",	ft_LISTofCARD8,	NULL},
	{	10,	"#valuators",	ft_COUNT8,	NULL},
	{ OFS_LATER,	"valuators",	ft_LISTofCARD32,	NULL},
	EOP
};

static const struct parameter eparamXInputDeviceKeystateNotify[] = {
	{	 1,	"device",	ft_CARD8,	NULL},
	{	 4,	"keys",		ft_LISTofCARD8,	NULL},
	EOP
};

static const struct parameter eparamXInputDeviceButtonstateNotify[] = {
	{	 1,	"device",	ft_CARD8,	NULL},
	{	 4,	"buttons",	ft_LISTofCARD8,	NULL},
	EOP
};

static const struct parameter eparamXInputDeviceMappingNotify[] = {
	{	 1,	"device",	ft_CARD8,	NULL},
	{	 4,	"request",	ft_CARD8,	NULL},
	{	 5,	"first key code",	ft_KEYCODE,	NULL},
	{	 6,	"count",	ft_UINT8,	NULL},
	{        8,     "timestamp",    ft_TIMESTAMP,   NULL},
	EOP
};

static const struct parameter eparamXInputChangeDeviceNotify[] = {
	{	 1,	"device",	ft_CARD8,	NULL},
	{        4,     "timestamp",    ft_TIMESTAMP,   NULL},
	{	 8,	"request",	ft_CARD8,	NULL},
	EOP
};

static const struct parameter eparamXInputDevicePresenceNotify[] = {
	{        4,     "timestamp",    ft_TIMESTAMP,   NULL},
	{	 8,	"change",	ft_ENUM8,	c_device_change},
	{	 9,	"device",	ft_CARD8,	NULL},
	{	10,	"control",	ft_CARD16,	NULL},
	EOP
};

#define ev(name) { "XINPUT " #name , eparamXInput ## name }
static const struct event eventsXInput[16] = {
	ev(DeviceValuator),
	ev(DeviceKeyPress),
	ev(DeviceKeyRelease),
	ev(DeviceButtonPress),
	ev(DeviceButtonRelease),
	ev(DeviceMotionNotify),
	ev(DeviceFocusIn),
	ev(DeviceFocusOut),
	ev(ProximityIn),
	ev(ProximityOut),
	ev(DeviceStateNotify),
	ev(DeviceMappingNotify),
	ev(ChangeDeviceNotify),
	ev(DeviceKeystateNotify),
	ev(DeviceButtonstateNotify),
	ev(DevicePresenceNotify)
};
#undef ev

static const char *errorsXInput[5] = {
	"BadDevice",
	"BadEvent",
	"BadMode",
	"DeviceBusy",
	"BadClass"
};
#undef EOP
