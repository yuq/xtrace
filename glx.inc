/* -*- mode: c; tab-width: 2; indent-tabs-mode: nil; c-basic-offset: 2; coding: utf-8-unix -*- */
/*  This file is part of "xtrace"
 *  Copyright (C) 2008,2009 RALOVICH, Kristóf
 *  modifications Copyright (C) 2009 Bernhard R. Link
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

#define EOP {0,NULL,0,NULL}
#define LC(len) {len,NULL,0,NULL}

/*{offs, name, type, ?}*/
static const struct parameter parameterUnknown[] = {
  EOP
};
static const struct parameter returnUnknown[] = {
  EOP
};

/* opcode 1 */
/* static const struct parameter listGLXRenderCommand[] = { */
/*   /\* LC(8), *\/ */
/*   {  0, "rend_len", ft_UINT16, NULL}, */
/*   {  2, "rend_op", ft_UINT16, NULL}, */
/*   EOP */
/* }; */
/* #define ft_LISTofGLXRenderCommand ft_LISTofStruct,(void*)listGLXRenderCommand */

static const struct parameter parameterglXRender[] = {
  {  4, "context_tag",  ft_CARD32, NULL},
  /* {  8, "render_commands", ft_LISTofGLXRenderCommand}, */
  {  8, "render commands (cannot yet parse)", ft_LISTofCARD8, NULL},
  EOP
};

/* opcode 2 */
static const struct parameter parameterglXRenderLarge[] = {
  {  4, "context_tag", ft_CARD32, NULL},
  {  8, "req_num",     ft_CARD16, NULL},
  { 10, "req_tot",     ft_CARD16, NULL},
  { 12, "n",           ft_CARD32, NULL},
  EOP
};

/* opcode 3 */
static const struct parameter parameterglXCreateContext[] = {
  {  4, "context",    ft_CARD32, NULL},
  {  8, "visual_id",  ft_UINT32, NULL},
  { 12, "screen",     ft_CARD32, NULL},
  { 16, "share_list", ft_CARD32, NULL},
  { 20, "is_direct",  ft_UINT8,  NULL},
  EOP
};

/* opcode 4 */
static const struct parameter parameterglXDestroyContext[] = {
  {  4, "context",         ft_CARD32, NULL},
  EOP
};

/* opcode 5 */
static const struct parameter parameterglXMakeCurrent[] = {
  {  4, "drawable",        ft_CARD32, NULL},
  {  8, "context",         ft_CARD32, NULL},
  { 12, "old_context_tag", ft_CARD32, NULL},
  EOP
};
static const struct parameter returnglXMakeCurrent[] = {
  {  8, "new_context_tag", ft_CARD32,  NULL},
  EOP
};

/* opcode 6 */
static const struct parameter parameterglXIsDirect[] = {
  {  4, "context",  ft_CARD32, NULL},
  EOP
};
static const struct parameter returnglXIsDirect[] = {
  {  8, "is_direct",  ft_UINT8,  NULL},
  EOP
};

/* opcode 7 */
static const struct parameter parameterglXQueryVersion[] = {
  {  4, "client_major_version",  ft_UINT32, NULL},
  {  8, "client_minor_version",  ft_UINT32, NULL},
  EOP
};
static const struct parameter returnglXQueryVersion[] = {
  {  8, "server_major_version",  ft_UINT32,  NULL},
  { 12, "server_minor_version",  ft_UINT32,  NULL},
  EOP
};

/* opcode 11 */
static const struct parameter parameterglXSwapBuffers[] = {
  {  4, "context_tag",  ft_CARD32, NULL},
  {  8, "drawable",     ft_CARD32, NULL},
  EOP
};

/* opcode 14 */
static const struct parameter parameterglXGetVisualConfigs[] = {
  {  4, "screen",  ft_CARD32, NULL},
  EOP
};
static const struct parameter returnglXGetVisualConfigs[] = {
  {  8, "num_visuals",  ft_UINT32,  NULL},
  { 12, "num_properties",  ft_UINT32,  NULL},
  EOP
};

/* opcode 17 */
static const struct parameter parameterglXVendorPrivateWithReply[] = {
  {  4, "vendor_op", ft_CARD32, NULL},
  {  8, "vendor_data", ft_LISTofCARD8, NULL}, /* FIXME proper size */
  EOP
};
static const struct parameter returnglXVendorPrivateWithReply[] = {
  {  8, "data1",  ft_LISTofCARD8,  NULL},
  { 32, "data2",  ft_LISTofCARD8,  NULL},
  EOP
};

/* opcode 19 */
static const struct parameter parameterglXQueryServerString[] = {
  {  4, "context_tag",  ft_CARD32, NULL},
  {  8, "name",         ft_CARD32, NULL},
  EOP
};
static const struct parameter returnglXQueryServerString[] = {
  {  8, "n",              ft_UINT32, NULL},
  { 12, "num_properties", ft_UINT32, NULL},
  { 32, "string",         ft_LISTofCARD8, NULL}, /* FIXME proper size */
  EOP
};

/* opcode 20 */
static const struct parameter parameterglXClientInfo[] = {
  {  4, "gl_client_major", ft_UINT32, NULL},
  {  8, "gl_client_minor", ft_UINT32, NULL},
  { 12, "n",               ft_UINT32, NULL},
  { 16, "extension_string", ft_LISTofCARD8, NULL}, /* FIXME proper size */
  EOP
};

/* opcode 117 */
static const struct parameter parameterglGetIntegerv[] = {
  {  4, "context_tag",  ft_CARD32, NULL},
  {  8, "pname",        ft_CARD32, NULL},
  EOP
};
static const struct parameter returnglGetIntegerv[] = {
  { 12, "n",      ft_UINT32, NULL},
  /* FIXME extend */
  EOP
};

/* opcode 101 */
static const struct parameter parameterglNewList[] = {
  {  4,  "context_tag", ft_CARD32, NULL},
  {  8,  "list",        ft_CARD32, NULL},
  {  12, "mode",        ft_CARD32, NULL},
  EOP
};

/* opcode 102 */
static const struct parameter parameterglEndList[] = {
  {  4, "context_tag",  ft_CARD32, NULL},
  EOP
};

/* opcode 103 */
static const struct parameter parameterglDeleteLists[] = {
  {  4, "context_tag",  ft_CARD32, NULL},
  {  8, "list",         ft_CARD32, NULL},
  { 12, "range",        ft_INT32,  NULL},
  EOP
};

/* opcode 104 */
static const struct parameter parameterglGenLists[] = {
  {  4, "context_tag",  ft_CARD32, NULL},
  {  8, "range",        ft_INT32, NULL},
  EOP
};
static const struct parameter returnglGenLists[] = {
  { 8,  "retval",      ft_UINT32, NULL},
  { 12, "unused", ft_LISTofCARD8, NULL},
  EOP
};

/* opcode 115 */
static const struct parameter parameterglGetError[] = {
  {  4, "context_tag",  ft_CARD32, NULL},
  EOP
};
static const struct parameter returnglGetError[] = {
  { 8,  "error",  ft_UINT32,      NULL},
  { 12, "unused", ft_LISTofCARD8, NULL},
  EOP
};

/* opcode 129 */
static const struct parameter parameterglGetString[] = {
  {  4, "context_tag",  ft_CARD32, NULL},
  {  8, "name",         ft_CARD32, NULL},
  EOP
};
static const struct parameter returnglGetString[] = {
  { 12, "n",      ft_UINT32, NULL},
  { 32, "string", ft_LISTofCARD8, NULL}, /* FIXME proper size */
  EOP
};

#define ra(a)  {#a, parameter##a,     NULL,          NULL, NULL} /* request only */
#define raf(a) {#a, parameterUnknown, NULL,          NULL, NULL}
#define rb(a)  {#a, parameter##a,     return##a,     NULL, NULL} /* request + reply */
#define rbf(a) {#a, parameterUnknown, returnUnknown, NULL, NULL}
static const struct request extensionGLX[] = {
  rb(Unknown), /* 0 */
  ra(glXRender),
  ra(glXRenderLarge),
  ra(glXCreateContext),
  ra(glXDestroyContext),
  rb(glXMakeCurrent),
  rb(glXIsDirect),
  rb(glXQueryVersion),
  raf(glXWaitGL),
  raf(glXWaitX),
  raf(glXCopyContext), /* 10 */
  ra(glXSwapBuffers),
  raf(glXUseXFont),
  raf(glXCreateGLXPixmap),
  rb(glXGetVisualConfigs),
  raf(DestroyGLXPixmap),
  raf(glXVendorPrivate),
  rb(glXVendorPrivateWithReply),
  rbf(glXQueryExtensionsString),
  rb(glXQueryServerString),
  ra(glXClientInfo), /* 20 */
  rbf(glXGetFBConfigs),
  raf(glXCreatePixmap),
  raf(glXDestroyPixmap),
  raf(glXCreateNewContext),
  rbf(QueryContext),
  rbf(glXMakeContextCurrent),
  raf(glXCreatePbuffer),
  raf(glXDestroyPbuffer),
  rbf(glXGetDrawableAttributes),
  raf(glXChangeDrawableAttributes), /* 30 */
  raf(glXCreateWindow),
  raf(glXDeleteWindow),
  raf(glXSetClientInfoARB),
  raf(glXCreateContextAttribsARB),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown), /* 40 */
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown), /* 50 */
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown), /* 60 */
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown), /* 70 */
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown), /* 80 */
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown), /* 90 */
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown),
  rb(Unknown), /* 100 */
  ra(glNewList),
  ra(glEndList),
  ra(glDeleteLists),
  rb(glGenLists),
  raf(glFeedbackBuffer),
  raf(glSelectBuffer),
  rbf(glRenderMode),
  rbf(glFinish),
  raf(glPixelStoref),
  raf(glPixelStorei), /* 110 */
  rbf(glReadPixels),
  rbf(glGetBooleanv),
  rbf(glGetClipPlane),
  rbf(glGetDoublev),
  rb(glGetError),
  rbf(GetFloatv),
  rb(glGetIntegerv),
  rbf(glGetLightfv),
  rbf(glGetLightiv),
  rbf(glGetMapdv), /* 120 */
  rbf(glGetMapfv),
  rbf(glGetMapiv),
  rbf(glGetMaterialfv),
  rbf(glGetMaterialiv),
  rbf(glGetPixelMapfv),
  rbf(glGetPixelMapuiv),
  rbf(glGetPixelMapusv),
  rbf(glGetPolygonStipple),
  rb(glGetString),
  rbf(glGetTexEnvfv), /* 130 */
  rbf(glGetTexEnviv),
  rbf(glGetTexGendv),
  rbf(glGetTexGenfv),
  rbf(glGetTexGeniv),
  rbf(glGetTexImage),
  rbf(glGetTexParameterfv),
  rbf(glGetTexParameteriv),
  rbf(glGetTexLevelParameterfv),
  rbf(glGetTexLevelParameteriv),
  rbf(glIsEnabled), /* 140 */
  rbf(glIsList),
  raf(glFlush),
  rbf(glAreTexturesResident),
  raf(glDeleteTextures),
  rbf(glGenTextures),
  rbf(glIsTexture),
  rbf(glGetColorTable),
  rbf(glGetColorTableParameterfv),
  rbf(glGetColorTableParameteriv),
  rbf(glGetConvolutionFilter), /* 150 */
  rbf(glGetConvolutionParameterfv),
  rbf(glGetConvolutionParameteriv),
  rbf(glGetSeparableFilter),
  rbf(glGetHistogram),
  rbf(glGetHistogramParameterfv),
  rbf(glGetHistogramParameteriv),
  rbf(glGetMinmax),
  rbf(glGetMinmaxParameterfv),
  rbf(glGetMinmaxParameteriv),
  rbf(glGetCompressedTexImage), /* 160 */
  raf(glDeleteQueries),
  rbf(glGenQueries),
  rbf(glIsQuery),
  rbf(glGetQueryiv),
  rbf(glGetQueryObjectiv),
  rbf(glGetQueryObjectuiv),
};
#undef rbf
#undef rb
#undef raf
#undef ra

static const struct parameter eparamGLX_PbufferClobber[] = {
  {  4, "event_type", ft_CARD16, NULL},
  {  6, "draw_type",  ft_CARD16, NULL},
  {  8, "drawable",   ft_CARD32, NULL},
  { 12, "buffer_mask", ft_CARD32, NULL},
  { 16, "aux_buffer", ft_CARD16, NULL},
  { 18, "x",          ft_CARD16, NULL},
  { 20, "y",          ft_CARD16, NULL},
  { 22, "width",      ft_CARD16, NULL},
  { 24, "height",     ft_CARD16, NULL},
  { 26, "count",      ft_CARD16, NULL},
  EOP
};

#define ev(name) { #name , eparam ## name }
static const struct event eventsGLX[] =
{
  ev(GLX_PbufferClobber)
};
#undef ev

static const char *errorsGLX[] =
{
  "GLXBadContext",
  "GLXBadContextState",
  "GLXBadDrawable",
  "GLXBadPixmap",
  "GLXBadContextTag",
  "GLXBadCurrentWindow",
  "GLXBadRenderRequest",
  "GLXBadLargeRequest",
  "GLXUnsupportedPrivateRequest",
  "GLXBadFBConfig",
  "GLXBadPbuffer",
  "GLXBadCurrentDrawable",
  "GLXBadWindow"
};

#undef EOP

