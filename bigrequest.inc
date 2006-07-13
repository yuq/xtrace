/*  This file is part of "xtrace"
 *  Copyright (C) 2005 Bernhard R. Link
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
/* This file is based on the following document:
  		   Big Requests Extension

			Version 2.0
		   X Consortium Standard
		 X Version 11, Release 6.4

		       Bob Scheifler
		     X Consortium, Inc.
Copyright (C) 1993, 1994 X Consortium

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated documenta-
tion files (the ``Software''), to deal in the Software with-
out restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to
whom the Software is furnished to do so, subject to the fol-
lowing conditions:

The above copyright notice and this permission notice shall
be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED ``AS IS'', WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PUR-
POSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE X CONSOR-
TIUM BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.

Except as contained in this notice, the name of the X Con-
sortium shall not be used in advertising or otherwise to
promote the sale, use or other dealings in this Software
without prior written authorization from the X Consortium.
*/

#define EOP {0,NULL,0,NULL}

#define parameterBigReqEnable parameterEmpty

const struct parameter returnBigReqEnable[] ={
	{	8,	"maximum-request-length",	ft_UINT32,	NULL},
	EOP
};


#define rb(a) { #a , parameter ## a , return ## a ,NULL,NULL}
static const struct request extensionBIGREQUEST[] = {
	rb(BigReqEnable)
};
#undef rb

#define ev(name) { #name , eparam ## name }
static const struct event eventsBIGREQUEST[] = {
};
#undef ev

static const char *errorsBIGREQUEST[] = {};

#undef EOP
