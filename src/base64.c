/*
 * base64.c
 * $Id: smtpauth.c,v 1.14 2009/06/12 08:55:50 taizo Exp $
 * Copyright (C) 2009 HDE, Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with GNU Emacs; see the file COPYING.  If not, write to
 * the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#define _GNU_SOURCE
#include <ctype.h>

#define B64(c)  (isascii(c) ? base64val[(int)(c)] : -1)

static const char base64char[64] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const char base64val[128] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
};


void
base64_encode(char *out, const char *in, int inlen) {

    const char *inp = in;
    char *outp = out;

    while(inlen >= 3) {
        *outp++ = base64char[(inp[0] >> 2) & 0x3f];
        *outp++ = base64char[((inp[0] & 0x03) << 4) | ((inp[1] >> 4) & 0x0f)];
        *outp++ = base64char[((inp[1] & 0x0f) << 2) | ((inp[2] >> 6) & 0x03)];
        *outp++ = base64char[inp[2] & 0x3f];
        inp += 3;
        inlen -= 3;
    }
    if(inlen > 0) {
        *outp++ = base64char[(inp[0] >> 2) & 0x3f];
        if(inlen == 1) {
            *outp++ = base64char[(inp[0] & 0x03) << 4];
            *outp++ = '=';
        }
        else {
            *outp++ = base64char[((inp[0] & 0x03) << 4) | ((inp[1] >> 4) & 0x0f)];
            *outp++ = base64char[((inp[1] & 0x0f) << 2)];
        }
        *outp++ = '=';
    }
    *outp = '\0';
}


int
base64_decode(char *out, const char *in, int inlen) {

    const char *inp = in;
    char *outp = out;
    char buf[4];

    if(inlen < 0) {
        inlen = 2100000000;
    }
    while(inlen >=4 && *inp != '\0') {
        buf[0] = *inp++;
        inlen--;
        if( B64(buf[0]) == -1) break;

        buf[1] = *inp++;
        inlen--;
        if(B64(buf[1]) == -1) break;

        buf[2] = *inp++;
        inlen--;
        if(buf[2] != '=' && B64(buf[2]) == -1) break;

        buf[3] = *inp++;
        inlen--;
        if(buf[3] != '=' && B64(buf[3]) ==  -1) break;

        *outp++ = ((B64(buf[0]) << 2) & 0xfc) | ((B64(buf[1]) >> 4) & 0x03);
        if(buf[2] != '=') {
           *outp++ = ((B64(buf[1]) & 0x0f) << 4) | ((B64(buf[2]) >> 2) & 0x0f);
           if(buf[3] != '=') {
                *outp++ = ((B64(buf[2]) & 0x03) << 6) | (B64(buf[3]) & 0x3f);
           }
        }
    }
    return outp - out;
}

