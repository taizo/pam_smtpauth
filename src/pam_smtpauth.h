/*
 * pam_smtpauth.h
 * $Id$
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

#include <sys/types.h>
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifndef PAM_SMTPAUTH_H
#define PAM_SMTPAUTH_H

/* the debug levels:
 * The level number is higer, or more debug logging is printed.
 * DEBUG_0 (the default) prints nothing.
 */
 
#define DEBUG_10 10
#define DEBUG_9   9
#define DEBUG_8   8
#define DEBUG_7   7
#define DEBUG_6   6
#define DEBUG_5   5
#define DEBUG_4   4
#define DEBUG_3   3
#define DEBUG_2   2
#define DEBUG_1   1
#define DEBUG_0   0

struct param {
    int debuglevel;
};
typedef struct param param_t;

#endif
