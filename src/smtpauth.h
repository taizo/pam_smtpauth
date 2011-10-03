/*
 * smtpauth.h
 * $Id: smtpauth.h,v 1.4 2009/06/12 01:23:43 taizo Exp $
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
#ifdef USE_SSL
#include <openssl/ssl.h>
#endif

#ifndef SMTPAUTH_H
#define SMTPAUTH_H

struct config {
    char *host;
    int port;
    char *username;
    char *password;
    int timeout;
    int conn_timeout;
#ifdef USE_SSL
    char *certfile;
    unsigned int use_smtps:1;
    unsigned int require_ssl:1;
    unsigned int use_sslv2:1;
    unsigned int use_sslv3:1;
    unsigned int use_tlsv1:1;
#endif
    char *trymechs;
};
typedef struct config config_t;

typedef struct {
    int fd;
#ifdef USE_SSL
    unsigned int use_ssl:1;
    SSL *ssl;
#endif
} socket_t;


typedef struct {
    socket_t *sock;
    int bytes;
    int offset;
    char buf[1024];
} buffer_t;

typedef struct {
    socket_t *sock;
    buffer_t *buf;
    int error;
    char * error_message;
#ifdef USE_SSL
    unsigned int have_starttls:1;
#endif
} smtp_t;

#endif
