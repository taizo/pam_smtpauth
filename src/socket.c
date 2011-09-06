/*
 * smtpauth.c
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include <assert.h>
#include <errno.h>
#include <syslog.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "smtpauth.h"
#include "pam_smtpauth.h"

#ifdef USE_SSL
#include <openssl/err.h>
#include <openssl/md5.h>

#ifndef MIN
#define MIN(a,b) (((a) < (b)) ? (a) : (b))
#endif

#ifndef SSIZE_MAX
#define SSIZE_MAX LONG_MAX
#endif
#endif

param_t params;

void
sig_timeout(void) {
    signal(SIGALRM, SIG_IGN);
    alarm(0);
    syslog(LOG_ERR, "[pam_smtpauth] connection is timed out");
    exit(1);
}

void
set_timeout(int timeout) {
    if(timeout == 0) {
#ifdef DEBUG
        log_debug(DEBUG_5, "clearing timeout");
#endif
        signal(SIGALRM, SIG_IGN);
        alarm(0);
    } else {
#ifdef DEBUG
        log_debug(DEBUG_5, "setting timeout: %d seconds", timeout);
#endif
        signal(SIGALRM, (void *)sig_timeout);
        alarm(timeout);
    }
}


#ifdef USE_SSL
void *
mempcpy(void *to, const void *from, size_t size) {
  memcpy(to, from, size);
  return (char *)to + size;
}

int
SSL_writev(SSL *ssl, const struct iovec *vector, int count) {

    char *buffer;
    register char *bp;
    size_t bytes=0, to_copy;
    ssize_t bytes_written;
    int i;

    for(i=0; i<count; ++i) {
#ifdef DEBUG
        log_debug(DEBUG_9, "vector[%d].iov_base %s", i, (char *)vector[i].iov_base);
        log_debug(DEBUG_9, "vector[%d].iov_len %d", i, vector[i].iov_len);
#endif
        if(SSIZE_MAX - bytes < vector[i].iov_len) {
            return -1;
        }
        bytes += vector[i].iov_len;
    }

    if((buffer = (char *)malloc(bytes))==NULL) {
        return -1;
    }

    to_copy = bytes;
    bp = buffer;
    for(i=0; i<count; ++i) {
        size_t copy = MIN(vector[i].iov_len, to_copy);
        bp = mempcpy((void *)bp, (void *)vector[i].iov_base, copy);
        to_copy -= copy;
        if(to_copy == 0) {
            break;
        }
    }
#ifdef DEBUG
    log_debug(DEBUG_9, "SSL_write: write buffer=%s", buffer);
    log_debug(DEBUG_9, "SSL_write: write bytes=%d", bytes);
#endif
    bytes_written = SSL_write(ssl, buffer, bytes);
#ifdef DEBUG
    log_debug(DEBUG_9, "SSL_write: written bytes=%d", bytes_written);
#endif
    free(buffer);
    return bytes_written;
}
#endif

int
socket_read(socket_t *sock, char *buf, size_t len) {
#ifdef USE_SSL
    if(sock->use_ssl) {
        return SSL_read(sock->ssl, buf, len);
    }
#endif
    return read(sock->fd, buf, len);
}

int
socket_write(socket_t *sock, char *buf, size_t len) {
#ifdef USE_SSL
    if(sock->use_ssl) {
        return SSL_write(sock->ssl, buf, len);
    }
#endif
    return write(sock->fd, buf, len);
}

void
socket_close(socket_t *sock) {
#ifdef USE_SSL
    if(sock->use_ssl) {
        SSL_shutdown(sock->ssl);
        SSL_free(sock->ssl);
    }
#endif
    close(sock->fd);
}

void
socket_perror(const char *func, socket_t *sock, int ret) {
#ifdef USE_SSL
    int err;

    if(sock->use_ssl) {
        switch((err = SSL_get_error(sock->ssl, ret))) {
            case SSL_ERROR_SYSCALL:
            case SSL_ERROR_SSL:
                if((err = ERR_get_error()) == 0) {
                    if(ret == 0) {
                        fprintf(stderr, "SSL_%s:got EOF\n", func);
                    } else {
                        fprintf(stderr, "SSL_%s:%d:%s\n", func, errno, strerror(errno));
                    }
                } else {
                    fprintf(stderr, "SSL_%s:%d:%s\n", func, err, ERR_error_string(err, 0));
                }
                return;
            default:
                fprintf(stderr, "SSL_%s:%d:unhandled SSL error\n", func, err);
                break;
        }
        return;
    }
#else
    (void)sock;
#endif
    if(ret) {
        perror(func);
    } else {
        fprintf(stderr, "%s: unexpected EOF\n", func);
    }
}

int
retry_writev(socket_t *sock, struct iovec *iov, int iovcnt) {

    int n;
    int cnt;
    int written;
    static int iov_max;

    iov_max = 8192;
    written = 0;

    for(;;) {
        while(iovcnt && iov[0].iov_len == 0) {
            iov++;
            iovcnt--;
        }
        if(!iovcnt) {
            return written;
        }
#ifdef USE_SSL
        if(sock->use_ssl) {
            n = SSL_writev(sock->ssl, iov, iovcnt > iov_max ? iov_max : iovcnt);
        } else {
            n = writev(sock->fd, iov, iovcnt > iov_max ? iov_max : iovcnt);
        }
#else
        n = writev(sock->fd, iov, iovcnt > iov_max ? iov_max : iovcnt);
#endif
        if(n == -1) {
            if(errno == EINVAL && iov_max > 10) {
                iov_max /= 2;
                continue;
            }
            if(errno == EINTR) {
                continue;
            }
            return -1;
        } else {
            written += n;
        }

        for(cnt=0; cnt<iovcnt; cnt++) {
            if((int)iov[cnt].iov_len > n) {
                iov[cnt].iov_base = (char *)iov[cnt].iov_base + n;
                iov[cnt].iov_len -= n;
                break;
            }
            n -= iov[cnt].iov_len;
            iov[cnt].iov_len = 0;
        }

        if(cnt == iovcnt) {
            return written;
        }
    }
}
