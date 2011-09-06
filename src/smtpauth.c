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
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/utsname.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "smtpauth.h"
#include "pam_smtpauth.h"

#ifdef USE_SSL
#include <openssl/err.h>
#include <openssl/md5.h>
#else
#include "global.h"
#include "md5.h"
#endif

#define SMTP_EHLO_CMD "EHLO "	/* ESMTP ehlo command */
#define SMTP_AUTH_CMD "AUTH "	/* ESMTP auth command */
#define SMTP_QUIT_CMD "QUIT"	/* ESMTP quit command */
#define SMTP_NEWLINE  "\r\n"	/* ESMTP newline */

#define RESP_LEN 1000
#define RESP_IERROR	 "internal error"
#define RESP_UNAVAILABLE "remote authentication server is currently unavailable"
#define RESP_UNEXPECTED	 "unexpected response from remote authentication server"
#define RESP_SYNCERROR   "error synchronizing with remote authentication server"
#define RESP_CREDERROR   "remote authentication server rejected your credentials"

#define AUTH_NG 0
#define AUTH_OK 1

#define AUTH_PLAIN      1 << 0
#define AUTH_LOGIN      1 << 1
#define AUTH_CRAM_MD5   1 << 2
#define AUTH_DIGEST_MD5 1 << 3

#define DIGEST_MD5_REALM_LEN   256
#define DIGEST_MD5_NONCE_LEN   64
#define DIGEST_MD5_CNONCE_LEN  33
#define DIGEST_MD5_QOP_LEN     64
#define DIGEST_MD5_URI_LEN     261

extern void base64_encode(char *out, const char *in, int inlen);
extern int base64_decode(char *out, const char *in, int inlen);
extern int retry_writev(socket_t *sock, struct iovec *iov, int iovcnt);
extern int socket_read(socket_t *sock, char *buf, size_t len);
extern int socket_close(socket_t *sock);
extern void socket_perror(const char *func, socket_t *sock, int ret);
extern void set_timeout(int timeout);

void md5_hex_hmac(char *hexdigest, unsigned char *text, unsigned int text_len, unsigned char *key, unsigned int key_len);
void hmac_md5(unsigned char *text, unsigned int text_len, unsigned char *key, unsigned int key_len, unsigned char *digest);
int start_tls(smtp_t *smtp, config_t *cfg);

int smtp_quit(socket_t *sock, config_t *cfg);
int auth_plain(socket_t *sock, config_t *cfg);
int auth_login(socket_t *sock, config_t *cfg);
int auth_cram_md5(socket_t *sock, config_t *cfg);
int auth_digest_md5(socket_t *sock, config_t *cfg);

config_t global;
param_t params;

static void
bin2hex(char *out, const unsigned char *in, int in_len) {
    static const char hex[17] = "0123456789abcdef";
    int cnt;

    for(cnt=0; cnt<in_len; cnt++) {
        out[cnt * 2]       = hex[in[cnt] >> 4];
        out[(cnt * 2) + 1] = hex[in[cnt]&0x0F];
    }
}

void
make_digest(char *md5str, unsigned char *digest) {
    bin2hex(md5str, digest, 16);
    md5str[32] = '\0';
}

void
md5_hex_hmac(char *hexdigest, unsigned char *text, unsigned int text_len, unsigned char *key, unsigned int key_len) {

    unsigned char digest[16];
    int cnt;

    hmac_md5(text, text_len, key, key_len, digest);
    for(cnt=0; cnt<16; cnt++) {
        sprintf(hexdigest + 2 * cnt, "%02x", digest[cnt]);
    }
}


void
hmac_md5(unsigned char *text, unsigned int text_len, unsigned char *key, unsigned int key_len, unsigned char *digest) {

    MD5_CTX context;
    unsigned char k_ipad[64];
    unsigned char k_opad[64];
    int cnt;

    memset(k_ipad, 0, sizeof(k_ipad));
    memset(k_opad, 0, sizeof(k_opad));
    if(key_len > 64) {
        MD5_CTX tctx;

#ifdef USE_SSL
        MD5_Init(&tctx);
        MD5_Update(&tctx, key, key_len);
        MD5_Final(k_ipad, &tctx);
        MD5_Final(k_opad, &tctx);
#else
        MD5Init(&tctx);
        MD5Update(&tctx, key, key_len);
        MD5Final(k_ipad, &tctx);
        MD5Final(k_opad, &tctx);
#endif
    } else {
        memcpy(k_ipad, key, key_len);
        memcpy(k_opad, key, key_len);
    }

    for(cnt=0; cnt<64; cnt++) {
        k_ipad[cnt] ^= 0x36;
        k_opad[cnt] ^= 0x5c;
    }

#ifdef USE_SSL
    MD5_Init(&context);
    MD5_Update(&context, k_ipad, 64);
    MD5_Update(&context, text, text_len);
    MD5_Final(digest, &context);

    MD5_Init(&context);
    MD5_Update(&context, k_opad, 64);
    MD5_Update(&context, digest, 16);
    MD5_Final(digest, &context);
#else
    MD5Init(&context);
    MD5Update(&context, k_ipad, 64);
    MD5Update(&context, text, text_len);
    MD5Final(digest, &context);

    MD5Init(&context);
    MD5Update(&context, k_opad, 64);
    MD5Update(&context, digest, 16);
    MD5Final(digest, &context);
#endif
}


int
extract_token(const char *str, const char *token, char *value, int len) {

    char *p = NULL, *q = NULL;

    memset(value,0x00,sizeof(char)*len);
    if((p = strstr(str, token)) != NULL) {
        p += strlen(token);
        if(*p == '\"') {
            if((q = strchr(p + 1, '\"')) == NULL)
                return -1;
            strncpy(value, p + 1, q - p - 1 >= len ? len - 1 : q - p - 1);

	} else {
            if((q = strchr(p, ',')) == NULL)
                q += strlen(p);
	    strncpy(value, p, q - p >= len ? len - 1 : q - p);
        }
    }
#ifdef DEBUG
    log_debug(DEBUG_9, "extract_token: str=%s", str);
#endif

    return 0;
}

void
digest_md5(char *response, unsigned char *text, unsigned int text_len, const char *login, const char *passwd) {

    char realm[DIGEST_MD5_REALM_LEN];
    char nonce[DIGEST_MD5_NONCE_LEN];
    char qop[DIGEST_MD5_QOP_LEN];
    char uri[DIGEST_MD5_URI_LEN];
    char cnonce[DIGEST_MD5_CNONCE_LEN];

    unsigned char random[16];

    MD5_CTX ctx;
    unsigned char digest[16];
    char hexA1[33], hexA2[33], resp[33];


#ifdef DEBUG
    log_debug(DEBUG_9, "digest_md5: text=%s", text);
#endif

    extract_token((const char *)text, "nonce=", nonce, DIGEST_MD5_NONCE_LEN);
    extract_token((const char *)text, "realm=", realm, DIGEST_MD5_REALM_LEN);
    extract_token((const char *)text, "qop=", qop, DIGEST_MD5_QOP_LEN);

    srand(time(NULL));
    snprintf((char *)random, sizeof(random), "%ld", (long int)rand());
    bin2hex(cnonce, random, 8);
    cnonce[16] = '\0';

    sprintf(uri, "smtp/%s", realm);
#ifdef DEBUG
    log_debug(DEBUG_9, "digest_md5: realm=%s", realm);
    log_debug(DEBUG_9, "digest_md5: nonce=%s", nonce);
    log_debug(DEBUG_9, "digest_md5: qop=%s", qop);
    log_debug(DEBUG_9, "digest_md5: cnonce=%s", cnonce);
    log_debug(DEBUG_9, "digest_md5: uri=%s", uri);
#endif

    /* A1 */
#ifdef USE_SSL
    MD5_Init(&ctx);
    MD5_Update(&ctx, login, strlen(login));
    MD5_Update(&ctx, ":", 1);
    MD5_Update(&ctx, realm, strlen(realm));
    MD5_Update(&ctx, ":", 1);
    MD5_Update(&ctx, passwd, strlen(passwd));
    MD5_Final(digest, &ctx);
#else
    MD5Init(&ctx);
    MD5Update(&ctx, login, strlen(login));
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, realm, strlen(realm));
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, passwd, strlen(passwd));
    MD5Final(digest, &ctx);
#endif

#ifdef USE_SSL
    MD5_Init(&ctx);
    MD5_Update(&ctx, digest, 16);
    MD5_Update(&ctx, ":", 1);
    MD5_Update(&ctx, nonce, strlen(nonce));
    MD5_Update(&ctx, ":", 1);
    MD5_Update(&ctx, cnonce, strlen(cnonce));
    MD5_Final(digest, &ctx);
#else
    MD5Init(&ctx);
    MD5Update(&ctx, digest, 16);
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, nonce, strlen(nonce));
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, cnonce, strlen(cnonce));
    MD5Final(digest, &ctx);
#endif
    make_digest(hexA1, digest);

#ifdef DEBUG
    log_debug(DEBUG_9, "digest_md5: A1=%s", hexA1);
#endif

    /* A2 */
#ifdef USE_SSL
    MD5_Init(&ctx);
    MD5_Update(&ctx, "AUTHENTICATE:", sizeof("AUTHENTICATE:") - 1);
    MD5_Update(&ctx, uri, strlen(uri));
    if(!strcmp(qop, "auth-int")) {
        MD5_Update(&ctx, ":00000000000000000000000000000000", sizeof(":00000000000000000000000000000000") - 1);
    }
    MD5_Final(digest, &ctx);
#else
    MD5Init(&ctx);
    MD5Update(&ctx, "AUTHENTICATE:", sizeof("AUTHENTICATE:") - 1);
    MD5Update(&ctx, uri, strlen(uri));
    if(!strcmp(qop, "auth-int")) {
        MD5Update(&ctx, ":00000000000000000000000000000000", sizeof(":00000000000000000000000000000000") - 1);
    }
    MD5Final(digest, &ctx);
#endif
    make_digest(hexA2, digest);

#ifdef DEBUG
    log_debug(DEBUG_9, "digest_md5: A2=%s", hexA2);
#endif

    /* response */
#ifdef USE_SSL
    MD5_Init(&ctx);
    MD5_Update(&ctx, hexA1, 32);
    MD5_Update(&ctx, ":", 1);
    MD5_Update(&ctx, nonce, strlen(nonce));
    MD5_Update(&ctx, ":00000001:", sizeof(":00000001:") - 1);
    MD5_Update(&ctx, cnonce, strlen(cnonce));
    MD5_Update(&ctx, ":", 1);
    MD5_Update(&ctx, qop, strlen(qop));
    MD5_Update(&ctx, ":", 1);
    MD5_Update(&ctx, hexA2, 32);
    MD5_Final(digest, &ctx);
#else
    MD5Init(&ctx);
    MD5Update(&ctx, hexA1, 32);
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, nonce, strlen(nonce));
    MD5Update(&ctx, ":00000001:", sizeof(":00000001:") - 1);
    MD5Update(&ctx, cnonce, strlen(cnonce));
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, qop, strlen(qop));
    MD5Update(&ctx, ":", 1);
    MD5Update(&ctx, hexA2, 32);
    MD5Final(digest, &ctx);
#endif

    make_digest(resp, digest);

#ifdef DEBUG
    log_debug(DEBUG_9, "digest_md5: resp=%s", resp);
#endif

    sprintf(response, "charset=utf-8,username=\"%s\",realm=\"%s\",nonce=\"%s\","
               "nc=00000001,cnonce=\"%s\",digest-uri=\"%s\",qop=%s,"
               "response=%s",
               login, realm, nonce, cnonce, uri, qop, resp);

#ifdef DEBUG
    log_debug(DEBUG_9, "digest_md5: response:%s", response);
    log_debug(DEBUG_9, "digest_md5: text:%s", text);
#endif
}


smtp_t *
smtp_auth(config_t *cfg) {

    int s;
    struct sockaddr_in addr;
    struct hostent *he;
    smtp_t *smtp = NULL;
    char msgbuf[256];

    struct iovec iov[5];
    char *c;
    int rc;
    char rbuf[RESP_LEN];
    int auth = 0;
    int avail_auth_type = 0;
    char *tbuf;
    struct utsname  h_name[1];
    char *myhostname;

    int                n;
    struct sockaddr_in taddr;
    int                sd;
    struct ifconf      ifconf;
    struct ifreq       *ifr, ifreq;
    unsigned char      *ifptr;
    int                iflen;
#ifdef USE_SSL
    int use_ssl;
#endif

    if(!cfg->password) {
        if(!global.password) {
            global.password = getpass("Password:");
            if(!global.password) {
                return 0;
            }
            if(!*global.password) {
                global.password = NULL;
                goto bail;
            }
            global.password = strdup(global.password);
        }
        cfg->password = strdup(global.password);
    }

    assert(cfg->username != NULL);
    assert(cfg->password != NULL);

    smtp = calloc(1, sizeof(smtp_t));
    smtp->sock = calloc(1, sizeof(socket_t));
    smtp->buf = calloc(1, sizeof(buffer_t));
    smtp->buf->sock = smtp->sock;
    smtp->sock->fd = -1;
    smtp->error = 0;

    /* open connection to SMTP server */
    memset(&addr, 0, sizeof(addr));
    addr.sin_port = htons(cfg->port);
    addr.sin_family = AF_INET;
    he = gethostbyname(cfg->host);
    if(!he) {
        smtp->error = 1;
        strcpy(msgbuf, "Error: resolving hostname ");
        strcat(msgbuf, cfg->host);
        smtp->error_message = malloc(strlen(msgbuf) + 1);
        strcpy(smtp->error_message, msgbuf);
        goto bail;
    }

    if((sd = socket(PF_INET, SOCK_DGRAM, 0)) != -1) {
        bzero(&ifconf, sizeof(struct ifconf));
        bzero(&ifreq, sizeof(struct ifreq));
        iflen = 10 * sizeof(struct ifreq);
        ifptr = malloc(iflen);
        ifconf.ifc_len = iflen;
        ifconf.ifc_ifcu.ifcu_req = (struct ifreq *)ifptr;
        if(ioctl(sd, SIOCGIFCONF, &ifconf) != -1) {
            for(iflen=sizeof(struct ifreq); iflen<=ifconf.ifc_len; iflen+=sizeof(struct ifreq)) {
                ifr = (struct ifreq *)ifptr;
                strcpy(ifreq.ifr_ifrn.ifrn_name, ifr->ifr_name);
                if(ioctl(sd, SIOCGIFADDR, &ifreq) != -1) {
                    n = 0;
                    while(he->h_addr_list[n]) {
                        if(he->h_addrtype == AF_INET) {
                            memset((char*)&taddr, 0, sizeof(taddr));
                            memcpy((char*)&taddr.sin_addr, he->h_addr_list[n], he->h_length);
#ifdef DEBUG
                            log_debug(DEBUG_5, "smtp_auth: my ip: %s",
                              inet_ntoa(((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr));
                            log_debug(DEBUG_5, "smtp_auth: smtp ip: %s",
                              inet_ntoa(taddr.sin_addr));
#endif
                            if(((struct sockaddr_in *)&ifreq.ifr_addr)->sin_addr.s_addr == taddr.sin_addr.s_addr) {
                                smtp->error = 1;
                                strcpy(msgbuf, "Error: this host is specified. ");
                                strcat(msgbuf, inet_ntoa(taddr.sin_addr));
                                smtp->error_message = malloc(strlen(msgbuf) + 1);
                                strcpy(smtp->error_message, msgbuf);
                                goto bail;
                            }
                        }
                        n++;
                    }
                }
                ifptr += sizeof(struct ifreq);
            }
        }
    }
    addr.sin_addr.s_addr = *((int *)he->h_addr_list[0]);
    s = socket(PF_INET, SOCK_STREAM, 0);

    if(cfg->conn_timeout > 0) {
        set_timeout(cfg->conn_timeout);
    }
    if(connect(s, (struct sockaddr *) &addr, sizeof(addr))) {
#ifdef DEBUG
        log_debug(DEBUG_1, "smtp_auth: connection error = %s",strerror(errno));
#endif
        smtp->error = 1;
        strcpy(msgbuf, "Error: connecting to ");
        strcat(msgbuf, inet_ntoa(addr.sin_addr));
        smtp->error_message = malloc(strlen(msgbuf) + 1);
        strcpy(smtp->error_message, msgbuf);
        goto bail;
    }
    smtp->sock->fd = s;
    if(cfg->conn_timeout > 0) {
        set_timeout(0);
    }

#ifdef USE_SSL
    use_ssl = 0;
    if(cfg->use_smtps) {
      if(start_tls(smtp, cfg)) {
        smtp->error = 1;
        strcpy(msgbuf, "Error: start_tls");
        smtp->error_message = malloc(strlen(msgbuf) + 1);
        strcpy(smtp->error_message, msgbuf);
        goto bail;
      }
      use_ssl = 1;
    }
#endif

    /* TCP connection to the remote SMTP server */
    if(cfg->timeout > 0) {
        set_timeout(cfg->timeout);
    }
    rc = socket_read(smtp->sock, rbuf, sizeof(rbuf));
    if(cfg->timeout > 0) {
        set_timeout(0);
    }
    if(rc == -1) {
#ifdef DEBUG
        log_debug(DEBUG_1, "smtp_auth: read (banner): %m");
#endif
        smtp->error = 1;
        strcpy(msgbuf, RESP_SYNCERROR);
        smtp->error_message = malloc(strlen(msgbuf) + 1);
        strcpy(smtp->error_message, msgbuf);
        goto bail;
    }
    rbuf[rc] = '\0';
    c = strpbrk(rbuf, SMTP_NEWLINE);
    if(c != NULL) {
        *c = '\0';
    }

    if(strncmp(rbuf, "220 ", sizeof("220 ")-1)) {
#ifdef DEBUG
        log_debug(DEBUG_1, "smtp_auth: unexpected response during initial handshake: %s", rbuf);
#endif
        smtp->error = 1;
        strcpy(msgbuf, RESP_UNEXPECTED);
        smtp->error_message = malloc(strlen(msgbuf) + 1);
        strcpy(smtp->error_message, msgbuf);
        goto bail;
    }

    if((uname(h_name)) < 0){
        myhostname = "localhost.localdomain";
    } else {
        myhostname = h_name->nodename;
    }

    iov[0].iov_base = SMTP_EHLO_CMD;
    iov[0].iov_len  = sizeof(SMTP_EHLO_CMD) - 1;
    iov[1].iov_base = myhostname;
    iov[1].iov_len  = strlen(myhostname);
    iov[2].iov_base = SMTP_NEWLINE;
    iov[2].iov_len  = sizeof(SMTP_NEWLINE) - 1;

#ifdef DEBUG
    log_debug(DEBUG_9, "smtp_auth: sending %s%s", SMTP_EHLO_CMD, myhostname);
#endif
    if(cfg->timeout > 0) {
        set_timeout(cfg->timeout);
    }
    rc = retry_writev(smtp->sock, iov, 3);
    memset(iov, 0, sizeof(iov));
    if(cfg->timeout > 0) {
        set_timeout(0);
    }
    if(rc == -1) {
#ifdef DEBUG
        log_debug(DEBUG_1, "smtp_auth: writev: %m");
#endif
        smtp->error = 1;
        strcpy(msgbuf, RESP_IERROR);
        smtp->error_message = malloc(strlen(msgbuf) + 1);
        strcpy(smtp->error_message, msgbuf);
        goto bail;
    }

    /* read and parse the EHLO response */
    if(cfg->timeout > 0) {
        set_timeout(cfg->timeout);
    }
    rc = socket_read(smtp->sock, rbuf, sizeof(rbuf));
    if(cfg->timeout > 0) {
        set_timeout(0);
    }
    if(rc == -1) {
#ifdef DEBUG
        log_debug(DEBUG_1, "smtp_auth: read (response): %m");
#endif
        smtp->error = 1;
        strcpy(msgbuf, RESP_IERROR);
        smtp->error_message = malloc(strlen(msgbuf) + 1);
        strcpy(smtp->error_message, msgbuf);
        goto bail;
    }

    if((tbuf = strstr(rbuf, "250-STARTTLS"))) {
#ifdef DEBUG
        log_debug(DEBUG_1, "smtp_auth: STARTTLS not supported.");
#endif
    }

    if((tbuf = strstr(rbuf, "250-AUTH"))) {
        if(strncmp(tbuf, "250", sizeof("250")-1) == 0) {
            char *p = tbuf;
            p += 3;
            if(*p == '-' || *p == ' ') p++;
            if(strncasecmp(p, "AUTH", sizeof("AUTH")-1) == 0) {
                p += 5;
                if(strcasestr(p, "PLAIN"))
                    avail_auth_type |= AUTH_PLAIN;
                if(strcasestr(p, "LOGIN"))
                    avail_auth_type |= AUTH_LOGIN;
                if(strcasestr(p, "CRAM-MD5"))
                    avail_auth_type |= AUTH_CRAM_MD5;
                if(strcasestr(p, "DIGEST-MD5"))
                    avail_auth_type |= AUTH_DIGEST_MD5;
            }
        }
    }

    if(avail_auth_type == 0) {
#ifdef DEBUG
        log_debug(DEBUG_1, "smtp_auth: smtp authentication is not implemented: %s", rbuf);
#endif
        smtp->error = 1;
        strcpy(msgbuf, RESP_UNEXPECTED);
        smtp->error_message = malloc(strlen(msgbuf) + 1);
        strcpy(smtp->error_message, msgbuf);
        goto bail;
    }
#ifdef DEBUG
    log_debug(DEBUG_1, "smtp_auth: auth_type=%d", avail_auth_type);
#endif

    /* build the AUTH command */
    if(avail_auth_type & AUTH_CRAM_MD5) {
        auth = auth_cram_md5(smtp->sock,&global);
    }
    else if((avail_auth_type & AUTH_LOGIN) != 0) {
        auth = auth_login(smtp->sock,&global);
    }
    else if((avail_auth_type & AUTH_PLAIN) != 0) {
        auth = auth_plain(smtp->sock,&global);
    }
    else if((avail_auth_type & AUTH_DIGEST_MD5) != 0) {
        auth = auth_digest_md5(smtp->sock,&global);
    }
    else {
#ifdef DEBUG
        log_debug(DEBUG_1, "smtp_auth: smtp authentication is not implemented: %s", rbuf);
#endif
        smtp->error = 1;
        strcpy(msgbuf, RESP_UNEXPECTED);
        smtp->error_message = malloc(strlen(msgbuf) + 1);
        strcpy(smtp->error_message, msgbuf);
        goto bail;
    }

#ifdef DEBUG
    log_debug(DEBUG_5, "smtp_auth: auth=%d", auth);
#endif
    if(auth == 0) {
#ifdef DEBUG
        log_debug(DEBUG_1, "smtp_auth: rejected=%s", global.username);
#endif
        smtp->error = 2;
        strcpy(msgbuf, RESP_CREDERROR);
        smtp->error_message = malloc(strlen(msgbuf) + 1);
        strcpy(smtp->error_message, msgbuf);
        goto bail;
    }

    smtp_quit(smtp->sock,&global);
    return smtp;

    bail:
        smtp_quit(smtp->sock,&global);
        if(smtp->error == 1)
            return smtp;
        else if(smtp->error == 2)
            return smtp;
        return smtp;
}


int
smtp_quit(socket_t *sock, config_t *cfg) {

    struct iovec iov[3];
    int rc;

    iov[0].iov_base = SMTP_QUIT_CMD;
    iov[0].iov_len  = sizeof(SMTP_QUIT_CMD) - 1;
    iov[1].iov_base = SMTP_NEWLINE;
    iov[1].iov_len  = sizeof(SMTP_NEWLINE) - 1;

#ifdef DEBUG
    log_debug(DEBUG_9, "smtp_quit: sending %s", SMTP_QUIT_CMD);
#endif
    if(cfg->timeout > 0) {
        set_timeout(cfg->timeout);
    }
    rc = retry_writev(sock, iov, 2);
    memset(iov, 0, sizeof(iov));
    if(cfg->timeout > 0) {
        set_timeout(0);
    }
    if(rc == -1) {
#ifdef DEBUG
        log_debug(DEBUG_1, "smtp_quit: quit writev: %m");
#endif
    }
    (void)socket_close(sock);
    return 1;
}


int
auth_cram_md5(socket_t *sock, config_t *cfg) {

    struct iovec iov[3];
    int rc;
    char rbuf[RESP_LEN];
    char buf[RESP_LEN];

#ifdef DEBUG
    log_debug(DEBUG_1, "auth_cram_md5: AUTH CRAM-MD5");
#endif
    iov[0].iov_base = SMTP_AUTH_CMD;
    iov[0].iov_len  = sizeof(SMTP_AUTH_CMD) - 1;
    iov[1].iov_base = "CRAM-MD5";
    iov[1].iov_len  = strlen("CRAM-MD5");
    iov[2].iov_base = SMTP_NEWLINE;
    iov[2].iov_len  = sizeof(SMTP_NEWLINE) - 1;

#ifdef DEBUG
    log_debug(DEBUG_9, "auth_cram_md5: sending %s%s", SMTP_AUTH_CMD,"CRAM-MD5");
#endif
    if(cfg->timeout > 0) {
        set_timeout(cfg->timeout);
    }
    rc = retry_writev(sock, iov, 3);
    memset(iov, 0, sizeof(iov));
    if(cfg->timeout > 0) {
        set_timeout(0);
    }
    if(rc == -1) {
#ifdef DEBUG
        log_debug(DEBUG_1, "auth_cram_md5: cram-md5 writev: %m");
#endif
        return AUTH_NG;
    }

    if(cfg->timeout > 0) {
        set_timeout(cfg->timeout);
    }
    rc = socket_read(sock, rbuf, sizeof(rbuf));
    if(cfg->timeout > 0) {
        set_timeout(0);
    }
    if(rc == -1) {
#ifdef DEBUG
        log_debug(DEBUG_1, "auth_cram_md5: read (response): %m");
#endif
        return AUTH_NG;
    }

#ifdef DEBUG
    log_debug(DEBUG_5, "auth_cram_md5: read (response): %s",rbuf);
#endif
    if(strncmp(rbuf, "334 ", sizeof("334 ")-1) == 0) {
        char *response;
        char *response64;
        unsigned char *challenge;
        int challengelen;
        unsigned char hexdigest[33];

        challenge = malloc(strlen(rbuf + 4) + 1);
        challengelen = base64_decode((char *)challenge, rbuf + 4, -1);
        challenge[challengelen] = '\0';
#ifdef DEBUG
        log_debug(DEBUG_9, "auth_cram_md5: challenge=%s", challenge);
#endif

        snprintf(buf, sizeof(buf), "%s", cfg->password);
        md5_hex_hmac((char *)hexdigest, challenge, challengelen, (unsigned char*)buf, strlen(cfg->password));
        free(challenge);

        response = malloc(sizeof(char)*128);
        sprintf(response, "%s %s", cfg->username, hexdigest);
        response64 = malloc((strlen(response) + 3) * 2 + 1);
        base64_encode(response64, response, strlen(response));
        free(response);

        iov[0].iov_base = response64;
        iov[0].iov_len  = strlen(response64);
        iov[1].iov_base = SMTP_NEWLINE;
        iov[1].iov_len  = sizeof(SMTP_NEWLINE) - 1;

#ifdef DEBUG
        log_debug(DEBUG_9, "auth_cram_md5: sending %s", response64);
#endif
        if(cfg->timeout > 0) {
            set_timeout(cfg->timeout);
        }
        rc = retry_writev(sock, iov, 2);
        memset(iov, 0, sizeof(iov));
        if(cfg->timeout > 0) {
            set_timeout(0);
        }
        if(rc == -1) {
#ifdef DEBUG
            log_debug(DEBUG_1, "auth_cram_md5: cram-md5 writev: %m");
#endif
            return AUTH_NG;
        }

        if(cfg->timeout > 0) {
            set_timeout(cfg->timeout);
        }
        rc = socket_read(sock, rbuf, sizeof(rbuf));
        if(cfg->timeout > 0) {
            set_timeout(0);
        }
        if(rc == -1) {
#ifdef DEBUG
            log_debug(DEBUG_1, "auth_cram_md5: read (response): %m");
#endif
            return AUTH_NG;
        }

#ifdef DEBUG
        log_debug(DEBUG_5, "auth_cram_md5: read (response): %s",rbuf);
#endif
        if(strncmp(rbuf, "235 ", sizeof("235 ")-1) != 0) {
#ifdef DEBUG
            log_debug(DEBUG_1, "auth_cram_md5: auth failure.");
#endif
            return AUTH_NG;
        }
        free(response64);
    } else {
#ifdef DEBUG
        log_debug(DEBUG_1, "auth_cram_md5: it seems cram-md5 mech is not implemented.");
#endif
        return AUTH_NG;
    }
    return AUTH_OK;
}


int
auth_login(socket_t *sock, config_t *cfg) {

    struct iovec iov[3];
    int rc;
    char rbuf[RESP_LEN];
    //char buf[RESP_LEN];
    char *buf;

#ifdef DEBUG
    log_debug(DEBUG_1, "auth_login: AUTH LOGIN");
#endif
    iov[0].iov_base = SMTP_AUTH_CMD;
    iov[0].iov_len  = sizeof(SMTP_AUTH_CMD) - 1;
    iov[1].iov_base = "LOGIN";
    iov[1].iov_len  = strlen("LOGIN");
    iov[2].iov_base = SMTP_NEWLINE;
    iov[2].iov_len  = sizeof(SMTP_NEWLINE) - 1;

#ifdef DEBUG
    log_debug(DEBUG_9, "auth_login: sending %s%s", SMTP_AUTH_CMD,"LOGIN");
#endif
    if(cfg->timeout > 0) {
        set_timeout(cfg->timeout);
    }
    rc = retry_writev(sock, iov, 3);
    memset(iov, 0, sizeof(iov));
    if(cfg->timeout > 0) {
        set_timeout(0);
    }
    if(rc == -1) {
#ifdef DEBUG
        log_debug(DEBUG_1, "auth_login: login writev: %m");
#endif
        return AUTH_NG;
    }

    if(cfg->timeout > 0) {
        set_timeout(cfg->timeout);
    }
    rc = socket_read(sock, rbuf, sizeof(rbuf));
    if(cfg->timeout > 0) {
        set_timeout(0);
    }
    if(rc == -1) {
#ifdef DEBUG
        log_debug(DEBUG_1, "auth_login: read (response): %m");
#endif
        return AUTH_NG;
    }

#ifdef DEBUG
    log_debug(DEBUG_5, "auth_login: read (response): %s",rbuf);
#endif
    if(strncmp(rbuf, "334 ", sizeof("334 ")-1) == 0) {
        buf = malloc(sizeof(char)*128);
        base64_encode(buf, cfg->username, strlen(cfg->username));

        iov[0].iov_base = buf;
        iov[0].iov_len  = strlen(buf);
        iov[1].iov_base = SMTP_NEWLINE;
        iov[1].iov_len  = sizeof(SMTP_NEWLINE) - 1;

#ifdef DEBUG
        log_debug(DEBUG_9, "auth_login: sending %s", buf);
#endif
        if(cfg->timeout > 0) {
            set_timeout(cfg->timeout);
        }
        rc = retry_writev(sock, iov, 2);
        memset(iov, 0, sizeof(iov));
        if(cfg->timeout > 0) {
            set_timeout(0);
        }
        if(rc == -1) {
#ifdef DEBUG
            log_debug(DEBUG_1, "auth_login: login writev: %m");
#endif
            return AUTH_NG;
        }

        if(cfg->timeout > 0) {
            set_timeout(cfg->timeout);
        }
        rc = socket_read(sock, rbuf, sizeof(rbuf));
        if(cfg->timeout > 0) {
            set_timeout(0);
        }
        if(rc == -1) {
#ifdef DEBUG
            log_debug(DEBUG_1, "auth_login: read (response): %m");
#endif
            return AUTH_NG;
        }

#ifdef DEBUG
        log_debug(DEBUG_5, "auth_login: read (response): %s",rbuf);
#endif
        if(strncmp(rbuf, "334 ", sizeof("334 ")-1) == 0) {
            buf = malloc(sizeof(char)*128);
            base64_encode(buf, cfg->password, strlen(cfg->password));

            iov[0].iov_base = buf;
            iov[0].iov_len  = strlen(buf);
            iov[1].iov_base = SMTP_NEWLINE;
            iov[1].iov_len  = sizeof(SMTP_NEWLINE) - 1;

#ifdef DEBUG
            log_debug(DEBUG_9, "auth_login: sending %s", buf);
#endif
            if(cfg->timeout > 0) {
                set_timeout(cfg->timeout);
            }
            rc = retry_writev(sock, iov, 2);
            memset(iov, 0, sizeof(iov));
            if(cfg->timeout > 0) {
                set_timeout(0);
            }
            if(rc == -1) {
#ifdef DEBUG
                log_debug(DEBUG_1, "auth_login: login writev: %m");
#endif
                return AUTH_NG;
            }

            if(cfg->timeout > 0) {
                set_timeout(cfg->timeout);
            }
            rc = socket_read(sock, rbuf, sizeof(rbuf));
            if(cfg->timeout > 0) {
                set_timeout(0);
            }
            if(rc == -1) {
#ifdef DEBUG
                log_debug(DEBUG_1, "auth_login: read (response): %m");
#endif
                return AUTH_NG;
            }

#ifdef DEBUG
            log_debug(DEBUG_5, "auth_login: read (response): %s",rbuf);
#endif
            if(strncmp(rbuf, "235 ", sizeof("235 ")-1) != 0) {
#ifdef DEBUG
                log_debug(DEBUG_1, "auth_login: auth failure.");
#endif
                return AUTH_NG;
            }
        } else {
#ifdef DEBUG
            log_debug(DEBUG_1, "auth_login: it seems login mech is not implemented.");
#endif
            return AUTH_NG;
        }
    } else {
#ifdef DEBUG
        log_debug(DEBUG_1, "auth_login: it seems login mech is not implemented.");
#endif
        return AUTH_NG;
    }
    return AUTH_OK;
}


int
auth_plain(socket_t *sock, config_t *cfg) {

    struct iovec iov[3];
    int rc;
    char rbuf[RESP_LEN];
    //char buf[RESP_LEN];
    char *buf;
    int cnt, len;
    char phrase[512];

#ifdef DEBUG
    log_debug(DEBUG_1, "auth_plain: AUTH PLAIN");
#endif
    sprintf(phrase,"%s^%s^%s", cfg->username, cfg->username, cfg->password);
    len = strlen(phrase);
    for(cnt=len-1; cnt>=0; cnt--) {
        if(phrase[cnt] == '^') {
            phrase[cnt] = '\0';
        }
    }
    buf = malloc(sizeof(char)*128);
    base64_encode(buf, phrase, len);

    iov[0].iov_base = SMTP_AUTH_CMD;
    iov[0].iov_len  = sizeof(SMTP_AUTH_CMD) - 1;
    iov[1].iov_base = "PLAIN ";
    iov[1].iov_len  = strlen("PLAIN ");
    iov[2].iov_base = buf;
    iov[2].iov_len  = strlen(buf);
    iov[3].iov_base = SMTP_NEWLINE;
    iov[3].iov_len  = sizeof(SMTP_NEWLINE) - 1;

#ifdef DEBUG
    log_debug(DEBUG_9, "auth_plain: sending %s%s %s", SMTP_AUTH_CMD,"PLAIN",buf);
#endif
    if(cfg->timeout > 0) {
        set_timeout(cfg->timeout);
    }
    rc = retry_writev(sock, iov, 4);
    memset(iov, 0, sizeof(iov));
    free(buf);
    if(cfg->timeout > 0) {
        set_timeout(0);
    }
    if(rc == -1) {
#ifdef DEBUG
        log_debug(DEBUG_1, "auth_plain: plain writev: %m");
#endif
        return AUTH_NG;
    }

    if(cfg->timeout > 0) {
        set_timeout(cfg->timeout);
    }
    rc = socket_read(sock, rbuf, sizeof(rbuf));
    if(cfg->timeout > 0) {
        set_timeout(0);
    }
    if(rc == -1) {
#ifdef DEBUG
        log_debug(DEBUG_1, "auth_plain: read (response): %m");
#endif
        return AUTH_NG;
    }

#ifdef DEBUG
    log_debug(DEBUG_5, "auth_plain: read (response): %s",rbuf);
#endif

    if(strncmp(rbuf, "235 ", sizeof("235 ")-1) != 0) {
#ifdef DEBUG
        log_debug(DEBUG_1, "auth_plain: auth failure.");
#endif
        return AUTH_NG;
    }
    return AUTH_OK;
}


int
auth_digest_md5(socket_t *sock, config_t *cfg) {

    struct iovec iov[3];
    int rc;
    char rbuf[RESP_LEN];
    char *buf;

#ifdef DEBUG
    log_debug(DEBUG_1, "auth_digest_md5: AUTH DIGEST-MD5");
#endif

    iov[0].iov_base = SMTP_AUTH_CMD;
    iov[0].iov_len  = sizeof(SMTP_AUTH_CMD) - 1;
    iov[1].iov_base = "DIGEST-MD5";
    iov[1].iov_len  = strlen("DIGEST-MD5");
    iov[2].iov_base = SMTP_NEWLINE;
    iov[2].iov_len  = sizeof(SMTP_NEWLINE) - 1;

#ifdef DEBUG
    log_debug(DEBUG_9, "auth_digest_md5: sending %s%s", SMTP_AUTH_CMD,"DIGEST-MD5");
#endif
    if(cfg->timeout > 0) {
        set_timeout(cfg->timeout);
    }
    rc = retry_writev(sock, iov, 3);
    memset(iov, 0, sizeof(iov));
    if(cfg->timeout > 0) {
        set_timeout(0);
    }
    if(rc == -1) {
#ifdef DEBUG
        log_debug(DEBUG_1, "auth_digest_md5: digest-md5 writev: %m");
#endif
        return AUTH_NG;
    }

    if(cfg->timeout > 0) {
        set_timeout(cfg->timeout);
    }
    rc = socket_read(sock, rbuf, sizeof(rbuf));
    if(cfg->timeout > 0) {
        set_timeout(0);
    }
    if(rc == -1) {
#ifdef DEBUG
        log_debug(DEBUG_1, "auth_digest_md5: read (response): %m");
#endif
        return AUTH_NG;
    }

#ifdef DEBUG
    log_debug(DEBUG_5, "auth_digest_md5: read (response): %s",rbuf);
#endif
    if(strncmp(rbuf, "334 ", sizeof("334 ")-1) == 0) {
        char *response;
        char *response64;
        char *challenge;
        int challengelen;
        unsigned char hexdigest[256];

        challenge = malloc(strlen(rbuf + 4) + 1);
        challengelen = base64_decode(challenge, rbuf + 4, -1);
        challenge[challengelen] = '\0';
#ifdef DEBUG
        log_debug(DEBUG_9, "auth_digest_md5: challenge=%s", challenge);
#endif

        digest_md5((char *)hexdigest, (unsigned char*)challenge, challengelen, cfg->username, cfg->password);
#ifdef DEBUG
        log_debug(DEBUG_9, "auth_digest_md5: hexdigest=%s", hexdigest);
#endif

        response = malloc(sizeof(char)*256);
        snprintf(response, 256, "%s", hexdigest);
#ifdef DEBUG
        log_debug(DEBUG_9, "auth_digest_md5: response=%s", response);
#endif
        response64 = malloc((strlen(response) + 3) * 2 + 1);
        base64_encode(response64, response, strlen(response));
        free(response);
#ifdef DEBUG
        log_debug(DEBUG_9, "auth_digest_md5: response64=%s", response64);
#endif

        iov[0].iov_base = response64;
        iov[0].iov_len  = strlen(response64);
        iov[1].iov_base = SMTP_NEWLINE;
        iov[1].iov_len  = sizeof(SMTP_NEWLINE) - 1;

#ifdef DEBUG
        log_debug(DEBUG_9, "auth_digest_md5: sending %s", response64);
#endif
        if(cfg->timeout > 0) {
            set_timeout(cfg->timeout);
        }
        rc = retry_writev(sock, iov, 2);
        memset(iov, 0, sizeof(iov));
        if(cfg->timeout > 0) {
            set_timeout(0);
        }
        if(rc == -1) {
#ifdef DEBUG
            log_debug(DEBUG_1, "auth_digest_md5: digest-md5 writev: %m");
#endif
            return AUTH_NG;
        }

        if(cfg->timeout > 0) {
            set_timeout(cfg->timeout);
        }
        rc = socket_read(sock, rbuf, sizeof(rbuf));
        if(cfg->timeout > 0) {
            set_timeout(0);
        }
        if(rc == -1) {
#ifdef DEBUG
            log_debug(DEBUG_1, "auth_digest_md5: read (response): %m");
#endif
            return AUTH_NG;
        }

#ifdef DEBUG
        log_debug(DEBUG_5, "auth_digest_md5: read (response): %s",rbuf);
#endif
        if(strncmp(rbuf, "334 ", sizeof("334 ")-1) == 0) {
            int buflen;

            buf = malloc(strlen(rbuf + 4) + 1);
            buflen = base64_decode(buf, rbuf + 4, -1);
            buf[buflen] = '\0';

            iov[0].iov_base = buf;
            iov[0].iov_len  = strlen(buf);
            iov[1].iov_base = SMTP_NEWLINE;
            iov[1].iov_len  = sizeof(SMTP_NEWLINE) - 1;

#ifdef DEBUG
            log_debug(DEBUG_9, "auth_digest_md5: sending %s", buf);
#endif
            if(cfg->timeout > 0) {
                set_timeout(cfg->timeout);
            }
            rc = retry_writev(sock, iov, 2);
            memset(iov, 0, sizeof(iov));
            if(cfg->timeout > 0) {
                set_timeout(0);
            }
            if(rc == -1) {
#ifdef DEBUG
                log_debug(DEBUG_1, "auth_digest_md5: digest-md5 writev: %m");
#endif
                return AUTH_NG;
            }

            if(cfg->timeout > 0) {
                set_timeout(cfg->timeout);
            }
            rc = socket_read(sock, rbuf, sizeof(rbuf));
            if(cfg->timeout > 0) {
                set_timeout(0);
            }
            if(rc == -1) {
#ifdef DEBUG
                log_debug(DEBUG_1, "auth_digest_md5: read (response): %m");
#endif
                return AUTH_NG;
            }

#ifdef DEBUG
            log_debug(DEBUG_5, "auth_digest_md5: read (response): %s",rbuf);
#endif
            if(strncmp(rbuf, "235 ", sizeof("235 ")-1) != 0) {
#ifdef DEBUG
                log_debug(DEBUG_1, "auth_digest_md5: auth failure.");
#endif
                return AUTH_NG;
            }
        } else {
#ifdef DEBUG
            log_debug(DEBUG_1, "auth_digest_md5: it seems digest-md5 mech is not implemented.");
#endif
            return AUTH_NG;
        }
        free(response64);
    } else {
#ifdef DEBUG
        log_debug(DEBUG_1, "auth_digest_md5: it seems digest-md5 mech is not implemented.");
#endif
        return AUTH_NG;
    }
    return AUTH_OK;
}

#ifdef USE_SSL
SSL_CTX *SSLContext = 0;

#ifdef VERYIFY_CERT
static int
verify_cert(SSL *ssl) {

    X509 *cert;
    int err;
    char buf[256];
    int ret = -1;
    BIO *bio;

    cert = SSL_get_peer_certificate(ssl);
    if(!cert) {
#ifdef DEBUG
        log_debug(DEBUG_1, "verify_cert: Error: no server certificate.");
#endif
        return -1;
    }

    err = SSL_get_verify_result(ssl);
    if(err == X509_V_OK) {
        return 0;
    }

#ifdef DEBUG
    log_debug(DEBUG_1, "verify_cert: Error: can't verify certificate: %s (%d).", X509_verify_cert_error_string(err), err);
#endif
    X509_NAME_oneline(X509_get_subject_name(cert), buf, sizeof(buf));
    fprintf(stderr,"\nSubject: %s\n", buf);
    X509_NAME_oneline(X509_get_issuer_name(cert), buf, sizeof(buf));
    fprintf(stderr,"Issuer:  %s\n", buf);
    bio = BIO_new(BIO_s_mem());
    ASN1_TIME_print(bio, X509_get_notBefore(cert));
    memset(buf, 0, sizeof(buf));
    BIO_read(bio, buf, sizeof(buf) - 1);
    fprintf(stderr,"Valid from: %s\n", buf);
    ASN1_TIME_print(bio, X509_get_notAfter(cert));
    memset(buf, 0, sizeof(buf));
    BIO_read(bio, buf, sizeof(buf) - 1);
    BIO_free(bio);
    fprintf(stderr,"      to:   %s\n", buf);

    fprintf(stderr, 
        "\nThere is no way to verify this certificate.\n"
         " It is possible that a hostile attacker has replaced the server certificate.\n"
         " Continue at your own risk!\n"
         "\nAccept this certificate anyway? [no]: ");
    if(fgets(buf, sizeof(buf), stdin) && (buf[0] == 'y' || buf[0] == 'Y')) {
        ret = 0;
        fprintf(stderr, "\nFine, but don't say I didn't warn you!\n\n");
    }
    return ret;
}
#endif

static int
init_ssl(config_t *conf) {

    SSL_METHOD *method;
    int options = 0;

    if(!conf->certfile) {
#ifdef DEBUG
        log_debug(DEBUG_1, "init_ssl: Error: SSLCertificateFile not defined.");
#endif
        return -1;
    }
    SSL_load_error_strings();
    SSL_library_init();
    if(conf->use_tlsv1 && !conf->use_sslv2 && !conf->use_sslv3)
        method = TLSv1_client_method();
    else
        method = SSLv23_client_method();

    SSLContext = SSL_CTX_new(method);

    if(access(conf->certfile, F_OK)) {
        if(errno != ENOENT) {
#ifdef DEBUG
            log_debug(DEBUG_1, "init_ssl: Error: SSLCertificateFile is not accessible.");
#endif
            return -1;
        }
#ifdef DEBUG
        log_debug(DEBUG_1, "init_ssl: Warning: SSLCertificateFile doesn't exist, can't verify server certificates.");
#endif
    } else if(!SSL_CTX_load_verify_locations(SSLContext, conf->certfile, NULL)) {
#ifdef DEBUG
        log_debug(DEBUG_1, "init_ssl: Error: SSL_CTX_load_verify_locations: %s.",ERR_error_string(ERR_get_error(), 0));
#endif
        SSL_CTX_free(SSLContext);
        return -1;
    }

    if(!conf->use_sslv2) {
        options |= SSL_OP_NO_SSLv2;
    }
    if(!conf->use_sslv3) {
        options |= SSL_OP_NO_SSLv3;
    }
    if(!conf->use_tlsv1) {
        options |= SSL_OP_NO_TLSv1;
    }

    SSL_CTX_set_options(SSLContext, options);

    /* we check the result of the verification after SSL_connect() */
    SSL_CTX_set_verify(SSLContext, SSL_VERIFY_NONE, 0);
    return 0;
}

int
start_tls(smtp_t *smtp, config_t *cfg) {

    int ret;
    /* initialize SSL */
    if(init_ssl(cfg)) {
#ifdef DEBUG
        log_debug(DEBUG_1, "start_tls: failed to initialize ssl session.");
#endif
        return 1;
    }

    smtp->sock->ssl = SSL_new(SSLContext);
    SSL_set_fd(smtp->sock->ssl, smtp->sock->fd);
    if((ret = SSL_connect(smtp->sock->ssl)) <= 0) {
        socket_perror("connect", smtp->sock, ret);
#ifdef DEBUG
        log_debug(DEBUG_1, "start_tls: failed to connect ssl session.");
#endif
        return 1;
    }
#ifdef VERIFY_CERT
    /* verify the server certificate */
    if(verify_cert(smtp->sock->ssl)) {
        return 1;
    }
#endif
    smtp->sock->use_ssl = 1;
#ifdef DEBUG
    log_debug(DEBUG_1, "start_tls: SSL support enabled.");
#endif
    return 0;
}
#endif

