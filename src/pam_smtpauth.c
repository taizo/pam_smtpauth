/*
 * pam_smtpauth.c
 * $Id: pam_smtpauth.c,v 1.8 2009/06/12 01:23:43 taizo Exp $
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
#include <sys/syslog.h>
#include <fcntl.h>
#include <netdb.h>
#include <regex.h>
#include <security/pam_appl.h>
#include <security/pam_modules.h>
#include <security/pam_misc.h>
#include <stdarg.h>

#include "smtpauth.h"
#include "pam_smtpauth.h"

#define PAM_SM_AUTH
#define _PAM_EXTERN_FUNCTIONS

#define MAX_LENGTH_USERNAME 64
#define MAX_LENGTH_PASSWORD 128
#define MAX_LENGTH_CONFFILE 256
#define SMTPAUTH_CONF "/etc/pam_smtpauth.conf"

#define NETWORK_CONN_TIMEOUT 10
#define NETWORK_IO_TIMEOUT   30
#define DEFAULT_TRYMETHOD    "first"
#define DEFAULT_TRYMECHS     "CRAM-MD5,LOGIN,PLAIN,DIGEST-MD5"

#define SA_NO_SERVER_LEFT 127
#define SA_SERVER_CONNECT_FAILURE 64
#define SA_SERVER_LOGIN_FAILURE   65

#define LOG_BUF_SIZE 2048

int smtp_connect(int num);
int converse(pam_handle_t *pamh, int nargs, struct pam_message **msg, struct pam_response **resp);
int prompt_password(pam_handle_t *pamh);
char *get_config(const char *filepath, char *param);

extern smtp_t *smtp_auth (config_t * cfg);

smtp_t *smtp = NULL;
config_t global;
param_t params;
char configfile[MAX_LENGTH_CONFFILE];

void
log_debug(int level, const char *fmt, ...) {
  char buf[LOG_BUF_SIZE] = {'\0'};
  va_list msg;

  if(params.debuglevel < level) {
    return;
  }

  if(fmt == NULL) {
    return;
  }

  memset(buf, '\0', sizeof(buf));
  va_start(msg, fmt);
  vsnprintf(buf, sizeof(buf), fmt, msg);
  va_end(msg);

  buf[sizeof(buf) - 1] = '\0';
  syslog(LOG_MAIL|LOG_DEBUG, "[pam_smtpauth] %s", buf);
}

PAM_EXTERN int
pam_sm_authenticate( pam_handle_t *pamh, int flags, int argc, const char **argv) {

    int cnt;
    int result;
    const char *username;
    char *password;
    int fd;
    char *timeout_buf;
    int timeout;
    char *conn_timeout_buf;
    int conn_timeout;
    char *debuglevel_buf;
    char *blockedfile;
    char *trymethod;


    password = NULL;
    global.password = NULL;
    params.debuglevel = DEBUG_0;

    /********
      Get configuration file name
     */
#ifdef DEBUG
    log_debug(DEBUG_1, "pam_sm_authenticate() start");
#endif
    if(argc == 0) {
        if((fd = open(SMTPAUTH_CONF, O_RDONLY)) != -1) {
            strcpy(configfile, SMTPAUTH_CONF);
            close(fd);
        }
    }
    if(argc == 1) {
        char *confpath = (char *)malloc((strlen(argv[0]))+1);
        strcpy(confpath, argv[0]);
        if((strchr(confpath, (int) '=') != NULL)) {
            strtok(confpath, "=");
            strcpy(configfile, strtok(NULL, "="));
        }
        else {
            syslog(LOG_ERR, "[pam_smtpauth] invalid module parameter.");
        }
    }

    debuglevel_buf = get_config(configfile, "DebugLevel");
    if(debuglevel_buf != NULL) {
        params.debuglevel = atoi(debuglevel_buf);
    }
#ifdef DEBUG
    log_debug(DEBUG_1, "debuglevel=%d", params.debuglevel);
#endif

    trymethod = get_config(configfile, "TryMethod");
    if(trymethod == NULL) {
        trymethod = DEFAULT_TRYMETHOD;
    }
#ifdef DEBUG
    log_debug(DEBUG_1, "trymethod=%s", trymethod);
#endif

    /********
      Get username
     */
    result = pam_get_user(pamh, &username, NULL);
    if(result != PAM_SUCCESS || username == NULL) {
        syslog(LOG_ERR, "[pam_smtpauth] no user specified.");
        return PAM_USER_UNKNOWN;
    }
#ifdef DEBUG
    log_debug(DEBUG_1, "username=%s", username);
#endif

    if((blockedfile = get_config(configfile, "BlockedUserListFile")) != NULL) {
        FILE *fp;
        char *line = NULL;
        size_t len = 0;
        ssize_t read;

        int regsuccess;		
        int nmatch = 3;
        regex_t reg;	
        regmatch_t match[nmatch];	

#ifdef DEBUG
        log_debug(DEBUG_1, "blockedfile=%s", blockedfile);
#endif
        if((fp = fopen(blockedfile, "r")) != NULL) {
            while((read = getline(&line, &len, fp)) != -1) {
                if(line[0] == '#' || line[0] == '\n') {
                    continue;
                }
                line[read-1] = '\0';
                if(read > 0) {
                    regcomp(&reg, line, REG_EXTENDED);
                    regsuccess = regexec(&reg, username, nmatch, match, 0 );
                    regfree(&reg);
                    if(regsuccess == 0) {
#ifdef DEBUG
                        log_debug(DEBUG_1, "rejected username='%s' regex='%s'", username, line);
#endif
                        return PAM_AUTH_ERR;
                    }
                }
            }
        }
    }

    /********
      Get password
     */
    if(password != NULL) {
#ifdef DEBUG
        log_debug(DEBUG_5, "password is not NULL.");
#endif
        pam_set_item(pamh, PAM_AUTHTOK, (const void**)&password);
    }
    result = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
    if(password == NULL) {
        prompt_password(pamh);
    }
    result = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&password);
    if(password == NULL) {
        syslog(LOG_ERR, "[pam_smtpauth] password is NULL.");
#ifdef DEBUG
        log_debug(DEBUG_1, "password is NULL.");
#endif
        return PAM_AUTHINFO_UNAVAIL;
    }
    if(strcmp(password, "") == 0) {
        syslog(LOG_ERR, "[pam_smtpauth] password is empty.");
#ifdef DEBUG
        log_debug(DEBUG_1, "password is empty.");
#endif
        return PAM_AUTH_ERR;
    }
#ifdef DEBUG
    log_debug(DEBUG_9, "password=%s", password);
#endif

    if(!global.username) {
        global.username = (char *)malloc(MAX_LENGTH_USERNAME);
    }
    strncpy(global.username,username, MAX_LENGTH_USERNAME);
    if(!global.password) {
        global.password = (char *)malloc(MAX_LENGTH_PASSWORD);
    }
    strncpy(global.password,password, MAX_LENGTH_PASSWORD);

    timeout_buf = get_config(configfile, "Timeout");
    if(timeout_buf == NULL) {
        timeout = NETWORK_IO_TIMEOUT;
    } else {
        timeout = atoi(timeout_buf);
    }
    global.timeout = timeout;

    conn_timeout_buf = get_config(configfile, "ConnectTimeout");
    if(conn_timeout_buf == NULL) {
        conn_timeout = NETWORK_CONN_TIMEOUT;
    } else {
        conn_timeout = atoi(conn_timeout_buf);
    }
    global.conn_timeout = conn_timeout;
#ifdef DEBUG
    log_debug(DEBUG_1, "timeout: %d",timeout);
    log_debug(DEBUG_1, "conn_timeout: %d",conn_timeout);
#endif

    for(cnt=0;;cnt++) {
        result = smtp_connect(cnt);
#ifdef DEBUG
        log_debug(DEBUG_5, "smtp_connect cnt=%d result=%d", cnt, result);
#endif
        if(result == SA_NO_SERVER_LEFT) {
#ifdef DEBUG
            log_debug(DEBUG_5, "No more authentication server cannot be found.");
#endif
            password = NULL;
            global.password = NULL;
            return PAM_AUTHINFO_UNAVAIL;
        }
        else if(result == SA_SERVER_CONNECT_FAILURE) {
            continue;
        }
        else if(result == SA_SERVER_LOGIN_FAILURE) {
#ifdef DEBUG
            log_debug(DEBUG_5, "authentication error cnt=%d.", cnt);
#endif
            if(strncmp(trymethod,"first",5) == 0) {
                password = NULL;
                global.password = NULL;
                return PAM_AUTH_ERR;
            } else {
#ifdef DEBUG
            log_debug(DEBUG_5, "retry next server...");
#endif
            }
        } else if(result == PAM_AUTH_ERR) {
            syslog(LOG_ERR, "[pam_smtpauth] authentication error cnt=%d.", cnt);
#ifdef DEBUG
            log_debug(DEBUG_5, "authentication error cnt=%d.", cnt);
#endif
            password = NULL;
            global.password = NULL;
            return PAM_AUTH_ERR;
        }
        else {
            return PAM_SUCCESS;
        }
    }
    password = NULL;
    global.password = NULL;

    free(global.username);
    free(global.password);
    return PAM_AUTH_ERR;
}


int
smtp_connect(int num) {

    int cnt;
    char param[16];
    char tnum[16];
    char *smtp_server;
    char *buffer;
    struct servent *se;
    char *trymechs;

#ifdef DEBUG
    log_debug(DEBUG_5, "smtp_connect num=%d", num);
#endif

    strcpy(param, "SMTPServer_");
    sprintf(tnum, "%d", num);
    strcat(param, tnum);
    smtp_server = get_config(configfile, param);
#ifdef DEBUG
    log_debug(DEBUG_1, "smtp_server=%s", smtp_server);
#endif

    if(smtp_server == NULL) {
        return SA_NO_SERVER_LEFT;
    }

    if((strstr(smtp_server, "smtps:")) != NULL) {
#ifdef USE_SSL
#ifdef DEBUG
        log_debug(DEBUG_1, "use smtps");
#endif
        global.use_smtps = 1;
        global.require_ssl = 1;
        global.use_sslv2 = 1;
        global.use_sslv3 = 1;
        global.use_tlsv1 = 1;
        global.certfile = get_config(configfile, "SSLCertificateFile");
        if(global.certfile == NULL) {
            global.certfile = "/usr/share/certs/pam_smtpauth.crt";
        }
#else
        syslog(LOG_INFO, "[pam_smtpauth] smtps is not implemented.");
#endif
        strtok(smtp_server, ":");
        buffer = strtok(NULL, ":");
        global.host = buffer;
        buffer = strtok(NULL, ":");
    }
    else {
        buffer = strtok(smtp_server, ":");
        global.host = buffer;
        buffer = strtok(NULL, ":");
    }
    if((se = getservbyname(buffer, "tcp")) == NULL) {
        global.port = atoi(buffer);
    } else {
        global.port =  htons(se->s_port);
    }

    trymechs = get_config(configfile, "TryMechs");
    if(trymechs == NULL) {
        trymechs = DEFAULT_TRYMECHS;
    }
    for(cnt=0; cnt<strlen(trymechs); cnt++) {
      if (trymechs[cnt] >= 'a' && trymechs[cnt] <= 'z') {
        trymechs[cnt] = (char)((int)trymechs[cnt] + (int)'A' - (int)'a');
      }
    }
    if(!global.trymechs) {
        global.trymechs = (char *)malloc(64);
    }
    strncpy(global.trymechs,trymechs, 64);

#ifdef DEBUG
    log_debug(DEBUG_5, "global.host=%s", global.host);
    log_debug(DEBUG_5, "global.port=%d", global.port);
    log_debug(DEBUG_5, "global.username=%s", global.username);
    log_debug(DEBUG_9, "global.password=%s", global.password);
    log_debug(DEBUG_5, "global.trymechs=%s", global.trymechs);
#endif

    smtp = (smtp_t *)smtp_auth(&global);
#ifdef DEBUG
    log_debug(DEBUG_5, "smtp->error=%d", smtp->error);
#endif
    free(global.trymechs);

    //sleep(3);

    // Program error
    if(smtp == 0) {
        syslog(LOG_ERR, "[pam_smtpauth] mail_status -> FAIL");
#ifdef DEBUG
        log_debug(DEBUG_1, "mail_status -> FAIL");
#endif
        return PAM_AUTH_ERR;
    }

    // remote connection error or the error before AUTH command(EHLO etc)
    else if(smtp->error == 1) {
        syslog(LOG_WARNING, "[pam_smtpauth] SERVER connection failure: %s:%d => %s", global.host, global.port, smtp->error_message);
#ifdef DEBUG
        log_debug(DEBUG_1, "SERVER connection failure: %s:%d => %s", global.host, global.port, smtp->error_message);
#endif
        return SA_SERVER_CONNECT_FAILURE;
    }

    // the error after AUTH command
    else if(smtp->error == 2) {
        syslog(LOG_ERR, "[pam_smtpauth] LOGIN FAILURE user %s on %s:%d => %s", global.username, global.host, global.port, smtp->error_message);
#ifdef DEBUG
        log_debug(DEBUG_1, "LOGIN FAILURE user %s on %s:%d => %s", global.username, global.host, global.port, smtp->error_message);
#endif
        return SA_SERVER_LOGIN_FAILURE;
    }

    // Authentication is complete and OK
    else if(smtp->error == 0) {
        syslog(LOG_INFO, "[pam_smtpauth] mail_status -> OK for %s", global.username);
#ifdef DEBUG
        log_debug(DEBUG_1, "mail_status -> OK for %s", global.username);
#endif
        return PAM_SUCCESS;
    }

    // Other errors
    else {
        return PAM_CRED_INSUFFICIENT;
    }
    return 0;
}


int
converse(pam_handle_t *pamh, int nargs, struct pam_message **msg, struct pam_response **resp) {

    int result;
    struct pam_conv *conv;

    result = pam_get_item( pamh, PAM_CONV, (const void **)&conv);
    if(result == PAM_SUCCESS) {
        result = conv->conv(nargs, (const struct pam_message **)msg, resp, conv->appdata_ptr);
        if((result != PAM_SUCCESS) && (result != PAM_CONV_AGAIN)) {
#ifdef DEBUG
            log_debug(DEBUG_5, "conversation failure [%s]", pam_strerror(pamh, result));
#endif
        }
    }
    else {
        syslog(LOG_ERR, "[pam_smtpauth] couldn't obtain coversation function [%s]", pam_strerror(pamh, result));
    }
    return result;
}


int
prompt_password(pam_handle_t *pamh) {

    struct pam_message msg[3], *mesg[3];
    struct pam_response *resp=NULL;
    char *prompt = NULL;
    int i=0;
    int result;

    msg[i].msg = (char *)get_config(configfile, "PasswordPrompt");
    msg[i].msg_style = PAM_PROMPT_ECHO_OFF;
    mesg[i] = &msg[0];
    result = converse(pamh, ++i, mesg, &resp);
    if(prompt) {
        _pam_overwrite(prompt);
        _pam_drop(prompt);
    }
    if(result != PAM_SUCCESS) {
        if(resp != NULL) {
            _pam_drop_reply(resp,i);
        }
        return ((result == PAM_CONV_AGAIN) ? PAM_INCOMPLETE:PAM_AUTHINFO_UNAVAIL);
    }
    return pam_set_item(pamh, PAM_AUTHTOK, resp->resp);
}


char *
get_config(const char *filepath, char *param) {

    FILE *fp;
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    char *tstr = NULL;
    char *result = NULL;
    int i, j;

    fp = fopen(filepath, "r");
    while((read = getline(&line, &len, fp)) != -1) {
        if(line[0] == '#' || line[0] == '\n') {
            continue;
        }
        if(strncmp(line, param, strlen(param)) == 0) {
            tstr = strstr(line, param);
            if(tstr != NULL) {
                result = malloc(strlen(tstr) + 1);
                memset(result, 0, strlen(tstr) + 1);
                for(i=0; tstr[i]!='='; i++) ;
                i++;
                while(tstr[i] == ' ' || tstr[i] == '"') {
                    i++;
                }
                for(j=0; tstr[i]!='\0' && tstr[i]!='\n'; i++,j++) {
                    result[j] = tstr[i];
                }
                result[j] = '\0';
                break;
            }
        }
    }
    fclose(fp);
    if(tstr != NULL) {
        free(tstr);
        return(result);
    }
    else {
        return(NULL);
    }
}

/********************   Other PAM library calls  *****************************/

/* --- account management functions --- */
PAM_EXTERN int pam_sm_acct_mgmt(pam_handle_t * pamh,
        int flags,
        int argc,
        const char **argv)
{
        syslog(LOG_INFO, "[pam_smtpauth] acct_mgmt called but not implemented.");
        return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_setcred(pam_handle_t *pamh,
        int flags,
        int argc,
        const char **argv)
{
        syslog(LOG_INFO, "[pam_smtpauth] setcred called but not implemented.");
        return PAM_SUCCESS;
}

/* --- password management --- */
PAM_EXTERN
int pam_sm_chauthtok(pam_handle_t *pamh,int flags,int argc
,const char **argv)
{
        syslog(LOG_INFO, "[pam_smtpauth] chauthtok called but not implemented.  \
                Password NOT CHANGED!");
        return PAM_SUCCESS;
}

/* --- session management --- */
PAM_EXTERN
int pam_sm_open_session(pam_handle_t *pamh,
        int flags,
        int argc,
        const char **argv)
{
        syslog(LOG_INFO, "[pam_smtpauth] open_session called but not implemented.");
        return PAM_SUCCESS;
}

PAM_EXTERN
int pam_sm_close_session(pam_handle_t *pamh,
        int flags,
        int argc,
        const char **argv)
{
        syslog(LOG_INFO, "[pam_smtpauth] close_session called but not implemented.");
        return PAM_SUCCESS;
}

/* end of module definition */


#ifdef PAM_STATIC

/* static module data */
struct pam_module _pam_smtpauth_modstruct = {
     "pam_smtpauth",
     pam_sm_authenticate,
     pam_sm_setcred,
     pam_sm_acct_mgmt,
     pam_sm_open_session,
     pam_sm_close_session,
     pam_sm_chauthtok
};

#endif

