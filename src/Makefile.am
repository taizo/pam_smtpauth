noinst_PROGRAMS = pam_smtpauth.so

pam_smtpauth_so_SOURCES = pam_smtpauth.c smtpauth.c pam_smtpauth.h smtpauth.h socket.c base64.c global.h md5c.c md5.h
pam_smtpauth_so_LDFLAGS = -shared

CFLAGS = -Wall -fPIC

DEFS = @DEFS@

#NATIVE_LINK = $(pam_smtpauth_so_LD) $(AM_LDFLAGS) -o $@ 
GNU_LINK = $(CCLD) $(AM_CFLAGS) $(CFLAGS) $(AM_LDFLAGS) $(LDFLAGS) -o $@

# This is horrible but appears to be the only way to work with
# recent versions of automake. Any better ideas, let me know.
LINK = $(NATIVE_LINK) $(GNU_LINK)

install-exec-local: pam_smtpauth.so
	@$(NORMAL_INSTALL)
	$(mkinstalldirs) $(DESTDIR)$(libdir)/security
	$(INSTALL_PROGRAM) pam_smtpauth.so $(DESTDIR)$(libdir)/security/pam_smtpauth.so

uninstall-local:
	@$(NORMAL_UNINSTALL)

