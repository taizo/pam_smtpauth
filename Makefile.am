man_MANS = pam_smtpauth.5
EXTRA_DIST = NEWS COPYING README INSTALL AUTHORS ChangeLog pam_smtpauth.spec sample/* $(man_MANS) debian/* CONFIGURATION.eucjp

SUBDIRS = src tools

all: pam_smtpauth.spec

install-data-local:
	@$(NORMAL_INSTALL)
	@if test ! -f $(DESTDIR)$(sysconfdir); then \
		$(mkinstalldirs) $(DESTDIR)$(sysconfdir); \
		$(INSTALL_DATA) $(srcdir)/sample/pam_smtpauth.conf $(DESTDIR)$(sysconfdir); \
	fi

uninstall-local:
	@$(NORMAL_UNINSTALL)

mkrpm: dist
	@if ! which rpmbuild >/dev/null 2>&1; then \
		echo "ERROR: rpmbuild not found"; \
		exit 1; \
	fi
	rpmbuild -ta pam_smtpauth-@VERSION@.tar.gz

mkdeb:
	@if ! which dpkg >/dev/null 2>&1 || ! which debchange >/dev/null 2>&1; then \
		echo "ERROR: dpkg or devchange not found"; \
		exit 1; \
	fi
	@if head -1 debian/changelog | grep -e "\(@VERSION@-[0-9]*\)" -e "\(@VERSION@\)" >/dev/null 2>&1; then \
		debchange -i "rebuild"; \
	else \
		debchange -v @VERSION@-1 "new version"; \
	fi
	dpkg-buildpackage -rfakeroot || true
