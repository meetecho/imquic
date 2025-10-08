ACLOCAL_AMFLAGS = -I m4

# FIXME: make docs work with distcheck
DISTCHECK_CONFIGURE_FLAGS = --disable-docs

EXTRA_DIST = imquic.pc.in
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = imquic.pc
DISTCLEANFILES = imquic.pc

SUBDIRS = src examples docs
#~ dist_html_DATA = README.md

.PHONY: FORCE
FORCE:
