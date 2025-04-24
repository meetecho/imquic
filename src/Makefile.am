EXTRA_DIST = $(NULL)
CLEANFILES = $(NULL)

headerdir = $(includedir)/imquic
header_HEADERS = \
	imquic/imquic.h \
	imquic/debug.h \
	imquic/roq.h \
	imquic/moq.h

lib_LTLIBRARIES = libimquic.la
libimquic_la_SOURCES = \
	imquic.c \
	imquic/imquic.h \
	internal/configuration.h \
	quic.c \
	internal/quic.h \
	connection.c \
	internal/connection.h \
	stream.c \
	internal/stream.h \
	crypto.c \
	internal/crypto.h \
	error.c \
	internal/error.h \
	buffer.c \
	internal/buffer.h \
	loop.c \
	internal/loop.h \
	network.c \
	internal/network.h \
	imquic/cctrl.h \
	newreno.c \
	internal/newreno.h \
	ccnone.c \
	internal/ccnone.h \
	qlog.c \
	internal/qlog.h \
	utils.c \
	internal/utils.h \
	listmap.c \
	internal/listmap.h \
	http3.c \
	internal/http3.h \
	qpack.c \
	internal/qpack.h \
	internal/huffman.h \
	imquic-moq.c \
	imquic/moq.h \
	moq.c \
	internal/moq.h \
	imquic-roq.c \
	imquic/roq.h \
	roq.c \
	internal/roq.h \
	internal/mutex.h \
	internal/refcount.h \
	imquic/debug.h \
	version.c \
	internal/version.h
libimquic_la_CFLAGS = \
	$(AM_CFLAGS) \
	$(IMQUIC_CFLAGS) \
	$(QUICTLS_CFLAGS) \
	$(BORINGSSL_CFLAGS) \
	$(JANSSON_CFLAGS) \
	$(NULL)
libimquic_la_LDFLAGS = \
	-version-info $(IMQUIC_VERSION_SO) \
	$(NULL)
libimquic_la_LIBADD = \
	$(IMQUIC_LIBS) \
	$(IMQUIC_MANUAL_LIBS) \
	$(QUICTLS_LIBS) \
	$(BORINGSSL_LIBS) \
	$(JANSSON_LIBS) \
	$(NULL)

BUILT_SOURCES = version.c

directory = ../.git
dir_target = $(directory)-$(wildcard $(directory))
dir_present = $(directory)-$(directory)
dir_absent = $(directory)-

if WITH_SOURCE_DATE_EPOCH
build_date = $(shell LC_ALL=C date --utc --date="@$(SOURCE_DATE_EPOCH)")
else
build_date = $(shell date)
endif

version.c: FORCE | $(dir_target)
	echo "$(build_date)" | awk 'BEGIN {} {print "const char *imquic_build_git_time = \""$$0"\";"} END {} ' >> version.c
	echo "imquic" | awk 'BEGIN {} {print "const char *imquic_name = \""$$0"\";"} END {} ' >> version.c
	echo "$(IMQUIC_VERSION_MAJOR)" | awk 'BEGIN {} {print "int imquic_version_major = "$$0";"} END {} ' >> version.c
	echo "$(IMQUIC_VERSION_MINOR)" | awk 'BEGIN {} {print "int imquic_version_minor = "$$0";"} END {} ' >> version.c
	echo "$(IMQUIC_VERSION_PATCH)" | awk 'BEGIN {} {print "int imquic_version_patch = "$$0";"} END {} ' >> version.c
	echo "$(IMQUIC_VERSION_RELEASE)" | awk 'BEGIN {} {print "const char *imquic_version_release = \""$$0"\";"} END {} ' >> version.c
	echo "$(IMQUIC_VERSION_STRING)" | awk 'BEGIN {} {print "const char *imquic_version_string = \""$$0"\";"} END {} ' >> version.c
	echo "$(IMQUIC_VERSION_STRING)/$(IMQUIC_VERSION_RELEASE)" | awk 'BEGIN {} {print "const char *imquic_version_string_full = \""$$0"\";"} END {} ' >> version.c

$(dir_present):
	`which git` rev-parse HEAD | awk 'BEGIN {print "#include \"internal/version.h\""} {print "const char *imquic_build_git_sha = \"" $$0"\";"} END {}' > version.c

$(dir_absent):
	echo "not-a-git-repo" | awk 'BEGIN {print "#include \"internal/version.h\""} {print "const char *imquic_build_git_sha = \"" $$0"\";"} END {}' > version.c

CLEANFILES += version.c

.PHONY: FORCE
FORCE:
