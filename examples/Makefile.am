bin_PROGRAMS =

if ENABLE_ECHO_EXAMPLES

bin_PROGRAMS += imquic-echo-server imquic-echo-client

imquic_echo_server_SOURCES = \
	echo-server.c \
	echo-server-options.c \
	echo-server-options.h
imquic_echo_server_CFLAGS = \
	$(AM_CFLAGS) \
	$(IMQUIC_CFLAGS) \
	-I ../src \
	$(NULL)
imquic_echo_server_LDADD = \
	$(IMQUIC_LIBS) \
	$(IMQUIC_MANUAL_LIBS) \
	-L../src/.libs -limquic \
	$(NULL)

imquic_echo_client_SOURCES = \
	echo-client.c \
	echo-client-options.c \
	echo-client-options.h
imquic_echo_client_CFLAGS = \
	$(AM_CFLAGS) \
	$(IMQUIC_CFLAGS) \
	-I ../src \
	$(NULL)
imquic_echo_client_LDADD = \
	$(IMQUIC_LIBS) \
	$(IMQUIC_MANUAL_LIBS) \
	-L../src/.libs -limquic \
	$(NULL)

endif

if ENABLE_MOQ_EXAMPLES

bin_PROGRAMS += imquic-moq-relay imquic-moq-pub imquic-moq-sub imquic-moq-test

imquic_moq_relay_SOURCES = \
	moq-relay.c \
	moq-relay-options.c \
	moq-relay-options.h \
	moq-utils.c \
	moq-utils.h
imquic_moq_relay_CFLAGS = \
	$(AM_CFLAGS) \
	$(IMQUIC_CFLAGS) \
	-I ../src \
	$(NULL)
imquic_moq_relay_LDADD = \
	$(IMQUIC_LIBS) \
	$(IMQUIC_MANUAL_LIBS) \
	-L../src/.libs -limquic \
	$(NULL)

imquic_moq_pub_SOURCES = \
	moq-pub.c \
	moq-pub-options.c \
	moq-pub-options.h \
	moq-utils.c \
	moq-utils.h
imquic_moq_pub_CFLAGS = \
	$(AM_CFLAGS) \
	$(IMQUIC_CFLAGS) \
	-I ../src \
	$(NULL)
imquic_moq_pub_LDADD = \
	$(IMQUIC_LIBS) \
	$(IMQUIC_MANUAL_LIBS) \
	-L../src/.libs -limquic \
	$(NULL)

imquic_moq_sub_SOURCES = \
	moq-sub.c \
	moq-sub-options.c \
	moq-sub-options.h \
	moq-utils.c \
	moq-utils.h
imquic_moq_sub_CFLAGS = \
	$(AM_CFLAGS) \
	$(IMQUIC_CFLAGS) \
	-I ../src \
	$(NULL)
imquic_moq_sub_LDADD = \
	$(IMQUIC_LIBS) \
	$(IMQUIC_MANUAL_LIBS) \
	-L../src/.libs -limquic \
	$(NULL)

imquic_moq_test_SOURCES = \
	moq-test.c \
	moq-test-options.c \
	moq-test-options.h \
	moq-utils.c \
	moq-utils.h
imquic_moq_test_CFLAGS = \
	$(AM_CFLAGS) \
	$(IMQUIC_CFLAGS) \
	-I ../src \
	$(NULL)
imquic_moq_test_LDADD = \
	$(IMQUIC_LIBS) \
	$(IMQUIC_MANUAL_LIBS) \
	-L../src/.libs -limquic \
	$(NULL)

endif

if ENABLE_ROQ_EXAMPLES

bin_PROGRAMS += imquic-roq-server imquic-roq-client

imquic_roq_server_SOURCES = \
	roq-server.c \
	roq-server-options.c \
	roq-server-options.h
imquic_roq_server_CFLAGS = \
	$(AM_CFLAGS) \
	$(IMQUIC_CFLAGS) \
	-I ../src \
	$(NULL)
imquic_roq_server_LDADD = \
	$(IMQUIC_LIBS) \
	$(IMQUIC_MANUAL_LIBS) \
	-L../src/.libs -limquic \
	$(NULL)

imquic_roq_client_SOURCES = \
	roq-client.c \
	roq-client-options.c \
	roq-client-options.h
imquic_roq_client_CFLAGS = \
	$(AM_CFLAGS) \
	$(IMQUIC_CFLAGS) \
	-I ../src \
	$(NULL)
imquic_roq_client_LDADD = \
	$(IMQUIC_LIBS) \
	$(IMQUIC_MANUAL_LIBS) \
	-L../src/.libs -limquic \
	$(NULL)

endif

.PHONY: FORCE
FORCE:
