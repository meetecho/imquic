AC_INIT([imquic],[0.0.1],[https://github.com/meetecho/imquic],[imquic],[https://imquic.conf.meetecho.com])
AC_LANG(C)
AC_CONFIG_AUX_DIR([.])
AC_CONFIG_MACRO_DIR([m4])

AC_ENABLE_SHARED(yes)
AC_ENABLE_STATIC(no)

AM_INIT_AUTOMAKE([foreign subdir-objects])
AM_SILENT_RULES([yes])

AC_USE_SYSTEM_EXTENSIONS

AC_PROG_CC

LT_PREREQ([2.2])
LT_INIT

# Common CFLAGS
CFLAGS="$CFLAGS \
	-fPIC \
	-fstack-protector-all \
	-fstrict-aliasing \
	-pthread \
	-Wall \
	-Warray-bounds \
	-Wextra \
	-Wformat-nonliteral \
	-Wformat-security \
	-Wformat=2 \
	-Winit-self \
	-Wlarger-than=2097152 \
	-Wmissing-declarations \
	-Wmissing-format-attribute \
	-Wmissing-include-dirs \
	-Wmissing-noreturn \
	-Wmissing-prototypes \
	-Wnested-externs \
	-Wold-style-definition \
	-Wpacked \
	-Wpointer-arith \
	-Wsign-compare \
	-Wstrict-prototypes \
	-Wswitch-default \
	-Wunused \
	-Wno-unused-parameter \
	-Wno-unused-result \
	-Wwrite-strings \
	-Werror=implicit-function-declaration"

case "$CC" in
*clang*)
	# Specific clang flags
	CFLAGS="$CFLAGS \
		-Wno-initializer-overrides \
		-Wno-missing-noreturn"
;;
cc*)
	CFLAGS="$CFLAGS \
		-Wno-cast-align \
		-Wno-initializer-overrides"
;;
*)
	# Specific gcc flags
	CFLAGS="$CFLAGS \
		-Wno-override-init \
		-Wunsafe-loop-optimizations \
		-Wunused-but-set-variable"
esac

IMQUIC_VERSION_MAJOR=0
AC_SUBST(IMQUIC_VERSION_MAJOR)
IMQUIC_VERSION_MINOR=0
AC_SUBST(IMQUIC_VERSION_MINOR)
IMQUIC_VERSION_PATCH=1
AC_SUBST(IMQUIC_VERSION_PATCH)
IMQUIC_VERSION_STRING="0.0.1"
AC_SUBST(IMQUIC_VERSION_STRING)
IMQUIC_VERSION_RELEASE="alpha"
AC_SUBST(IMQUIC_VERSION_RELEASE)
IMQUIC_VERSION_SO="0:0:0"
AC_SUBST(IMQUIC_VERSION_SO)

glib_version=2.34

AC_ARG_ENABLE([boringssl],
              [AS_HELP_STRING([--enable-boringssl],
                              [Use BoringSSL instead of OpenSSL])],
              [
                case "${enableval}" in
                  yes) boringssl_dir=/opt/boringssl ;;
                  no)  boringssl_dir= ;;
                  *) boringssl_dir=${enableval} ;;
                esac
              ],
              [boringssl_dir=])

PKG_CHECK_MODULES([IMQUIC],[
	glib-2.0 >= $glib_version
])

IMQUIC_PACKAGES_PUBLIC="glib-2.0 >= $glib_version"
IMQUIC_PACKAGES_PRIVATE=""

IMQUIC_MANUAL_LIBS="${IMQUIC_MANUAL_LIBS} -lm"
AC_SUBST(IMQUIC_MANUAL_LIBS)

AS_IF([test "x${boringssl_dir}" != "x"],
      [echo "Trying to use BoringSSL instead of quictls...";
       AC_MSG_NOTICE([BoringSSL directory is ${boringssl_dir}])
       CFLAGS="$CFLAGS -I${boringssl_dir}/include";
       BORINGSSL_CFLAGS="-I${boringssl_dir}/include";
       AC_SUBST(BORINGSSL_CFLAGS)
       BORINGSSL_LIBS="-lstdc++ -L${boringssl_dir}/lib64 -lssl -lcrypto";
       AC_SUBST(BORINGSSL_LIBS)
       AC_CHECK_HEADERS([${boringssl_dir}/include/openssl/opensslconf.h],
                        [AC_DEFINE(IMQUIC_BORINGSSL)],
                        [AC_MSG_ERROR([BoringSSL headers not found in ${boringssl_dir}])])
      ],
      [
       PKG_CHECK_MODULES([QUICTLS],[openssl+quictls])
      ])
AM_CONDITIONAL([ENABLE_BORINGSSL], [test "x${boringssl_dir}" != "x"])

AC_ARG_ENABLE([qlog],
              [AS_HELP_STRING([--enable-qlog],
                              [Enable QLOG support (requires Jansson)])],
              [],
              [enable_qlog=no])
AM_CONDITIONAL([ENABLE_QLOG], false)
AS_IF([test "x$enable_qlog" != "xno"],
      [PKG_CHECK_MODULES([JANSSON],
                         [jansson >= 2.5.0],
                         [
                          AC_DEFINE(HAVE_QLOG)
                          enable_qlog=yes
                          AM_CONDITIONAL([ENABLE_QLOG], true)
                          IMQUIC_PACKAGES_PRIVATE="jansson >= 2.5.0"
                         ],
                         [
                          AC_MSG_ERROR([Jansson headers not found])])
                         ])

AC_SUBST(IMQUIC_PACKAGES_PUBLIC)
AC_SUBST(IMQUIC_PACKAGES_PRIVATE)

##
# Examples
##

AC_ARG_ENABLE([echo-examples],
              [AS_HELP_STRING([--enable-echo-examples],
                              [Build the QUIC echo server and client examples])],
              [],
              [enable_echo_examples=no])
AM_CONDITIONAL([ENABLE_ECHO_EXAMPLES], [test "x$enable_echo_examples" = "xyes"])

AC_ARG_ENABLE([moq-examples],
              [AS_HELP_STRING([--enable-moq-examples],
                              [Build the MoQ (Media Over QUIC) examples])],
              [],
              [enable_moq_examples=no])
AM_CONDITIONAL([ENABLE_MOQ_EXAMPLES], [test "x$enable_moq_examples" = "xyes"])

AC_ARG_ENABLE([roq-examples],
              [AS_HELP_STRING([--enable-roq-examples],
                              [Build the RoQ (RTP Over QUIC) examples])],
              [],
              [enable_roq_examples=no])
AM_CONDITIONAL([ENABLE_ROQ_EXAMPLES], [test "x$enable_roq_examples" = "xyes"])

##
# Docs
##

AC_ARG_ENABLE([docs],
              [AS_HELP_STRING([--enable-docs],
                              [Enable building documentation])],
              [],
              [enable_docs=no])

AC_CHECK_PROG([DOXYGEN],
              [doxygen],
              [doxygen])
AC_CHECK_PROG([DOT],
              [dot],
              [dot])
AS_IF([test -z "$DOXYGEN" -o -z "$DOT"],
      [
        AS_IF([test "x$enable_docs" = "xyes"],
              [AC_MSG_ERROR([doxygen or dot not found. See README.md for installation instructions or remove --enable-docs])])
      ])
AM_CONDITIONAL([ENABLE_DOCS], [test "x$enable_docs" = "xyes"])
if test "x$enable_docs" = "xyes"; then
    doxygen_version=$($DOXYGEN --version)
    AS_VERSION_COMPARE([$doxygen_version], [1.8.11],
                       [],
                       [],
                       [
                        AS_VERSION_COMPARE([$doxygen_version], [1.8.14],
                                           [AC_MSG_ERROR([Doxygen $doxygen_version not usable: versions between 1.8.12 and 1.8.14 are known to render poorly.])],
                                           [],
                                           []
                                          )
                       ]
                      )
fi

AM_CONDITIONAL([WITH_SOURCE_DATE_EPOCH], [test "x$SOURCE_DATE_EPOCH" != "x"])

##
# Summary
##

AC_CONFIG_FILES([
  Makefile
  src/Makefile
  examples/Makefile
  docs/Makefile
  imquic.pc
])

AC_OUTPUT

echo
echo "Compiler:      $CC"
AM_COND_IF([ENABLE_BORINGSSL],
	[echo "Encryption:    BoringSSL"],
	[echo "Encryption:    quictls"])
AM_COND_IF([ENABLE_QLOG],
	[echo "QLOG Support:  yes"],
	[echo "QLOG Support:  no"])
AM_COND_IF([ENABLE_DOCS],
	[echo "Documentation: yes"],
	[echo "Documentation: no"])
echo
echo "Examples:"
AM_COND_IF([ENABLE_ECHO_EXAMPLES],
	[echo "  -- Echo examples: yes"],
	[echo "  -- Echo examples: no"])
AM_COND_IF([ENABLE_MOQ_EXAMPLES],
	[echo "  -- MoQ examples:  yes"],
	[echo "  -- MoQ examples:  no"])
AM_COND_IF([ENABLE_ROQ_EXAMPLES],
	[echo "  -- RoQ examples:  yes"],
	[echo "  -- RoQ examples:  no"])

echo
echo "If this configuration is ok for you, do a 'make' to start building imquic. A 'make install' will install the library to the specified prefix."
echo
