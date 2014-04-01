#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([tcptrace], [6.6.7], [bri@aem7.net])
AM_INIT_AUTOMAKE([-Wall foreign])
# AC_CONFIG_SRCDIR([mod_collie.c])
# AC_CONFIG_HEADERS([config.h])

AC_ARG_ENABLE([mod-traffic],
              [AC_HELP_STRING([--disable-mod-traffic], [Disable Traffic Module])],
              [],
              [enable_mod_traffic=yes])

AM_CONDITIONAL([MOD_TRAFFIC], [test x$enable_mod_traffic = xyes])

# Checks for programs.
AC_PROG_CC
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_INSTALL

AM_PROG_LEX
AC_PROG_YACC

# Checks for libraries.

# Checks for header files.
AC_FUNC_ALLOCA
AC_CHECK_HEADERS([arpa/inet.h fcntl.h limits.h malloc.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/socket.h sys/time.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_OFF_T
AC_TYPE_SIZE_T

AC_CHECK_SIZEOF(unsigned long long int)
AC_CHECK_SIZEOF(unsigned long int)
AC_CHECK_SIZEOF(unsigned int)
AC_CHECK_SIZEOF(unsigned short)

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_FUNC_MMAP
AC_FUNC_REALLOC
AC_SEARCH_LIBS([sqrt],[m])
AC_SEARCH_LIBS([floor],[m])
AC_SEARCH_LIBS([ceilf],[m])
AC_SEARCH_LIBS([truncf],[m])
AC_CHECK_FUNCS([bzero dup2 gethostbyaddr gettimeofday inet_ntoa memchr memmove memset mkdir munmap strcasecmp strchr strdup strncasecmp strrchr strstr])
# should probably go barf when any of those are missing

# Checks for _BSD_SOURCE flag
if [[ -f /lib/libc-2* -o -f /lib/*linux*/libc-2* ]]; then
 CPPFLAGS="$CPPFLAGS -D_BSD_SOURCE"
fi

# version.c stuff
BUILT_USER=\\\"`whoami`\\\"
BUILT_DATE=\\\"`date`\\\"
BUILT_HOST=\\\"`hostname`\\\"
CPPFLAGS="$CPPFLAGS -DBUILT_USER=\"$BUILT_USER\" -DBUILT_DATE=\"$BUILT_DATE\" -DBUILT_HOST=\"$BUILT_HOST\""

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
