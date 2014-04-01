#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.68])
AC_INIT([tcptrace], [6.6.7], [bri@aem7.net])
AM_INIT_AUTOMAKE([-Wall foreign])
# AC_CONFIG_SRCDIR([mod_collie.c])
# AC_CONFIG_HEADERS([config.h])

## Input format options

# pcap/tcpdump (enabled by default)
AC_ARG_ENABLE([pcap],
              [AC_HELP_STRING([--disable-pcap], [Disable pcap/tcpdump format])],
              [], [enable_pcap=yes])
AM_CONDITIONAL([FORMAT_PCAP], [test x$enable_pcap = xyes])

# snoop (enabled by default)
AC_ARG_ENABLE([snoop],
              [AC_HELP_STRING([--disable-snoop], [Disable Sun snoop format])],
              [], [enable_snoop=yes])
AM_CONDITIONAL([FORMAT_SNOOP], [test x$enable_snoop = xyes])

# netm (enabled by default)
AC_ARG_ENABLE([netm],
              [AC_HELP_STRING([--disable-netm], [Disable HP netm format])],
              [], [enable_netm=yes])
AM_CONDITIONAL([FORMAT_NETM], [test x$enable_netm = xyes])

# etherpeek (enabled by default)
AC_ARG_ENABLE([etherpeek],
              [AC_HELP_STRING([--disable-etherpeek], [Disable etherpeek format])],
              [], [enable_etherpeek=yes])
AM_CONDITIONAL([FORMAT_ETHERPEEK], [test x$enable_etherpeek = xyes])

# LBL network simulator (enabled by default)
AC_ARG_ENABLE([ns],
              [AC_HELP_STRING([--disable-ns], [Disable LBL ns format])],
              [], [enable_ns=yes])
AM_CONDITIONAL([FORMAT_NS], [test x$enable_ns = xyes])

# netscout (enabled by default)
AC_ARG_ENABLE([netscout],
              [AC_HELP_STRING([--disable-netscout], [Disable netscout format])],
              [], [enable_netscout=yes])
AM_CONDITIONAL([FORMAT_NETSCOUT], [test x$enable_netscout = xyes])

# Endace Technology dagsnap (enabled by default)
AC_ARG_ENABLE([erf],
              [AC_HELP_STRING([--disable-erf], [Disable Endace dagsnap format])],
              [], [enable_erf=yes])
AM_CONDITIONAL([FORMAT_ERF], [test x$enable_erf = xyes])

# NLANL NLANR (disabled by default, supposedly not working well)
AC_ARG_ENABLE([nlanr],
              [AC_HELP_STRING([--enable-nlanr=@<:@yes/no@:>@], [Enable NLANR format])],
              [], [enable_nlanr=no])
AM_CONDITIONAL([FORMAT_NLANR], [test x$enable_nlanr = xyes])

## Module options

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

# Math library.
AC_SEARCH_LIBS([sqrt],[m])
AC_SEARCH_LIBS([floor],[m])
AC_SEARCH_LIBS([ceilf],[m])
AC_SEARCH_LIBS([truncf],[m])

# Others
# should probably barf when any of these are missing
AC_CHECK_FUNCS([bzero dup2 gethostbyaddr gettimeofday inet_ntoa memchr memmove memset mkdir munmap strcasecmp strchr strdup strncasecmp strrchr strstr])

# look for pcap (tcpdump) library if pcap is enabled
AM_COND_IF([FORMAT_PCAP],
    AC_CHECK_LIB([pcap], [pcap_dispatch],
                 [],
                 AM_CONDITIONAL([FORMAT_PCAP], [false])
    )
)

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