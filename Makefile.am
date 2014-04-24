AUTOMAKE_OPTIONS = foreign
# ACLOCAL_AMFLAGS([-I m4])

bin_PROGRAMS = tcptrace

# have yacc generate filt_parser.h
BUILT_SOURCES = filt_parser.h

# need to rename token prefix because libpcap uses the default
AM_YFLAGS = -d -p filtyy
# need to rename token prefix in lex, too, but also need to keep the
# output file the same, due to automake's ylwrap program
AM_LFLAGS = -P filtyy -o lex.yy.c

tcptrace_SOURCES = \
    avl.c compress.c erf.c etherpeek.c gcache.c mfiles.c names.c \
    netm.c output.c plotter.c print.c rexmit.c snoop.c nlanr.c \
    tcpdump.c tcptrace.c thruput.c trace.c \
    filter.c udp.c \
    ns.c netscout.c version.c pool.c poolaccess.c \
    dstring.c \
    filt_parser.y \
    filt_scanner.l

tcptrace_LDADD = libtcptrace.la @LEXLIB@

tcptrace_CPPFLAGS =

lib_LTLIBRARIES = libtcptrace.la
libtcptrace_la_SOURCES = \
    ipv6.c file_load.c initialize.c process.c modules.c modules_list.c
libtcptrace_la_CPPFLAGS = 

# Input format options
# Have to fix these includes, probably

if FORMAT_PCAP
    tcptrace_CPPFLAGS += -DGROK_TCPDUMP
    libtcptrace_la_CPPFLAGS += -DGROK_TCPDUMP
endif
if FORMAT_SNOOP
    tcptrace_CPPFLAGS += -DGROK_SNOOP
    libtcptrace_la_CPPFLAGS += -DGROK_SNOOP
endif
if FORMAT_NETM
    tcptrace_CPPFLAGS += -DGROK_NETM
    libtcptrace_la_CPPFLAGS += -DGROK_NETM
endif
if FORMAT_ETHERPEEK
    tcptrace_CPPFLAGS += -DGROK_ETHERPEEK
    libtcptrace_la_CPPFLAGS += -DGROK_ETHERPEEK
endif
if FORMAT_NS
    tcptrace_CPPFLAGS += -DGROK_NS
    libtcptrace_la_CPPFLAGS += -DGROK_NS
endif
if FORMAT_NLANR
    tcptrace_CPPFLAGS += -DGROK_NLANR
    libtcptrace_la_CPPFLAGS += -DGROK_NLANR
endif
if FORMAT_NETSCOUT
    tcptrace_CPPFLAGS += -DGROK_NETSCOUT
    libtcptrace_la_CPPFLAGS += -DGROK_NETSCOUT
endif
if FORMAT_ERF
    tcptrace_CPPFLAGS += -DGROK_ERF
    libtcptrace_la_CPPFLAGS += -DGROK_ERF
endif

# Module options

if MOD_HTTP
    tcptrace_CPPFLAGS += -DLOAD_MODULE_HTTP -DHTTP_SAFE -DHTTP_DUMP_TIMES
    libtcptrace_la_CPPFLAGS += -DLOAD_MODULE_HTTP -DHTTP_SAFE -DHTTP_DUMP_TIMES
    libtcptrace_la_SOURCES += mod_http.c
endif
if MOD_TRAFFIC
    tcptrace_CPPFLAGS += -DLOAD_MODULE_TRAFFIC
    libtcptrace_la_CPPFLAGS += -DLOAD_MODULE_TRAFFIC
    libtcptrace_la_SOURCES += mod_traffic.c
endif
if MOD_SLICE
    tcptrace_CPPFLAGS += -DLOAD_MODULE_SLICE
    libtcptrace_la_CPPFLAGS += -DLOAD_MODULE_SLICE
    libtcptrace_la_SOURCES += mod_slice.c
endif
if MOD_RTT
    tcptrace_CPPFLAGS += -DLOAD_MODULE_RTTGRAPH
    libtcptrace_la_CPPFLAGS += -DLOAD_MODULE_RTTGRAPH
    libtcptrace_la_SOURCES += mod_rttgraph.c
endif
if MOD_COLLIE
    tcptrace_CPPFLAGS += -DLOAD_MODULE_COLLIE
    libtcptrace_la_CPPFLAGS += -DLOAD_MODULE_COLLIE
    libtcptrace_la_SOURCES += mod_collie.c
endif
if MOD_REALTIME
    tcptrace_CPPFLAGS += -DLOAD_MODULE_REALTIME
    libtcptrace_la_CPPFLAGS += -DLOAD_MODULE_REALTIME
    libtcptrace_la_SOURCES += mod_realtime.c
endif

# modules disabled by default
if MOD_INBOUNDS
    tcptrace_CPPFLAGS += -DLOAD_MODULE_INBOUNDS
    libtcptrace_la_CPPFLAGS += -DLOAD_MODULE_INBOUNDS
    libtcptrace_la_SOURCES += mod_inbounds.c
endif
if MOD_TCPLIB
    tcptrace_CPPFLAGS += -DLOAD_MODULE_TCPLIB
    libtcptrace_la_CPPFLAGS += -DLOAD_MODULE_TCPLIB
    libtcptrace_la_SOURCES += mod_tcplib.c
endif

# decompression options
if COMPRESS_GZIP
    tcptrace_CPPFLAGS += -DGUNZIP=\"gunzip\"
endif

if COMPRESS_BZIP2
    tcptrace_CPPFLAGS += -DBUNZIP2=\"bunzip2\"
endif

# missing: dependencies?

