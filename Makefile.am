AUTOMAKE_OPTIONS = foreign

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
    tcpdump.c tcptrace.c thruput.c trace.c ipv6.c   \
    filter.c udp.c \
    ns.c netscout.c version.c pool.c poolaccess.c \
    dstring.c \
    filt_parser.y \
    filt_scanner.l

tcptrace_LDADD = @LEXLIB@

tcptrace_CPPFLAGS =

# Input format options

if FORMAT_PCAP
    tcptrace_CPPFLAGS += -DGROK_TCPDUMP
endif

# Module options

if MOD_TRAFFIC
    tcptrace_CPPFLAGS += -DLOAD_MODULE_TRAFFIC
    tcptrace_SOURCES += mod_traffic.c
endif

