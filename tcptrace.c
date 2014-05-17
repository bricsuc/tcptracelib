/*
 * Copyright (c) 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001,
 *               2002, 2003, 2004
 *	Ohio University.
 *
 * ---
 * 
 * Starting with the release of tcptrace version 6 in 2001, tcptrace
 * is licensed under the GNU General Public License (GPL).  We believe
 * that, among the available licenses, the GPL will do the best job of
 * allowing tcptrace to continue to be a valuable, freely-available
 * and well-maintained tool for the networking community.
 *
 * Previous versions of tcptrace were released under a license that
 * was much less restrictive with respect to how tcptrace could be
 * used in commercial products.  Because of this, I am willing to
 * consider alternate license arrangements as allowed in Section 10 of
 * the GNU GPL.  Before I would consider licensing tcptrace under an
 * alternate agreement with a particular individual or company,
 * however, I would have to be convinced that such an alternative
 * would be to the greater benefit of the networking community.
 * 
 * ---
 *
 * This file is part of Tcptrace.
 *
 * Tcptrace was originally written and continues to be maintained by
 * Shawn Ostermann with the help of a group of devoted students and
 * users (see the file 'THANKS').  The work on tcptrace has been made
 * possible over the years through the generous support of NASA GRC,
 * the National Science Foundation, and Sun Microsystems.
 *
 * Tcptrace is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Tcptrace is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tcptrace (in the file 'COPYING'); if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place, Suite 330, Boston,
 * MA 02111-1307 USA
 * 
 * Author:	Shawn Ostermann
 * 		School of Electrical Engineering and Computer Science
 * 		Ohio University
 * 		Athens, OH
 *		ostermann@cs.ohiou.edu
 *		http://www.tcptrace.org/
 */
#include "tcptrace.h"
static char const GCC_UNUSED copyright[] =
    "@(#)Copyright (c) 2004 -- Ohio University.\n";
static char const GCC_UNUSED rcsid[] =
    "@(#)$Header: /usr/local/cvs/tcptrace/tcptrace.c,v 5.59 2004/10/01 21:42:34 mramadas Exp $";

#include "file_formats.h"
#include "file_load.h"
#include "process.h"
#include "modules.h"
#include "version.h"

#include <stddef.h>

extern tcptrace_ext_bool_op tcptrace_extended_bools[];
extern tcptrace_ext_var_op tcptrace_extended_vars[];

/* version information */
static char *tcptrace_version = VERSION;


/* local routines */
static void Args(void);

static void DumpFlags(void);
static void ExplainOutput(void);
static void Help(char *harg);
static void Hints(void);
static void ListModules(void);
static void UsageModules(void);
static void CheckArguments(int *pargc, char *argv[]);
static void ParseArgs(char *argsource, int *pargc, char *argv[]);
static void ParseExtendedBool(char *argsource, char *arg);
static void ParseExtendedVar(char *argsource, char *arg);
static void QuitSig(int signum);
static void Usage(void);
static void BadArg(char *argsource, char *format, ...);
static void Version(void);
static char *FileToBuf(char *filename);

/* globals confined to this file */

/* global context (contains options and context for tcptrace client) */
static tcptrace_context_t *global_context;

static char **filenames = NULL;
static int num_files = 0;
static char *progname;

/* for elapsed processing time */
/* static struct timeval wallclock_start; */
static struct timeval wallclock_finished;

static void
Help(
    char *harg)
{
    if (harg && *harg && strncmp(harg,"arg",3) == 0) {
	Args();
    } else if (harg && *harg && strncmp(harg,"xarg",3) == 0) {
	UsageModules();
    } else if (harg && *harg && strncmp(harg,"filt",4) == 0) {
	HelpFilter();
    } else if (harg && *harg && strncmp(harg,"conf",4) == 0) {
	tcptrace_show_formats();
	CompFormats();
	ListModules();
    } else if (harg && *harg && strncmp(harg,"out",3) == 0) {
	ExplainOutput();
    } else if (harg && *harg &&
	       ((strncmp(harg,"hint",4) == 0) || (strncmp(harg,"int",3) == 0))) {
	Hints();
    } else {
	fprintf(stderr,"\
For help on specific topics, try:  \n\
  -hargs    tell me about the program's arguments  \n\
  -hxargs   tell me about the module arguments  \n\
  -hconfig  tell me about the configuration of this binary  \n\
  -houtput  explain what the output means  \n\
  -hfilter  output filtering help  \n\
  -hhints   usage hints  \n");
    }

    fprintf(stderr,"\n");
    Version();
    exit(0);
}



static void
BadArg(
    char *argsource,
    char *format,
    ...)
{
    va_list ap;

    fprintf(stderr,"Argument error");
    if (argsource)
	fprintf(stderr," (from %s)", argsource);
    fprintf(stderr,": ");
    
    va_start(ap,format);
    vfprintf(stderr,format,ap);
    va_end(ap);
    
    Usage();
}



static void
Usage(void)
{
    fprintf(stderr,"usage: %s [args...]* dumpfile [more files]*\n",
	    progname);

    Help(NULL);

    exit(-2);
}


static void
ExplainOutput(void)
{
    fprintf(stderr,"\n\
OK, here's a sample output (using -l) and what each line means:\n\
\n\
1 connection traced:\n\
              ####   how many distinct TCP connections did I see pieces of\n\
13 packets seen, 13 TCP packets traced\n\
              ####   how many packets did I see, how many did I trace\n\
connection 1:\n\
              #### I'll give you a separate block for each connection,\n\
              #### here's the first one\n\
	host a:        132.235.3.133:1084\n\
	host b:        132.235.1.2:79 \n\
              #### Each connection has two hosts.  To shorten output\n\
              #### and file names, I just give them letters.\n\
              #### Connection 1 has hosts 'a' and 'b', connection 2\n\
              #### has hosts 'c' and 'd', etc.\n\
	complete conn: yes\n\
              #### Did I see the starting FINs and closing SYNs?  Was it reset?\n\
	first packet:  Wed Jul 20 16:40:30.688114\n\
              #### At what time did I see the first packet from this connection?\n\
	last packet:   Wed Jul 20 16:40:41.126372\n\
              #### At what time did I see the last packet from this connection?\n\
	elapsed time:  0:00:10.438257\n\
              #### Elapsed time, first packet to last packet\n\
	total packets: 13\n\
              #### total packets this connection\n\
\n\
              #### ... Now, there's two columns of output (TCP is\n\
              #### duplex) one for each direction of packets.\n\
              #### I'll just explain one column...\n\
   a->b:			      b->a:\n\
     total packets:             7           total packets:             6\n\
              #### packets sent in each direction\n\
     ack pkts sent:             6           ack pkts sent:             6\n\
              #### how many of the packets contained a valid ACK\n\
     unique bytes sent:        11           unique bytes sent:      1152\n\
              #### how many data bytes were sent (not counting retransmissions)\n\
     actual data pkts:          2           actual data pkts:          1\n\
              #### how many packets did I see that contained any amount of data\n\
     actual data bytes:        11           actual data bytes:      1152\n\
              #### how many data bytes did I see (including retransmissions)\n\
     rexmt data pkts:           0           rexmt data pkts:           0\n\
              #### how many data packets were retransmissions\n\
     rexmt data bytes:          0           rexmt data bytes:          0\n\
              #### how many bytes were retransmissions\n\
     outoforder pkts:           0           outoforder pkts:           0\n\
              #### how many packets were out of order (or I didn't see the first transmit!)\n\
     SYN/FIN pkts sent:       1/1           SYN/FIN pkts sent:       1/1\n\
              #### how many SYNs and FINs were sent in each direction\n\
     mss requested:          1460 bytes     mss requested:          1460 bytes\n\
              #### What what the requested Maximum Segment Size\n\
     max segm size:             9 bytes     max segm size:          1152 bytes\n\
              #### What was the largest segment that I saw\n\
     min segm size:             2 bytes     min segm size:          1152 bytes\n\
              #### What was the smallest segment that I saw\n\
     avg segm size:             5 bytes     avg segm size:          1150 bytes\n\
              #### What was the average segment that I saw\n\
     max win adv:            4096 bytes     max win adv:            4096 bytes\n\
              #### What was the largest window advertisement that I sent\n\
     min win adv:            4096 bytes     min win adv:            4085 bytes\n\
              #### What was the smallest window advertisement that I sent\n\
     zero win adv:              0 times     zero win adv:              0 times\n\
              #### How many times did I sent a zero-sized window advertisement\n\
     avg win adv:            4096 bytes     avg win adv:            4092 bytes\n\
              #### What was the average window advertisement that I sent\n\
     initial window:            9 bytes     initial window:         1152 bytes\n\
              #### How many bytes in the first window (before the first ACK)\n\
     initial window:            1 pkts      initial window:            1 pkts\n\
              #### How many packets in the first window (before the first ACK)\n\
     throughput:                1 Bps       throughput:              110 Bps\n\
              #### What was the data throughput (Bytes/second)\n\
     ttl stream length:        11 bytes     ttl stream length:      1152 bytes\n\
              #### What was the total length of the stream (from FIN to SYN)\n\
              #### Note that this might be larger than unique data bytes because\n\
              #### I might not have captured every segment!!!\n\
     missed data:               0 bytes     missed data:               0 bytes\n\
              #### How many bytes of data were in the stream that I didn't see?\n\
     RTT samples:               2           RTT samples:               1\n\
              #### How many ACK's could I use to get an RTT sample\n\
     RTT min:                45.9 ms        RTT min:                19.4 ms\n\
              #### What was the smallest RTT that I saw\n\
     RTT max:               199.0 ms        RTT max:                19.4 ms\n\
              #### What was the largest RTT that I saw\n\
     RTT avg:               122.5 ms        RTT avg:                19.4 ms\n\
              #### What was the average RTT that I saw\n\
     RTT stdev:               0.0 ms        RTT stdev:               0.0 ms\n\
              #### What was the standard deviation of the RTT that I saw\n\
     segs cum acked:            0           segs cum acked:            0\n\
              #### How many segments were cumulatively ACKed (the ACK that I saw\n\
	      #### was for a later segment.  Might be a lost ACK or a delayed ACK\n\
     duplicate acks:            2           duplicate acks:            0\n\
              #### How many duplicate ACKs did I see\n\
     max # retrans:             0           max # retrans:             0\n\
              #### What was the most number of times that a single segment\n\
              #### was retransmitted\n\
     min retr time:           0.0 ms        min retr time:           0.0 ms\n\
              #### What was the minimum time between retransmissions of a\n\
              #### single segment\n\
     max retr time:           0.0 ms        max retr time:           0.0 ms\n\
              #### What was the maximum time between retransmissions of a\n\
              #### single segment\n\
     avg retr time:           0.0 ms        avg retr time:           0.0 ms\n\
              #### What was the average time between retransmissions of a\n\
              #### single segment\n\
     sdv retr time:           0.0 ms        sdv retr time:           0.0 ms\n\
              #### What was the stdev between retransmissions of a\n\
              #### single segment\n\
");
}



static void
Hints(void)
{
    fprintf(stderr,"\n\
Hints (in no particular order):\n\
For the first run through a file, just use \"tcptrace file\" to see\n\
   what's there\n\
For large files, use \"-t\" and I'll give you progress feedback as I go\n\
If there's a lot of hosts, particularly if they're non-local, use \"-n\"\n\
   to disable address to name mapping which can be very slow\n\
If you're graphing results and only want the information for a few conns,\n\
   from a large file, use the -o flag, as in \"tcptrace -o3,4,5 -o8-11\" to\n\
   only process connections 3,4,5, and 8 through 11.\n\
   Alternately, the '-oFILE' option allows you to write the connection\n\
   list into a file using some other program (or the file PF from -f)\n\
Make sure the snap length in the packet grabber is big enough.\n\
     Ethernet headers are 14 bytes, as are several others\n\
     IPv4 headers are at least 20 bytes, but can be as large as 64 bytes\n\
     TCP headers are at least 20 bytes, but can be as large as 64 bytes\n\
   Therefore, if you want to be SURE that you see all of the options,\n\
   make sure that you set the snap length to 14+64+64=142 bytes.  If\n\
   I'm not sure, I usually use 128 bytes.  If you're SURE that there are no\n\
   options (TCP usually has some), you still need at least 54 bytes.\n\
Compress trace files using gzip, I can uncompress them on the fly\n\
Stuff arguments that you always use into either the tcptrace resource file\n\
   ($HOME/%s) or the envariable %s.  If you need to turn\n\
   them off again from the command line, you can use\n\
   the \"+\" option flag.\n\
", TCPTRACE_RC_FILE, TCPTRACE_ENVARIABLE);
}


static void
Args(void)
{
    tcptrace_context_t *context = global_context;
    int i;
    
    fprintf(stderr,"\n\
Note: these options are first read from the file $HOME/%s\n\
  (if it exists), and then from the environment variable %s\n\
  (if it exists), and finally from the command line\n\
", TCPTRACE_RC_FILE, TCPTRACE_ENVARIABLE);
    fprintf(stderr,"\n\
Output format options\n\
  -b      brief output format\n\
  -l      long output format\n\
  -r      print rtt statistics (slower for large files)\n\
  -W      report on estimated congestion window (not generally useful)\n\
  -q      no output (if you just want modules output)\n\
Graphing options\n\
  -T      create throughput graph[s], (average over 10 segments, see -A)\n\
  -R      create rtt sample graph[s]\n\
  -S      create time sequence graph[s]\n\
  -N      create owin graph[s] (_o_utstanding data on _N_etwork)\n\
  -F      create segsize graph[s]\n\
  -L      create time line graph[s]\n\
  -G	  create ALL graphs\n\
Output format detail options\n\
  -D      print in decimal\n\
  -X      print in hexadecimal\n\
  -n      don't resolve host or service names (much faster)\n\
  -s      use short names (list \"picard.cs.ohiou.edu\" as just \"picard\")\n\
Connection filtering options\n\
  -iN     ignore connection N (can use multiple times)\n\
  -oN[-M] only connection N (or N through M).  Arg can be used many times.\n\
          If N is a file rather than a number, read list from file instead.\n\
  -c      ignore non-complete connections (didn't see syn's and fin's)\n\
  -BN     first segment number to analyze (default 1)\n\
  -EN     last segment number to analyze (default last in file)\n\
Graphing detail options\n\
  -C      produce color plot[s]\n\
  -M      produce monochrome (b/w) plot[s]\n\
  -AN     Average N segments for throughput graphs, default is 10\n\
  -z      zero axis options\n\
    -z      plot time axis from 0 rather than wall clock time (backward compat)\n\
    -zx     plot time axis from 0 rather than wall clock time\n\
    -zy     plot sequence numbers from 0 (time sequence graphs only)\n\
    -zxy    plot both axes from 0\n\
  -y      omit the (yellow) instantaneous throughput points in tput graph\n\
Misc options\n\
  -Z      dump raw rtt sample times to file[s]\n\
  -p      print all packet contents (can be very long)\n\
  -P      print packet contents for selected connections\n\
  -t      'tick' off the packet numbers as a progress indication\n\
  -fEXPR  output filtering (see -hfilter)\n\
  -v      print version information and exit\n\
  -w      print various warning messages\n\
  -d      whistle while you work (enable debug, use -d -d for more output)\n\
  -e      extract contents of each TCP stream into file\n\
  -h      print help messages\n\
  -u      perform (minimal) UDP analysis too\n\
  -Ofile  dump matched packets to tcpdump file 'file'\n\
  +[v]    reverse the setting of the -[v] flag (for booleans)\n\
Dump File Names\n\
  Anything else in the arguments is taken to be one or more filenames.\n\
  The files can be compressed, see compress.h for configuration.\n\
  If the dump file name is 'stdin', then we read from standard input\n\
    rather than from a file\n\
");

    fprintf(stderr,"\nExtended boolean options\n");
    fprintf(stderr," (unambiguous prefixes also work)\n");
    for (i = 0; tcptrace_extended_bools[i].bool_optname != NULL; i++) {
        Bool opt_val;
	tcptrace_ext_bool_op *pbop = &tcptrace_extended_bools[i];

        opt_val = tcptrace_get_option_bool(global_context, pbop->bool_optname);

	fprintf(stderr,"  --%-20s %s %s\n",
		pbop->bool_optname, pbop->bool_descr,
		(opt_val == pbop->bool_default)?"(default)":"");
	fprintf(stderr,"  --no%-18s DON'T %s %s\n",
		pbop->bool_optname, pbop->bool_descr,
		(opt_val != pbop->bool_default)?"(default)":"");
    }

    fprintf(stderr,"\nExtended variable options\n");
    fprintf(stderr," (unambiguous prefixes also work)\n");
    for (i=0; tcptrace_extended_vars[i].var_optname != NULL; i++) {
	char buf[256];		/* plenty large, but checked below with strncpy */
        char *var_value;

	tcptrace_ext_var_op *pvop = &tcptrace_extended_vars[i];
	strncpy(buf,pvop->var_optname,sizeof(buf)-10);
	strcat(buf,"=\"STR\"");

        /* var_location = find_str_option_location(pvop); */
        var_value = tcptrace_get_option_var(context, pvop->var_optname);

	fprintf(stderr,"  --%-20s %s (default: '%s')\n",
		buf,
		pvop->var_descr,
		var_value ? var_value : "<NULL>");
    }

    fprintf(stderr,"\n\
Module options\n\
  -xMODULE_SPECIFIC  (see -hxargs for details)\n\
");
}



static void
Version(void)
{
    fprintf(stderr,"Version: %s\n", tcptrace_version);
    fprintf(stderr,"  Compiled by '%s' at '%s' on machine '%s'\n",
	    tcptrace_built_bywhom, tcptrace_built_when, tcptrace_built_where);
}


static void
ListModules(void)
{
    int i;

    fprintf(stderr,"Included Modules:\n");
    for (i=0; i < NUM_MODULES; ++i) {
	fprintf(stderr,"  %-15s  %s\n",
		tcptrace_modules[i].module_name, tcptrace_modules[i].module_descr);
    }
}


static void
UsageModules(void)
{
    int i;

    for (i=0; i < NUM_MODULES; ++i) {
	fprintf(stderr," Module %s:\n", tcptrace_modules[i].module_name);
	if (tcptrace_modules[i].module_usage) {
	    fprintf(stderr,"    usage:\n");
	    (*tcptrace_modules[i].module_usage)();
	}
    }
}
     


int
main(
    int argc,
    char *argv[])
{
    int i;
    double etime;
    tcptrace_runtime_options_t *options;
    tcptrace_context_t *context;
    char *comment;
    u_int numfiles;
   
    /* allocate and initialize context */
    global_context = tcptrace_context_new();

    context = global_context;
    options = context->options;

    if (argc == 1) {
	Help(NULL);
    }

    /* initialize internals */
    trace_init(context);
    udptrace_init(context);

    /* let modules start first */
    tcptrace_modules_load(context, argc, argv);

    /* parse the flags */
    CheckArguments(&argc,argv);

    /* initialize plotter (picks up arguments from CheckArguments()) */
    plot_init(context);

    /* Used with <SP>-separated-values,
     * prints a '#' before each header line if --csv/--tsv is requested.
     */

    /* (this is admittedly dumb, but less dumb than what was here before) */
    comment = context->comment_prefix;
    if (options->csv || options->tsv || (options->sv != NULL)) {
        strncpy(comment, "# ", __TCPTRACE_COMMENT_PREFIX_MAX);
        comment[__TCPTRACE_COMMENT_PREFIX_MAX - 1] = '\0';
    }

    /* get starting wallclock time */
    gettimeofday(&context->wallclock_start, NULL);

    num_files = argc;
    printf("%s%d arg%s remaining, starting with '%s'\n",
	   comment,
	   num_files,
	   num_files>1?"s":"",
	   filenames[0]);

    if (tcptrace_debuglevel > 1)
	DumpFlags();

    /* knock, knock... */
    printf("%s%s\n\n", comment, VERSION);


    /* read each file in turn */
    numfiles = argc;
    for (i=0; i < argc; ++i) {
	if (tcptrace_debuglevel || (numfiles > 1)) {
	    if (argc > 1)
		printf("%sRunning file '%s' (%d of %d)\n", comment, filenames[i], i+1, numfiles);
	    else
		printf("%sRunning file '%s'\n", comment, filenames[i]);
	}

	/* do the real work */
	tcptrace_process_file(context, filenames[i]);
    }

    /* clean up output */
    if (options->printticks) {
	printf("\n");
    }

    /* get ending wallclock time */
    gettimeofday(&wallclock_finished, NULL);

    /* general output */
    fprintf(stdout, "%s%lu packets seen, %lu TCP packets traced",
	    comment, context->pnum, context->tcp_trace_count);
    if (options->do_udp) {
	fprintf(stdout,", %lu UDP packets traced", context->udp_trace_count);
    }
    fprintf(stdout,"\n");

    /* processing time */
    etime = elapsed(context->wallclock_start,wallclock_finished);
    fprintf(stdout, "%selapsed wallclock time: %s, %d pkts/sec analyzed\n",
	    comment,
	    elapsed2str(etime),
	    (int)((double)context->pnum/(etime/1000000)));

    /* actual tracefile times */
    etime = elapsed(context->first_packet, context->last_packet);
    fprintf(stdout,"%strace %s elapsed time: %s\n",
	    comment,
	    (num_files==1)?"file":"files",
	    elapsed2str(etime));
    if (tcptrace_debuglevel) {
	fprintf(stdout,"%s\tfirst packet:  %s\n", comment, ts2ascii(&context->first_packet));
	fprintf(stdout,"%s\tlast packet:   %s\n", comment, ts2ascii(&context->last_packet));
    }
    if (options->verify_checksums) {
	fprintf(stdout,"%sbad IP checksums:  %ld\n", comment, context->bad_ip_checksums);
	fprintf(stdout,"%sbad TCP checksums: %ld\n", comment, context->bad_tcp_checksums);
	if (options->do_udp) {
	    fprintf(stdout,"%sbad UDP checksums: %ld\n", comment, context->bad_udp_checksums);
        }
    }

    /* close files, cleanup, and etc... */
    trace_done(context);
    udptrace_done(context);

    tcptrace_modules_finish(context);
    plotter_done(context);

    tcptrace_context_free(context);
    global_context = NULL;

    exit(0);
}

/* TODO: see if this is still necessary */
static void
QuitSig(
    int signum)
{
    tcptrace_context_t *context;

    context = global_context;

    printf("%c\n\n", 7);  /* BELL */
    printf("Terminating processing early on signal %d\n", signum);
    printf("Partial result after processing %lu packets:\n\n\n", context->pnum);
    tcptrace_modules_finish(context);
    plotter_done(context);
    trace_done(context);
    udptrace_done(context);
    exit(1);
}


static void
CheckArguments(
    int *pargc,
    char *argv[])
{
    char *home;
    char *envariable;
    char *rc_path = NULL;
    char *rc_buf = NULL;

    tcptrace_runtime_options_t *options = global_context->options;

    /* remember the name of the program for errors... */
    progname = argv[0];

    /* first, we read from the config file, "~/.tcptracerc" */
    if ((home = getenv("HOME")) != NULL) {
	struct stat statbuf;

	int rc_len=strlen(home)+strlen(TCPTRACE_RC_FILE)+2;

	rc_path = malloc(rc_len);

	snprintf(rc_path,rc_len, "%s/%s", home, TCPTRACE_RC_FILE);
	if (tcptrace_debuglevel>1)
	    printf("Looking for resource file '%s'\n", rc_path);

	if (stat(rc_path,&statbuf) != 0) {
	    rc_path = NULL;
	} else {
	    int argc;
	    char **argv;
	    char *pch_file;
	    char *pch_new;
	    char *file_buf;

	    if (tcptrace_debuglevel>1)
		printf("resource file %s exists\n", rc_path);

	    /* read the file into a buffer */
	    rc_buf = file_buf = FileToBuf(rc_path);

	    /* if it exists but can't be read, that's a fatal error */
	    if (rc_buf == NULL) {
		fprintf(stderr,
			"Couldn't read resource file '%s'\n", rc_path);
		fprintf(stderr,
			"(either make the file readable or change its name)\n");
		exit(-1);
	    }
	    

	    /* make a new buffer to hold the converted string */
	    pch_file = rc_buf;
	    rc_buf = pch_new = MallocZ(strlen(file_buf)+3);

	    /* loop until end of string */
	    while (*pch_file) {
		if (*pch_file == '\n') {
		    /* turn newlines into spaces */
		    *pch_new++ = ' ';
		    ++pch_file;
		} else if (*pch_file == '#') {
		    /* skip over the '#' */
		    ++pch_file;

		    /* remove comments (until NULL or newline) */
		    while ((*pch_file != '\00') &&
			   (*pch_file != '\n')) {
			++pch_file;
		    }
		    /* insert a space */
		    *pch_new++ = ' ';
		} else {
		    /* just copy the characters */
		    *pch_new++ = *pch_file++;
		}
	    }

	    /* append a NULL to pch_new */
	    *pch_new = '\00';

	    if (tcptrace_debuglevel>2)
		printf("Resource file string: '%s'\n", rc_buf);

	    /* we're finished with the original buffer, but need to keep pch_new */
	    free(file_buf);

	    /* parse those args */
	    StringToArgv(rc_buf,&argc,&argv);
	    ParseArgs(TCPTRACE_RC_FILE, &argc, argv);
	}
    }

    /* next, we read from the environment variable "TCPTRACEOPTS" */
    if ((envariable = getenv(TCPTRACE_ENVARIABLE)) != NULL) {
	int argc;
	char **argv;

	if (tcptrace_debuglevel)
	    printf("envariable %s contains:\n\t'%s'\n",
		   TCPTRACE_ENVARIABLE, envariable);

	StringToArgv(envariable,&argc,&argv);
	ParseArgs(TCPTRACE_ENVARIABLE, &argc, argv);
    }

    /* lastly, we read the command line arguments */
    ParseArgs("command line",pargc,argv);

    /* make sure we found the files */
    if (filenames == NULL) {
	BadArg(NULL,"must specify at least one file name\n");
    }

    /* if debugging is on, tell what was in the ENV and rc file */
    if (tcptrace_debuglevel) {
	if (rc_path)
	    printf("Flags from %s: '%s'\n", rc_path, rc_buf);
	if (envariable)
	    printf("envariable %s contains: '%s'\n",
		   TCPTRACE_ENVARIABLE, envariable);
    }

    if (rc_buf)
	free(rc_buf);

    /* heuristic, I set "-t" in my config file, but they don't work inside */
    /* emacs shell windows, which is a pain.  If the terminal looks like EMACS, */
    /* then turn OFF ticks! */
    if (options->printticks) {
	char *TERM = getenv("TERM");
	/* allow emacs and Emacs */
	if ((TERM != NULL) && 
	    ((strstr(TERM,"emacs") != NULL) ||
	     (strstr(TERM,"Emacs") != NULL))) {
	    printf("Disabling ticks for EMACS shell window\n");
	    options->printticks = 0;
	}
    }
}


/* these extended boolean options are table driven, to make it easier to
   add more later without messing them up */
static void
ParseExtendedBool(
    char *argsource,
    char *arg)
{
    int i;
    tcptrace_context_t *context = global_context;
    tcptrace_ext_bool_op *pbop_found = NULL;
    tcptrace_ext_bool_op *pbop_prefix = NULL;
    Bool prefix_ambig = FALSE;
    Bool negative_arg_prefix;
    char *argtext;
    int arglen;

    /* there must be at least SOME text there */
    if ((strcmp(arg,"--") == 0) || (strcmp(arg,"--no") == 0))
	BadArg(argsource, "Void extended boolean argument\n");

    /* find just the arg text */
    if (strncmp(arg,"--no",4) == 0) {
	argtext = arg+4;
	negative_arg_prefix = TRUE;
    } else {
	argtext = arg+2;
	negative_arg_prefix = FALSE;
    }
    arglen = strlen(argtext);


    /* search for a match on each extended boolean arg */
    pbop_found = tcptrace_find_option_bool(argtext);

    /* if no exact match, look for a partial match */
    if (pbop_found == NULL) {
        for (i = 0; tcptrace_extended_bools[i].bool_optname != NULL; i++) {
            tcptrace_ext_bool_op *pbop = &tcptrace_extended_bools[i];

            /* check for a prefix match */
            if (strncmp(argtext,pbop->bool_optname,arglen) == 0) {
                if (pbop_prefix == NULL) {
                    pbop_prefix = pbop;
                } else {
                    prefix_ambig = TRUE;
                }
            }
        }
    }


    /* if we never found a match, it's an error */
    if ((pbop_found == NULL) && (pbop_prefix == NULL))
	BadArg(argsource, "Unknown extended boolean argument '%s' (see -hargs)\n", arg);


    /* if the prefix is UNambiguous, that's good enough */
    if ((pbop_prefix != NULL) && (!prefix_ambig))
	pbop_found = pbop_prefix;

    /* either exact match or good prefix, do it */
    if (pbop_found != NULL) {
        Bool target_val;

	if (negative_arg_prefix) {
            target_val= !pbop_found->bool_default;
	} else {
	    target_val= pbop_found->bool_default;
        }

        tcptrace_set_option_bool(context, pbop_found->bool_optname, target_val);

	if (tcptrace_debuglevel>2) {
	    fprintf(stderr,"Set boolean variable '%s' to '%s'\n",
		    argtext, BOOL2STR(tcptrace_get_option_bool(context, argtext)));
        }
	return;
    }

    /* ... else ambiguous prefix */
    fprintf(stderr,"Extended boolean arg '%s' is ambiguous, it matches:\n", arg);
    for (i = 0; tcptrace_extended_bools[i].bool_optname != NULL; i++) {
	tcptrace_ext_bool_op *pbop = &tcptrace_extended_bools[i];
	if (strncmp(argtext,pbop->bool_optname,arglen) == 0)
	    fprintf(stderr,"  %s%s - %s%s\n",
		    negative_arg_prefix?"no":"",
		    pbop->bool_optname,
		    negative_arg_prefix?"DON'T ":"",
		    pbop->bool_descr);
    }
    BadArg(argsource, "Ambiguous extended argument '%s'\n", arg);
    
    return;
}



/* these extended variable options are table driven, to make it easier to add more
   later without messing them up */
/* note: the format is of the form   --output_dir=string   */
/* note2: if the string was quoted as --output_dir="this directory"
   then those quotes were removed by the shell */
static void
ParseExtendedVar(
    char *argsource,
    char *arg_in)
{
    tcptrace_context_t *context = global_context;
    int i;
    tcptrace_ext_var_op *pvop_found = NULL;
    tcptrace_ext_var_op *pvop_prefix = NULL;
    Bool prefix_ambig = FALSE;
    char *pequals;
    char *argname;		/* the variable name itself */
    char *argval;		/* the part just beyond the equal sign */
    int arglen;
    char *arg;

    /* we're going to modify the argument to split it in half, we we'd
       better make a copy first */
    /* note that the only way out of this routine is through BadArg(),
       which just exits, or the single return() below, so this isn't
       a memory leak*/
    arg = strdup(arg_in);

    /* there must be at least SOME text there */
    if ((strcmp(arg,"--") == 0))
	BadArg(argsource, "Void extended variable argument\n");

    /* find the '=' sign, it MUST be there */
    /* (can't really happen, because the '=' forced us to this routine */
    pequals=strchr(arg,'=');
    if (!pequals)
	BadArg(argsource, "Extended variable argument with no assignment \n");


    /* break the arg in half at the '=' sign (located above) */
    argname = arg+2;
    argval = pequals+1;
    *pequals = '\00';		/* split the string here */
    /* --output_dir=test */
    /*   ^ argname = 1002 */
    /*              ^ argval = 1013 */
    /*  therefore length = argval(1013)-argname(1002)-1 (10) */
    arglen = argval - argname - 1;

    /* TODO: we can use tcptrace_find_option_var() here */
    /* search for a match in the extended variable table */
    for (i=0; tcptrace_extended_vars[i].var_optname != NULL; i++) {
	tcptrace_ext_var_op *pvop = &tcptrace_extended_vars[i];

	/* check for an exact match */
	if (strcmp(argname,pvop->var_optname) == 0) {
	    pvop_found = pvop;
	    break;
	}

	/* check for a prefix match */
	if (strncmp(argname,pvop->var_optname,arglen) == 0) {
	    if (pvop_prefix == NULL)
		pvop_prefix = pvop;
	    else
		prefix_ambig = TRUE; /* already found one */
	}
    }


    /* if we never found a match, it's an error */
    if ((pvop_found == NULL) && (pvop_prefix == NULL))
	BadArg(argsource, "Unknown extended variable argument '%s' (see -hargs)\n", arg);


    /* if the prefix is UNambiguous, that's good enough */
    if ((pvop_prefix != NULL) && (!prefix_ambig)) 
	pvop_found = pvop_prefix;

    /* either exact match or good prefix, do it */
    if (pvop_found != NULL) {
        tcptrace_set_option_var(context, pvop_found->var_optname, argval);
	free(arg);
	return;
    }

    /* ... else ambiguous prefix */
    fprintf(stderr,"Extended variable arg '%s' is ambiguous, it matches:\n", arg);
    for (i=0; tcptrace_extended_vars[i].var_optname != NULL; i++) {
	tcptrace_ext_var_op *pvop = &tcptrace_extended_vars[i];
	if (strncmp(argname,pvop->var_optname,arglen) == 0)
	    fprintf(stderr,"  %s - %s\n",
		    pvop->var_optname, pvop->var_descr);
    }
    BadArg(argsource, "Ambiguous extended variable argument '%s'\n", arg);
    /* never returns */
}


static void
ParseArgs(
    char *argsource,
    int *pargc,
    char *argv[])
{
    int i;
    int saw_i_or_o = 0;
    tcptrace_context_t *context = global_context;
    tcptrace_runtime_options_t *options = global_context->options;

    /* parse the args */
    for (i=1; i < *pargc; ++i) {
	/* modules might have stolen args... */
	if (argv[i] == NULL)
	    continue;

	// Arguments beginning with "--" could be regular extended
        // variables or booleans.
	if (strncmp(argv[i],"--",2) == 0) {
            if (strchr(argv[i],'=') != NULL) {
                ParseExtendedVar(argsource, argv[i]);
            } else {
                ParseExtendedBool(argsource, argv[i]);
            }
            continue;
	}

	if (*argv[i] == '-') {
	    if (argv[i][1] == '\00') /* just a '-' */
		Usage();

	    while (*(++argv[i]))
		switch (*argv[i]) {
		  case 'A':
		    if (isdigit((int)(*(argv[i]+1))))
			options->thru_interval = atoi(argv[i]+1);
		    else
			BadArg(argsource, "-A  number missing\n");
		    if (options->thru_interval <= 0)
			BadArg(argsource, "-A  must be > 1\n");
		    *(argv[i]+1) = '\00'; break;
		  case 'B':
		    if (isdigit((int)(*(argv[i]+1))))
			options->beginpnum = atoi(argv[i]+1);
		    else
			BadArg(argsource, "-B  number missing\n");
		    if (options->beginpnum < 0)
			BadArg(argsource, "-B  must be >= 0\n");
		    *(argv[i]+1) = '\00'; break;
		  case 'C': options->colorplot = TRUE; break;
		  case 'D': options->hex = FALSE; break;
		  case 'E':
		    if (isdigit((int)(*(argv[i]+1))))
			options->endpnum = atoi(argv[i]+1);
		    else
			BadArg(argsource, "-E  number missing\n");
		    if (options->endpnum < 0)
			BadArg(argsource, "-E  must be >= 0\n");
		    *(argv[i]+1) = '\00'; break;
		  case 'F': options->graph_segsize = TRUE; break;
		  case 'G':
		    options->graph_tput = TRUE;
		    options->graph_tsg = TRUE;
		    options->graph_rtt = TRUE;
		    options->graph_owin = TRUE;
		    options->graph_segsize = TRUE;
		    options->graph_tline = TRUE;
		    break;
		  case 'L': options->graph_tline = TRUE;
		    fprintf(stderr, "\nWarning: You have chosen the option '-L' to plot Time Line Graphs.\n         This option is yet under development and may not reflect accurate results.\n         Please take a look at the file README.tline_graphs for more details.\n\n");
		    break;
		  case 'M': options->colorplot = FALSE; break;
		  case 'N': options->graph_owin = TRUE; break;
		  case 'O':
		    if (*(argv[i]+1)) {
			/* -Ofile */
			context->output_filename = strdup(argv[i]+1);
			*(argv[i]+1) = '\00';
		    } else {
			/* maybe -O file */
			BadArg(argsource, "-Ofile requires a file name\n");
		    }
		    break;
		  case 'P': options->printem = TRUE; break;
		  case 'R': options->graph_rtt = TRUE; break;
		  case 'S': options->graph_tsg = TRUE; break;
		  case 'T': options->graph_tput = TRUE; break;
		  case 'W': options->print_owin = TRUE; break;
		  case 'X': options->hex = TRUE; break;
		  case 'Z': options->dump_rtt = TRUE; break;
		  case 'b': options->printbrief = TRUE; break;
		  case 'c': options->ignore_incomplete = TRUE; break;
		  case 'd': options->debug++; tcptrace_debuglevel++; break;
		  case 'e': options->save_tcp_data = TRUE; break;
		  case 'f':
		    options->filter_output = TRUE;
		    if (*(argv[i]+1)) {
			/* -fEXPR */
			ParseFilter(argv[i]+1);
			*(argv[i]+1) = '\00';
		    } else {
			/* -f EXPR */
			BadArg(argsource, "-f requires a filter\n");
		    }
		    break;
		  case 'h': Help(argv[i]+1); *(argv[i]+1) = '\00'; break;
		  case 'i': tcptrace_ignore_tcp(context, argsource, argv[i]+1);
/*			      {
		      int conn = -1;
		      if (options->run_continuously) {
			fprintf(stderr, "Warning: cannot ignore connections in continuous mode\n");
		      }
		      else
			   
		      else {
			  if (isdigit((int)(*(argv[i]+1))))
			      conn = atoi(argv[i]+1);
			  else
			      BadArg(argsource, "-i  number missing\n");
		          if (conn < 0)
			      BadArg(argsource, "-i  must be >= 0\n");
 		          ++saw_i_or_o;
		          gIgnoreConn(conn);
		      }
 }*/		      *(argv[i]+1) = '\00'; 
		     break;
		  case 'l': options->printbrief = FALSE; break;
		  case 'm':
		    BadArg(argsource,
			   "-m option is obsolete (no longer necessary)\n");
		    *(argv[i]+1) = '\00'; break;
		  case 'n':
		    options->resolve_ipaddresses = FALSE;
		    options->resolve_ports = FALSE;
		    break;
		  case 'o':
		    if (options->run_continuously) {
		        fprintf(stderr, "Warning: cannot use 'grab only' flag in continuous mode\n");
		    }
		    else {
		        ++saw_i_or_o;
		        tcptrace_select_tcp(context, argsource, argv[i]+1);
		    }
		    *(argv[i]+1) = '\00'; break;
		  case 'p': options->printallofem = TRUE; break;
		  case 'q': options->printsuppress = TRUE; break;
		  case 'r': options->print_rtt = TRUE; break;
		  case 's': options->use_short_names = TRUE; break;
		  case 't': options->printticks = TRUE; break;
		  case 'u': options->do_udp = TRUE; break;
		  case 'v': Version(); exit(0); break;
		  case 'w':
		    options->warn_printtrunc = TRUE;
		    options->warn_printbadmbz = TRUE;
		    options->warn_printhwdups = TRUE;
		    options->warn_printbadcsum = TRUE;
		    options->warn_printbad_syn_fin_seq = TRUE;
		    options->warn_ooo = TRUE;
		    break;
		  case 'x':
		    BadArg(argsource,
			   "unknown module option (-x...)\n");
		    break;
		  case 'y': options->plot_tput_instant = FALSE; break;
		  case 'z':
		    if (strcmp(argv[i],"z") == 0) {
			/* backward compat, just zero the time */
			options->graph_time_zero = TRUE;
		    } else if (strcasecmp(argv[i],"zx") == 0) {
			options->graph_time_zero = TRUE;
		    } else if (strcasecmp(argv[i],"zy") == 0) {
			options->graph_seq_zero = TRUE;
		    } else if ((strcasecmp(argv[i],"zxy") == 0) ||
			       (strcasecmp(argv[i],"zyx") == 0)) {
			/* set BOTH to zero */
			options->graph_time_zero = TRUE;
			options->graph_seq_zero = TRUE;
		    } else {
			BadArg(argsource, "only -z -zx -zy and -zxy are legal\n");
		    }
		    *(argv[i]+1) = '\00';
		    break;
		  default:
		    BadArg(argsource,
			   "option '%c' not understood\n", *argv[i]);
		}
	} else if (*argv[i] == '+') {
	    /* a few of them have a REVERSE flag too */
	    if (argv[i][1] == '\00') /* just a '+' */
		Usage();

	    while (*(++argv[i]))
		switch (*argv[i]) {
		  case 'C': options->colorplot = !TRUE; break;
		  case 'D': options->hex = !FALSE; break;
		  case 'F': options->graph_segsize = !TRUE; break;
		  case 'L': options->graph_tline = !TRUE; break;
		  case 'M': options->colorplot = !FALSE; break;
		  case 'N': options->graph_owin = !TRUE; break;
		  case 'P': options->printem = !TRUE; break;
		  case 'R': options->graph_rtt = !TRUE; break;
		  case 'S': options->graph_tsg = !TRUE; break;
		  case 'T': options->graph_tput = !TRUE; break;
		  case 'W': options->print_owin = !TRUE; break;
		  case 'X': options->hex = !TRUE; break;
		  case 'Z': options->dump_rtt = !TRUE; break;
		  case 'b': options->printbrief = !TRUE; break;
		  case 'c': options->ignore_incomplete = !TRUE; break;
		  case 'e': options->save_tcp_data = FALSE; break;
		  case 'l': options->printbrief = !FALSE; break;
		  case 'n':
		    options->resolve_ipaddresses = !FALSE;
		    options->resolve_ports = !FALSE;
		    break;
		  case 'p': options->printallofem = !TRUE; break;
		  case 'q': options->printsuppress = !TRUE; break;
		  case 'r': options->print_rtt = !TRUE; break;
		  case 's': options->use_short_names = !TRUE; break;
		  case 't': options->printticks = !TRUE; break;
		  case 'u': options->do_udp = !TRUE; break;
		  case 'w':
		    options->warn_printtrunc = !TRUE;
		    options->warn_printbadmbz = !TRUE;
		    options->warn_printhwdups = !TRUE;
		    options->warn_printbadcsum = !TRUE;
		    options->warn_ooo = !TRUE;
		    break;
		  case 'y':
                    options->plot_tput_instant = !options->plot_tput_instant;
                    break;
		  case 'z':
		    if (strcmp(argv[i],"z") == 0) {
			/* backward compat, just zero the time */
			options->graph_time_zero = !TRUE;
		    } else if (strcasecmp(argv[i],"zx") == 0) {
			options->graph_time_zero = !TRUE;
		    } else if (strcasecmp(argv[i],"zy") == 0) {
			options->graph_seq_zero = !TRUE;
		    } else if ((strcasecmp(argv[i],"zxy") == 0) ||
			       (strcasecmp(argv[i],"zyx") == 0)) {
			/* set BOTH to zero */
			options->graph_time_zero = !TRUE;
			options->graph_seq_zero = !TRUE;
		    } else {
			BadArg(argsource, "only +z +zx +zy and +zxy are legal\n");
		    }
		    *(argv[i]+1) = '\00';
		    break;
		  default:
		    Usage();
		}
	} else {
	    filenames = &argv[i];
	    *pargc -= i;
	    return;
	}
    }

    return;
}


static void
DumpFlags(void)
{
    int i;
    tcptrace_context_t *context = global_context;
    tcptrace_runtime_options_t *options = context->options;

    fprintf(stderr,"printbrief:       %s\n", BOOL2STR(options->printbrief));
    fprintf(stderr,"printsuppress:    %s\n", BOOL2STR(options->printsuppress));
    fprintf(stderr,"print_rtt:        %s\n", BOOL2STR(options->print_rtt));
    fprintf(stderr,"graph rtt:        %s\n", BOOL2STR(options->graph_rtt));
    fprintf(stderr,"graph tput:       %s\n", BOOL2STR(options->graph_tput));
    fprintf(stderr,"graph tsg:        %s\n", BOOL2STR(options->graph_tsg));
    fprintf(stderr,"graph segsize:    %s\n", BOOL2STR(options->graph_segsize));
    fprintf(stderr,"graph owin:       %s\n", BOOL2STR(options->graph_owin));
    fprintf(stderr,"graph tline:      %s\n", BOOL2STR(options->graph_tline));
    fprintf(stderr,"plotem:           %s\n",
	    options->colorplot?"(color)":"(b/w)");
    fprintf(stderr,"hex printing:     %s\n", BOOL2STR(options->hex));
    fprintf(stderr,"ignore_incomplete:  %s\n", BOOL2STR(options->ignore_incomplete));
    fprintf(stderr,"printem:          %s\n", BOOL2STR(options->printem));
    fprintf(stderr,"printallofem:     %s\n", BOOL2STR(options->printallofem));
    fprintf(stderr,"printticks:       %s\n", BOOL2STR(options->printticks));
    fprintf(stderr,"use_short_names:  %s\n", BOOL2STR(options->use_short_names));
    fprintf(stderr,"save_tcp_data:    %s\n", BOOL2STR(options->save_tcp_data));
    fprintf(stderr,"graph_time_zero:  %s\n", BOOL2STR(options->graph_time_zero));
    fprintf(stderr,"graph_seq_zero:   %s\n", BOOL2STR(options->graph_seq_zero));
    fprintf(stderr,"beginning pnum:   %lu\n", options->beginpnum);
    fprintf(stderr,"ending pnum:      %lu\n", options->endpnum);
    fprintf(stderr,"throughput intvl: %d\n", options->thru_interval);
    fprintf(stderr,"NS simulator hdrs:%s\n", BOOL2STR(options->ns_hdrs));
    fprintf(stderr,"number modules:   %u\n", (unsigned)NUM_MODULES);
    fprintf(stderr,"debug:            %s\n", BOOL2STR(tcptrace_debuglevel));
	
    /* print out the stuff controlled by the extended boolean args */
    for (i = 0; tcptrace_extended_bools[i].bool_optname != NULL; i++) {
	tcptrace_ext_bool_op *pbop = &tcptrace_extended_bools[i];
	char buf[100];
	snprintf(buf,sizeof(buf),"%s:", pbop->bool_optname);
        fprintf(stderr, "%-18s%s\n",
                buf, BOOL2STR(tcptrace_get_option_bool(context, pbop->bool_optname)));
    }

    /* print out the stuff controlled by the extended variable args */
    for (i=0; tcptrace_extended_vars[i].var_optname != NULL; i++) {
	tcptrace_ext_var_op *bvop = &tcptrace_extended_vars[i];
	char buf[100];
        char *option_value;

	snprintf(buf,sizeof(buf),"%s:", bvop->var_optname);
        option_value = tcptrace_get_option_var(context, bvop->var_optname);
	fprintf(stderr,"%-18s%s\n", buf, (option_value)?option_value:"<NULL>");
    }
}


/* read from a file, store contents into NULL-terminated string */
/* memory returned must be "free"ed to be reclaimed */
static char *
FileToBuf(
    char *filename)
{
    FILE *f;
    struct stat str_stat;
    int filesize;
    char *buffer;

    /* open the file */
    if ((f = fopen(filename,"r")) == NULL) {
	fprintf(stderr,"Open of '%s' failed\n", filename);
	perror(filename);
	return(NULL);
    }


    /* determine the file length */
    if (fstat(fileno(f),&str_stat) != 0) {
	perror("fstat");
	exit(1);
    }
    filesize = str_stat.st_size;

    /* make a big-enough buffer */
    buffer = MallocZ(filesize+2);  /* with room to NULL terminate */


    /* read the file into the buffer */
    if (fread(buffer,1,filesize,f) != filesize) {
	perror("fread");
	exit(1);
    }

    fclose(f);

    /* put a NULL at the end */
    buffer[filesize] = '\00';

    if (tcptrace_debuglevel > 1)
	printf("Read %d characters from resource '%s': '%s'\n",
	       filesize, filename, buffer);

    /* somebody else will "free" it */
    return(buffer);
}


