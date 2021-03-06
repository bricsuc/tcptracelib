
#include "tcptrace.h"
#include "file_load.h"
#include "process.h"

static void progress_counter(tcptrace_context_t *context, raw_packet_t *raw_packet, tcptrace_working_file *working_file);

void
tcptrace_process_file(
    tcptrace_context_t *context,
    char *filename)
{
    pread_f *ppread;
    int ret;
    struct ip *pip;
    struct tcphdr *ptcp;
    int phystype;
    void *phys;  /* physical transport header */
    tcp_pair *ptp;
    int fix;
    int len;
    int tlen;
    void *plast;
    struct stat str_stat;
    long int location = 0;
    Bool is_stdin;

    tcptrace_runtime_options_t *options;

    /* storage for current working files and packets */
    tcptrace_working_file working_file_s, *working_file;
    raw_packet_t raw_packet;

    working_file = &working_file_s;

    options = context->options;

    /* set the current file name */
    context->current_filename = filename;

    /* load the file */
    {
        tcptrace_load_status_t status;
        status = tcptrace_load_file(filename, working_file);
        if (status != TCPTRACE_LOAD_SUCCESS) {
            exit(1);
            /* could use different exit codes depending on status */
            /* could also move some error reporting here */
        }
    }

    ppread = working_file->reader_function;
    is_stdin = working_file->is_stdin;
    working_file->pnum = 0;
    working_file->location = 0;

    if (tcptrace_debuglevel) {
        printf("Trace file size: %lu bytes\n", working_file->filesize);
    }

    location = 0;

    /* notify the modules of new file */
    tcptrace_modules_all_newfile(context, working_file, filename);

    context->file_count++;

    /* read each packet */
    while (1) {
        /* read the next packet */
	ret = (*ppread)(context, &context->current_time,&len,&tlen,&phys,&phystype,&pip,&plast);
	if (ret == 0) /* EOF */
	    break;

	/* update global and per-file packet counters */
	context->pnum++;        /* global */
	working_file->pnum++;	/* local to this file */

        /* TODO: move this stuff to read packet struct (maybe) */
        /* not sure if timestamp is necessary in raw_packet */
        /* (though it's the "correct" place for it) */
        raw_packet.timestamp = &context->current_time;
        raw_packet.pip = pip;
        raw_packet.len = len;
        raw_packet.tlen = tlen;
        raw_packet.phystype = phystype;
        raw_packet.phys = phys;
        raw_packet.plast = plast;


	/* in case only a subset analysis was requested */
	if (context->pnum < options->beginpnum) {
            continue;
        }

	if ((context->options->endpnum != 0) &&
            (context->pnum > options->endpnum)) {
	    context->pnum--;
	    working_file->pnum--;
	    break;
        }

#if 0
	/* install signal handler */
	if (working_file->pnum == 1) {
	    signal(SIGINT,QuitSig);
	}
#endif

        progress_counter(context, &raw_packet, working_file);

        ret = tcptrace_process_packet(context, &raw_packet, working_file);
        /* TODO: check ret, see if anything needs to be done about it */

#if 0
        /* TODO: this signal business doesn't seem necessary, and could */
        /* be harmful. Why would you have an abnormal number of signals here? */
        /* Would there be a problem if you did a ^C and the output was not */
        /* consistent? (and why would you care about that?) */
        /* can we trap signals in context, return, then die gracefully? */
        /* determine why this code is here and eliminate it if possible */

	/* for efficiency, only allow a signal every 1000 packets	*/
	/* (otherwise the system call overhead will kill us)		*/
	if (context->pnum % 1000 == 0) {
	    sigset_t mask;

	    sigemptyset(&mask);
	    sigaddset(&mask,SIGINT);

	    sigprocmask(SIG_UNBLOCK, &mask, NULL);
	    /* signal can happen EXACTLY HERE, when data structures are consistant */
	    sigprocmask(SIG_BLOCK, &mask, NULL);
	}
#endif /* 0, signal handler business */

    }

#if 0
    /* set ^C back to the default */
    /* (so we can kill the output if needed) */
    {
	sigset_t mask;

	sigemptyset(&mask);
	sigaddset(&mask,SIGINT);

	sigprocmask(SIG_UNBLOCK, &mask, NULL);
	signal(SIGINT,SIG_DFL);
    }
#endif

    /* unset current filename */
    context->current_filename = NULL;

    /* close the input file */
    CompCloseFile(working_file);

}



Bool
check_packet_type(tcptrace_context_t *context,
                  raw_packet_t *raw_packet,
                  tcptrace_working_file *working_file)
{

    /* TODO: need test for this one */
    /* quick sanity check, better be an IPv4/v6 packet */
    if (!PIP_ISV4(raw_packet->pip) && !PIP_ISV6(raw_packet->pip)) {
        static Bool warned = FALSE;

        if (!warned) {
            fprintf(stderr,
                    "Warning: saw at least one non-ip packet\n");
            warned = TRUE;
        }

        if (tcptrace_debuglevel) {
            fprintf(stderr,
                    "Skipping packet %lu, not an IPv4/v6 packet (version:%d)\n",
                    context->pnum, IP_V(raw_packet->pip));
        }
        return(FALSE);
    }

    /* TODO: need test for this one */
    /* another sanity check, only understand ETHERNET right now */
    if (raw_packet->phystype != PHYS_ETHER) {
        static int not_ether = 0;

        ++not_ether;
        if (not_ether == 5) {
            fprintf(stderr,
                    "More non-ethernet packets skipped (last warning)\n");
            fprintf(stderr, "\n\
If you'll send me a trace and offer to help, I can add support\n\
for other packet types, I just don't have a place to test them\n\n");
        } else if (not_ether < 5) {
            fprintf(stderr,
                    "Skipping packet %lu, not an ethernet packet\n",
                    context->pnum);
        } /* else, just shut up */
        return(FALSE);
    }

    return(TRUE);
}

int tcptrace_process_packet(tcptrace_context_t *context,
                            raw_packet_t *raw_packet,
                            tcptrace_working_file *working_file) {
    tcptrace_runtime_options_t *options = context->options;
    struct tcphdr *ptcp;
    tcp_pair *ptp;
    int ret;

    /* check for out-of-order packets (by timestamp, not protocol) */
    /* not sure why this first check is necessary */
    if (!ZERO_TIME(&context->last_packet)) {
        if (tv_gt(context->last_packet, context->current_time)) {
            /* out of order */
            if ((context->file_count > 1) && (working_file->pnum == 1)) {
                fprintf(stderr, "\
Warning, first packet in file %s comes BEFORE the last packet\n\
in the previous file.  That will likely confuse the program, please\n\
order the files in time if you have trouble\n", context->current_filename);
            } else {
                static int warned = 0;

                if (options->warn_ooo) {
                    fprintf(stderr, "\
Warning, packet %ld in file %s comes BEFORE the previous packet\n\
That will likely confuse the program, so be careful!\n",
                            working_file->pnum, context->current_filename);
                } else if (!warned) {
                    fprintf(stderr, "\
Packets in file %s are out of order.\n\
That will likely confuse the program, so be careful!\n", context->current_filename);
                }
                warned = 1;
            }

        }
    }
    

    if (check_packet_type(context, raw_packet, working_file) == FALSE) {
        /* if we don't support this packet type, skip it */
        return(-1);  /* TODO: enum return types */
    }

    /* print the packet, if requested */
    if (options->printallofem || options->dump_packet_data) {
        printf("Packet %lu\n", context->pnum);
        /* TODO: fix this function just to use raw_packet */
        printpacket(context,
                    raw_packet->len,
                    raw_packet->tlen,
                    raw_packet->phys,
                    raw_packet->phystype,
                    raw_packet->pip,
                    raw_packet->plast,
                    NULL);
    }

    /* keep track of global times */
    if (ZERO_TIME(&context->first_packet)) {
        context->first_packet = context->current_time;
    }
    context->last_packet = context->current_time;

    /* verify IP checksums, if requested */
    if (options->verify_checksums) {
        if (!ip_cksum_valid(raw_packet->pip, raw_packet->plast)) {
            context->bad_ip_checksums++;
            if (options->warn_printbadcsum) {
                fprintf(stderr, "packet %lu: bad IP checksum\n", context->pnum);
            }
            return(-1);  /* TODO: enum return codes */
        }
    }
                   
    /* find the start of the TCP header */
    ret = gettcp(context, raw_packet->pip, &ptcp, &raw_packet->plast);


    /* if that failed, it's not TCP */
    if (ret < 0) {
        udp_pair *pup;
        struct udphdr *pudp;

        /* look for a UDP header */
        ret = getudp(context, raw_packet->pip, &pudp, &raw_packet->plast);

        if (options->do_udp && (ret == 0)) {
            pup = tcptrace_run_trace_udp(context, raw_packet->pip, pudp, raw_packet->plast);

            /* verify UDP checksums, if requested */
            if (options->verify_checksums) {
                if (!udp_cksum_valid(context, raw_packet->pip, pudp, raw_packet->plast)) {
                    context->bad_udp_checksums++;
                    if (options->warn_printbadcsum) {
                        fprintf(stderr, "packet %lu: bad UDP checksum\n",
                                context->pnum);
                    }
                    return(-1);  /* TODO: enum return codes */
                }
            }
                   
            /* if it's a new connection, tell the modules */
            if (pup && pup->packets == 1) {
                tcptrace_modules_newconn_udp(context, pup);
            }
            /* also, pass the packet to any modules defined */
            tcptrace_modules_readpacket_udp(context, raw_packet->pip, pup, raw_packet->plast);
        } else if (ret < 0) {
            /* neither UDP nor TCP */
            tcptrace_modules_readpacket_nottcpudp(context, raw_packet->pip, raw_packet->plast);
        }

        /* TODO: enum return. This is either a UDP or "other" packet. */
        return(0);

    } else if (ret > 0) { /* not a valid TCP packet */
        /* TODO: enum return. */
        return(-1);
    }

    /* verify TCP checksums, if requested */
    if (options->verify_checksums) {
        if (!tcp_cksum_valid(context, raw_packet->pip, ptcp, raw_packet->plast)) {
            context->bad_tcp_checksums++;
            if (options->warn_printbadcsum) {
                fprintf(stderr, "packet %lu: bad TCP checksum\n", context->pnum);
            }
            /* TODO: enum return (here, bad checksum) */
            return(-1);
        }
    }
                   
    /* perform TCP packet analysis */
    ptp = tcptrace_run_trace_tcp(context, raw_packet->pip, ptcp, raw_packet->plast); 
    /* if it wasn't "interesting", we return NULL here */
    if (ptp == NULL) {
        /* TODO: enum return. What does "not interesting" mean? */
        return(-1);
    }

    /* unless this connection is being ignored, tell the modules about it */
    if (!ptp->ignore_pair) {
        /* if it's a new connection, tell the modules */
        if (ptp->packets == 1) {
            tcptrace_modules_newconn(context, ptp);
        }

        /* pass the packet to any modules */
        tcptrace_modules_readpacket(context, raw_packet->pip, ptp, raw_packet->plast);
    }
    
    /* TODO: enum return (this is "success," or, "tcp packet processed") */
    return(0);

}

static void progress_counter(tcptrace_context_t *context,
                             raw_packet_t *raw_packet,
                             tcptrace_working_file *working_file) {

    tcptrace_runtime_options_t *options = context->options;

    if (!options->printem &&
        !options->printallofem &&
        options->printticks) {
        if (CompIsCompressed(working_file))
            working_file->location += raw_packet->tlen;  /* just guess... */
        if (((working_file->pnum <    100) && (working_file->pnum %    10 == 0)) ||
            ((working_file->pnum <   1000) && (working_file->pnum %   100 == 0)) ||
            ((working_file->pnum <  10000) && (working_file->pnum %  1000 == 0)) ||
            ((working_file->pnum >= 10000) && (working_file->pnum % 10000 == 0))) {

            unsigned frac;

            if (tcptrace_debuglevel)
                fprintf(stderr, "%s: ", context->current_filename);
            if (working_file->is_stdin) {
                fprintf(stderr ,"%lu", working_file->pnum);
            } else if (CompIsCompressed(working_file)) {
                frac = working_file->location/(working_file->filesize/100);
                if (frac <= 100) {
                    fprintf(stderr ,"%lu ~%u%% (compressed)", working_file->pnum, frac);
                } else {
                    fprintf(stderr ,"%lu ~100%% + %u%% (compressed)", working_file->pnum, frac-100);
                }
            } else {
                working_file->location = ftell(stdin);
                frac = working_file->location/(working_file->filesize/100);

                fprintf(stderr ,"%lu %u%%", working_file->pnum, frac);
            }
            /* print elapsed time */
            {
                double etime = elapsed(context->first_packet,context->last_packet);
                fprintf(stderr," (%s)", elapsed2str(etime));
            }

            /* carriage return (but not newline) */
            fprintf(stderr ,"\r");
        }
        fflush(stderr);
    }
}
