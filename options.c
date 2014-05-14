
#include "tcptrace.h"
#include <stddef.h>

#define __T_OPTIONS_OFFSET(field) offsetof(tcptrace_runtime_options_t,field)

/* extended boolean options */
tcptrace_ext_bool_op tcptrace_extended_bools[] = {
    {"showsacks", NULL, __T_OPTIONS_OFFSET(show_sacks), TRUE,
     "show SACK blocks on time sequence graphs"},
    {"showrexmit", NULL, __T_OPTIONS_OFFSET(show_rexmit), TRUE,
     "mark retransmits on time sequence graphs"},
    {"showoutorder", NULL, __T_OPTIONS_OFFSET(show_out_order), TRUE,
     "mark out-of-order on time sequence graphs"},
    {"showzerowindow", NULL, __T_OPTIONS_OFFSET(show_zero_window), TRUE,
     "mark zero windows on time sequence graphs"},
    {"showurg", NULL, __T_OPTIONS_OFFSET(show_urg), TRUE,
     "mark packets with URGENT bit set on the time sequence graphs"},
    {"showrttdongles", NULL, __T_OPTIONS_OFFSET(show_rtt_dongles), TRUE,
     "mark non-RTT-generating ACKs with special symbols"},
    {"showdupack3", NULL, __T_OPTIONS_OFFSET(show_triple_dupack), TRUE,
     "mark triple dupacks on time sequence graphs"},
    {"showzerolensegs", NULL, __T_OPTIONS_OFFSET(graph_zero_len_pkts),  TRUE,
     "show zero length packets on time sequence graphs"},
    {"showzwndprobes", NULL, __T_OPTIONS_OFFSET(show_zwnd_probes), TRUE,
     "show zero window probe packets on time sequence graphs"},
    {"showtitle", NULL, __T_OPTIONS_OFFSET(show_title), TRUE,
     "show title on the graphs"},
    {"showrwinline", NULL, __T_OPTIONS_OFFSET(show_rwinline), TRUE,
     "show yellow receive-window line in owin graphs"},
    {"res_addr", NULL, __T_OPTIONS_OFFSET(resolve_ipaddresses), TRUE,
     "resolve IP addresses into names (may be slow)"},
    {"res_port", NULL, __T_OPTIONS_OFFSET(resolve_ports), TRUE,
     "resolve port numbers into names"},
    {"checksum", NULL, __T_OPTIONS_OFFSET(verify_checksums), TRUE,
     "verify IP and TCP checksums"},
    {"dupack3_data", NULL, __T_OPTIONS_OFFSET(triple_dupack_allows_data), TRUE,
     "count a duplicate ACK carrying data as a triple dupack"},
    {"check_hwdups", NULL, __T_OPTIONS_OFFSET(docheck_hw_dups), TRUE,
     "check for 'hardware' dups"},
    {"warn_ooo", NULL, __T_OPTIONS_OFFSET(warn_ooo), TRUE,
     "print warnings when packets timestamps are out of order"},
    {"warn_printtrunc", NULL, __T_OPTIONS_OFFSET(warn_printtrunc), TRUE,
     "print warnings when packets are too short to analyze"},
    {"warn_printbadmbz", NULL, __T_OPTIONS_OFFSET(warn_printbadmbz), TRUE,
     "print warnings when MustBeZero TCP fields are NOT 0"},
    {"warn_printhwdups", NULL, __T_OPTIONS_OFFSET(warn_printhwdups), TRUE,
     "print warnings for hardware duplicates"},
    {"warn_printbadcsum", NULL, __T_OPTIONS_OFFSET(warn_printbadcsum), TRUE,
     "print warnings when packets with bad checksums"},
    {"warn_printbad_syn_fin_seq", NULL, __T_OPTIONS_OFFSET(warn_printbad_syn_fin_seq), TRUE,
     "print warnings when SYNs or FINs rexmitted with different sequence numbers"},
    {"dump_packet_data", NULL, __T_OPTIONS_OFFSET(dump_packet_data), TRUE,
     "print all packets AND dump the TCP/UDP data"},
    {"continuous", NULL, __T_OPTIONS_OFFSET(run_continuously), TRUE,
     "run continuously and don't provide a summary"},
    {"print_seq_zero", NULL, __T_OPTIONS_OFFSET(print_seq_zero), TRUE,
     "print sequence numbers as offset from initial sequence number"},
    {"limit_conn_num", NULL, __T_OPTIONS_OFFSET(conn_num_threshold), TRUE,
     "limit the maximum number of connections kept at a time in real-time mode"},
    {"xplot_all_files", NULL, __T_OPTIONS_OFFSET(xplot_all_files), TRUE,
     "display all generated xplot files at the end"},
    {"ns_hdrs", NULL, __T_OPTIONS_OFFSET(ns_hdrs), TRUE,
     "assume that ns has the useHeaders_flag true (uses IP+TCP headers)"},
    {"csv", NULL, __T_OPTIONS_OFFSET(csv), TRUE,
     "display the long output as comma separated values"},
    {"tsv", NULL, __T_OPTIONS_OFFSET(tsv), TRUE,
     "display the long output as tab separated values"},
    {"turn_off_BSD_dupack", NULL, __T_OPTIONS_OFFSET(dup_ack_handling), FALSE,
     "turn off the BSD version of the duplicate ack handling"},
    /* null-filled record to indicate end of array */
    {NULL, NULL, 0, FALSE, NULL}
};

static Bool *find_option_location_bool(tcptrace_runtime_options_t *options, tcptrace_ext_bool_op *bopt);

/* try to find a boolean option's runtime location */
static Bool *find_option_location_bool(tcptrace_runtime_options_t *options, tcptrace_ext_bool_op *bopt) {
    Bool *option_location;

    /* TODO: we removed the address. Don't need this option_location stuff
     * anymore */

    option_location = bopt->bool_popt;

    if (option_location == NULL) {
        if (bopt->runtime_struct_offset != 0) {
            /* if this is an offset, find the actual location */
            unsigned char *p = (unsigned char *) options;
            p += bopt->runtime_struct_offset;
            option_location = (Bool *) p;
        } else {
            return(NULL);
        }
    }
    return(option_location);
}

tcptrace_ext_bool_op
*tcptrace_find_option_bool(char *argname) {
    tcptrace_ext_bool_op *option_found = NULL;
    int i;

    for (i = 0; tcptrace_extended_bools[i].bool_optname != NULL; i++) {
        tcptrace_ext_bool_op *option = &tcptrace_extended_bools[i];
        if (strcmp(argname, option->bool_optname) == 0) {
            option_found = option;
            break;
        }
    }

    return(option_found);
}

/* TODO: function to look for ambiguous option */

int tcptrace_set_option_bool(tcptrace_context_t *context, char *argname, Bool value) {
    tcptrace_ext_bool_op *pbop;
    Bool *option_loc;

    pbop = tcptrace_find_option_bool(argname);
    if (pbop == NULL) {
        /* option not found */
        return(-1);
    }

    option_loc = find_option_location_bool(context->options, pbop);
    *option_loc = value;

    return(0);
}

Bool tcptrace_get_option_bool(tcptrace_context_t *context, char *argname) {
    tcptrace_ext_bool_op *pbop;
    Bool *option_loc;

    pbop = tcptrace_find_option_bool(argname);

    if (pbop == NULL) {
        /* option not found */
        fprintf(stderr, "option %s not found.\n", argname);
        return(FALSE);
    }

    option_loc = find_option_location_bool(context->options, pbop);

    return(*option_loc);

}

