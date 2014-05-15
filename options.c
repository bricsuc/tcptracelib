
#include "tcptrace.h"
#include <stddef.h>

#define __T_OPTIONS_OFFSET(field) offsetof(tcptrace_runtime_options_t,field)

/* extended boolean options */
tcptrace_ext_bool_op tcptrace_extended_bools[] = {
    {"showsacks", __T_OPTIONS_OFFSET(show_sacks), TRUE,
     "show SACK blocks on time sequence graphs"},
    {"showrexmit", __T_OPTIONS_OFFSET(show_rexmit), TRUE,
     "mark retransmits on time sequence graphs"},
    {"showoutorder", __T_OPTIONS_OFFSET(show_out_order), TRUE,
     "mark out-of-order on time sequence graphs"},
    {"showzerowindow", __T_OPTIONS_OFFSET(show_zero_window), TRUE,
     "mark zero windows on time sequence graphs"},
    {"showurg", __T_OPTIONS_OFFSET(show_urg), TRUE,
     "mark packets with URGENT bit set on the time sequence graphs"},
    {"showrttdongles", __T_OPTIONS_OFFSET(show_rtt_dongles), TRUE,
     "mark non-RTT-generating ACKs with special symbols"},
    {"showdupack3", __T_OPTIONS_OFFSET(show_triple_dupack), TRUE,
     "mark triple dupacks on time sequence graphs"},
    {"showzerolensegs", __T_OPTIONS_OFFSET(graph_zero_len_pkts),  TRUE,
     "show zero length packets on time sequence graphs"},
    {"showzwndprobes", __T_OPTIONS_OFFSET(show_zwnd_probes), TRUE,
     "show zero window probe packets on time sequence graphs"},
    {"showtitle", __T_OPTIONS_OFFSET(show_title), TRUE,
     "show title on the graphs"},
    {"showrwinline", __T_OPTIONS_OFFSET(show_rwinline), TRUE,
     "show yellow receive-window line in owin graphs"},
    {"res_addr", __T_OPTIONS_OFFSET(resolve_ipaddresses), TRUE,
     "resolve IP addresses into names (may be slow)"},
    {"res_port", __T_OPTIONS_OFFSET(resolve_ports), TRUE,
     "resolve port numbers into names"},
    {"checksum", __T_OPTIONS_OFFSET(verify_checksums), TRUE,
     "verify IP and TCP checksums"},
    {"dupack3_data", __T_OPTIONS_OFFSET(triple_dupack_allows_data), TRUE,
     "count a duplicate ACK carrying data as a triple dupack"},
    {"check_hwdups", __T_OPTIONS_OFFSET(docheck_hw_dups), TRUE,
     "check for 'hardware' dups"},
    {"warn_ooo", __T_OPTIONS_OFFSET(warn_ooo), TRUE,
     "print warnings when packets timestamps are out of order"},
    {"warn_printtrunc", __T_OPTIONS_OFFSET(warn_printtrunc), TRUE,
     "print warnings when packets are too short to analyze"},
    {"warn_printbadmbz", __T_OPTIONS_OFFSET(warn_printbadmbz), TRUE,
     "print warnings when MustBeZero TCP fields are NOT 0"},
    {"warn_printhwdups", __T_OPTIONS_OFFSET(warn_printhwdups), TRUE,
     "print warnings for hardware duplicates"},
    {"warn_printbadcsum", __T_OPTIONS_OFFSET(warn_printbadcsum), TRUE,
     "print warnings when packets with bad checksums"},
    {"warn_printbad_syn_fin_seq", __T_OPTIONS_OFFSET(warn_printbad_syn_fin_seq), TRUE,
     "print warnings when SYNs or FINs rexmitted with different sequence numbers"},
    {"dump_packet_data", __T_OPTIONS_OFFSET(dump_packet_data), TRUE,
     "print all packets AND dump the TCP/UDP data"},
    {"continuous", __T_OPTIONS_OFFSET(run_continuously), TRUE,
     "run continuously and don't provide a summary"},
    {"print_seq_zero", __T_OPTIONS_OFFSET(print_seq_zero), TRUE,
     "print sequence numbers as offset from initial sequence number"},
    {"limit_conn_num", __T_OPTIONS_OFFSET(conn_num_threshold), TRUE,
     "limit the maximum number of connections kept at a time in real-time mode"},
    {"xplot_all_files", __T_OPTIONS_OFFSET(xplot_all_files), TRUE,
     "display all generated xplot files at the end"},
    {"ns_hdrs", __T_OPTIONS_OFFSET(ns_hdrs), TRUE,
     "assume that ns has the useHeaders_flag true (uses IP+TCP headers)"},
    {"csv", __T_OPTIONS_OFFSET(csv), TRUE,
     "display the long output as comma separated values"},
    {"tsv", __T_OPTIONS_OFFSET(tsv), TRUE,
     "display the long output as tab separated values"},
    {"turn_off_BSD_dupack", __T_OPTIONS_OFFSET(dup_ack_handling), FALSE,
     "turn off the BSD version of the duplicate ack handling"},
    /* null-filled record to indicate end of array */
    {NULL, 0, FALSE, NULL}
};

/* extended variable verification routines */
static u_long VerifyPositive(char *varname, char *value);
static void VerifyUpdateInt(tcptrace_context_t *context, char *varname, char *value);
static void VerifyMaxConnNum(tcptrace_context_t *context, char *varname, char *value);
static void VerifyLiveConnInt(tcptrace_context_t *context, char *varname, char *value);
static void VerifyNonrealLiveConnInt(tcptrace_context_t *context, char *varname, char*value);
static void VerifyClosedConnInt(tcptrace_context_t *context, char *varname, char *value);

static Bool *find_option_location_bool(tcptrace_runtime_options_t *options, tcptrace_ext_bool_op *bopt);

/* string/variable options */
tcptrace_ext_var_op tcptrace_extended_vars[] = {
    {"output_dir", __T_OPTIONS_OFFSET(output_file_dir), NULL,
     "directory where all output files are placed"},
    {"output_prefix", __T_OPTIONS_OFFSET(output_file_prefix), NULL,
     "prefix all output files with this string"},
    {"xplot_title_prefix", __T_OPTIONS_OFFSET(xplot_title_prefix), NULL,
     "prefix to place in the titles of all xplot files"},
    {"update_interval", 0, VerifyUpdateInt,
     "time interval for updates in real-time mode"},
    {"max_conn_num", 0, VerifyMaxConnNum,
     "maximum number of connections to keep at a time in real-time mode"},
    {"remove_live_conn_interval", 0, VerifyLiveConnInt,
     "idle time after which an open connection is removed in real-time mode"},
    {"endpoint_reuse_interval", 0, VerifyNonrealLiveConnInt,
     "time interval of inactivity after which an open connection is considered closed"},
    {"remove_closed_conn_interval", 0, VerifyClosedConnInt,
     "time interval after which a closed connection is removed in real-time mode"},
    {"xplot_args", __T_OPTIONS_OFFSET(xplot_args), NULL,
     "arguments to pass to xplot, if we are calling xplot from here"},
    {"sv", __T_OPTIONS_OFFSET(sv), NULL,
     "separator to use for long output with <STR>-separated-values"},
    {NULL, 0, NULL, NULL}
};

#define NUM_EXTENDED_VARS (sizeof(extended_vars) / sizeof(struct ext_var_op))

static char **find_option_location_str(tcptrace_runtime_options_t *options, tcptrace_ext_var_op *popt);



/* try to find a boolean option's runtime location */
static Bool *find_option_location_bool(tcptrace_runtime_options_t *options, tcptrace_ext_bool_op *bopt) {
    Bool *option_location = NULL;

    if (bopt->runtime_struct_offset != 0) {
        /* if this is an offset, find the actual location */
        unsigned char *p = (unsigned char *) options;
        p += bopt->runtime_struct_offset;
        option_location = (Bool *) p;
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


tcptrace_ext_var_op
*tcptrace_find_option_var(char *argname) {
    tcptrace_ext_var_op *option_found = NULL;
    int i;

    for (i = 0; tcptrace_extended_vars[i].var_optname != NULL; i++) {
        tcptrace_ext_var_op *option = &tcptrace_extended_vars[i];
        if (strcmp(argname, option->var_optname) == 0) {
            option_found = option;
            break;
        }
    }

    return(option_found);
}



char *tcptrace_get_option_var(tcptrace_context_t *context, char *argname) {
    tcptrace_ext_var_op *pvop;
    char **option_loc;

    pvop = tcptrace_find_option_var(argname);

    if (pvop == NULL) {
        /* option not found */
        fprintf(stderr, "option %s not found.\n", argname);
        return("");
    }

    /* some of these options don't show up as offsets */
    if (pvop->runtime_struct_offset == 0) {
        fprintf(stderr, "option %s not a string.\n", argname);
        return("");
    }

    option_loc = find_option_location_str(context->options, pvop);

    return(*option_loc);

}


/* try to find a string option's runtime location */
static char **find_option_location_str(tcptrace_runtime_options_t *options, tcptrace_ext_var_op *popt) {
    char **option_location = NULL;

    // option_location = popt->var_popt;

    if (option_location == NULL) {
        if (popt->runtime_struct_offset != 0) {
            /* if this is an offset, find the actual location */
            unsigned char *p = (unsigned char *) options;
            p += popt->runtime_struct_offset;
            option_location = (char **) p;
        } else {
            option_location = NULL;
        }
    }
    return(option_location);
}

static u_long
VerifyPositive(
    char *varname,
    char *value)
{
    int i, ivalue = 0;

    for (i = 0; i < strlen(value); i++) {
        if (!isdigit((int)value[i])) {
	    fprintf(stderr, 
		    "Value '%s' is not valid for variable '%s'\n", 
		    value, varname);
	    exit(1);
	}
    }
    ivalue = atoi(value);
    if (ivalue <= 0) {
	fprintf(stderr,
		"Value '%s' is not valid for variable '%s'\n", 
		value, varname);
	exit(1);
    }

    return (u_long)ivalue;
}


static void
VerifyUpdateInt(
    tcptrace_context_t *context,
    char *varname,
    char *value)
{
    tcptrace_runtime_options_t *options = context->options;

    options->update_interval = VerifyPositive(varname, value);
}


static void 
VerifyMaxConnNum(
    tcptrace_context_t *context,
    char *varname, 
    char *value)
{
    tcptrace_runtime_options_t *options = context->options;

    options->max_conn_num = VerifyPositive(varname, value);
    options->conn_num_threshold = TRUE;
}


static void 
VerifyLiveConnInt(
    tcptrace_context_t *context,
    char *varname, 
    char *value)
{
    tcptrace_runtime_options_t *options = context->options;

    options->remove_live_conn_interval = VerifyPositive(varname, value);
}

static void
VerifyNonrealLiveConnInt(
    tcptrace_context_t *context,
    char *varname,
    char *value)
{
    tcptrace_runtime_options_t *options = context->options;

    options->nonreal_live_conn_interval = VerifyPositive(varname, value);
}


static void 
VerifyClosedConnInt(
    tcptrace_context_t *context,
    char *varname, 
    char *value)
{
    tcptrace_runtime_options_t *options = context->options;

    options->remove_closed_conn_interval = VerifyPositive(varname, value);  
}

