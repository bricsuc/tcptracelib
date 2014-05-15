
#include "tcptrace.h"

int tcptrace_debuglevel = 0;

/* create and initialize a new tcptrace runtime context, including
 * runtime options */
tcptrace_context_t *tcptrace_context_new() {
    tcptrace_context_t *context;
    tcptrace_runtime_options_t *options;

    context = malloc(sizeof(tcptrace_context_t));
    if (!context) {
        /* TODO: fail here */
    }
    tcptrace_initialize_context(context);

    options = malloc(sizeof(tcptrace_runtime_options_t));
    if (!options) {
        /* TODO: fail here */
    }
    tcptrace_initialize_options(options);
    context->options = options;

    return(context);
}

void tcptrace_context_free(tcptrace_context_t *context) {
    if (context->options != NULL) {
        free(context->options);
        context->options = NULL;
    }
    free(context);
}

/* initialize the tcptrace runtime context */
void
tcptrace_initialize_context(tcptrace_context_t *context) {
    context->pnum = 0;

    context->last_packet.tv_sec = 0;
    context->last_packet.tv_usec = 0;
    context->first_packet.tv_sec = 0;
    context->first_packet.tv_usec = 0;

    context->current_time.tv_sec = 0;
    context->current_time.tv_usec = 0;

    context->ctrunc = 0;
    context->bad_ip_checksums = 0;
    context->bad_tcp_checksums = 0;
    context->bad_udp_checksums = 0;

    context->num_modules = 0;

    context->comment_prefix[0] = '\0';   /* no comment prefix by default */

    context->current_filename = NULL;
    context->file_count = 0;
    context->output_filename = NULL;

    /* TCP data */
    context->num_tcp_pairs = -1;
    context->max_tcp_pairs = 64;
    context->ttp = NULL;

    context->tcp_trace_count = 0;

    context->tcp_packet_count = 0;
    context->tcp_search_count = 0;

    context->tcp_ignore_pairs = NULL;
    context->tcp_more_conns_ignored = FALSE;
    context->num_removed_tcp_pairs = 0;

    context->tcp_active_conn_count = 0;
    context->tcp_closed_conn_count = 0;

    context->tline_left = 0;
    context->tline_right = 0;

    /* UDP data */
    context->udptrace_initialized = FALSE;

    context->num_udp_pairs = -1;
    context->max_udp_pairs = 64;
    context->utp = NULL;

    { /* initialize UDP hash table */
        int i;
        for (i = 0; i < UDP_HASH_TABLE_SIZE; i++) {
            context->pup_hashtable[i] = NULL;
        }
    }

    context->udp_packet_count = 0;
    context->udp_search_count = 0;
    context->udp_ignore_pairs = NULL;
    context->udp_more_conns_ignored = FALSE;
    context->udp_connections_cleared = FALSE;

    context->udp_trace_count = 0;


    context->tcp_pair_pool = -1;
    context->udp_pair_pool = -1;
    context->seqspace_pool = -1;
    context->ptp_snap_pool = -1;
    context->ptp_ptr_pool = -1;

}

/* initialize the tcptrace runtime options */
void
tcptrace_initialize_options(tcptrace_runtime_options_t *options) {
    options->debug = 0;

    options->beginpnum = 0;
    options->endpnum = 0;

    options->do_udp = FALSE;

    options->resolve_ipaddresses = TRUE;

    /* this doesn't seem to work on my Linux system-- */
    /* getservbyport() appears to fail */
    /* (it would be nice to remove all of that stuff from the code anyway) */
    options->resolve_ports = TRUE;

    options->print_rtt = FALSE;
    options->print_owin = FALSE;
    options->printbrief = TRUE;
    options->printsuppress = FALSE;

    options->ignore_incomplete = FALSE;

    options->printem = FALSE;
    options->printallofem = FALSE;
    options->printticks = FALSE;

    options->warn_ooo = FALSE;
    options->warn_printtrunc = FALSE;
    options->warn_printbadmbz = FALSE;
    options->warn_printhwdups = FALSE;
    options->warn_printbadcsum = FALSE;
    options->warn_printbad_syn_fin_seq = FALSE;

    options->show_title = TRUE;
    options->colorplot = TRUE;
    options->dump_rtt = FALSE;
    options->graph_rtt = FALSE;
    options->graph_tput = FALSE;
    options->graph_tsg = FALSE;
    options->graph_segsize = FALSE;
    options->graph_owin = FALSE;
    options->graph_tline = FALSE;

    options->hex = TRUE;

    options->show_rwinline = TRUE;

    options->graph_time_zero = FALSE;
    options->graph_seq_zero = FALSE;
    options->print_seq_zero = FALSE;
    options->graph_zero_len_pkts = TRUE;
    options->plot_tput_instant = TRUE;
    options->filter_output = FALSE;

    options->show_out_order = TRUE;
    options->show_rexmit = TRUE;
    options->show_zero_window = TRUE;
    options->show_sacks = TRUE;
    options->show_rtt_dongles = FALSE;
    options->show_zwnd_probes = TRUE;
    options->show_urg = TRUE;
    options->use_short_names = FALSE;

    options->show_triple_dupack = TRUE;

    options->triple_dupack_allows_data = FALSE;

    options->docheck_hw_dups = TRUE;
    options->save_tcp_data = FALSE;

    options->verify_checksums = FALSE;

    options->dump_packet_data = FALSE;

    /* realtime options */
    options->run_continuously = FALSE;
    options->conn_num_threshold = FALSE;
    options->xplot_all_files = FALSE;
    options->ns_hdrs = TRUE; /* realtime or just applicable to format? */
    options->dup_ack_handling = TRUE;

    options->csv = FALSE;
    options->tsv = FALSE;

    /* "long-format" string/int options */
    options->output_file_dir = NULL;
    options->output_file_prefix = NULL;
    options->xplot_title_prefix = NULL;
    options->xplot_args = NULL;
    options->sv = NULL;

    options->sep = NULL;

    /* TODO: maybe fix these strings */
    options->update_interval = UPDATE_INTERVAL;
    options->update_interval_s = "UPDATE_INTERVAL";
    options->max_conn_num = MAX_CONN_NUM;
    options->max_conn_num_s = "MAX_CONN_NUM";
    options->remove_live_conn_interval = REMOVE_LIVE_CONN_INTERVAL;
    options->remove_live_conn_interval_s = "REMOVE_LIVE_CONN_INTERVAL";
    options->nonreal_live_conn_interval = NONREAL_LIVE_CONN_INTERVAL;
    options->nonreal_live_conn_interval_s = "NONREAL_LIVE_CONN_INTERVAL";
    options->remove_closed_conn_interval = REMOVE_CLOSED_CONN_INTERVAL;
    options->remove_closed_conn_interval_s = "REMOVE_CLOSED_CONN_INTERVAL";

    options->thru_interval = 10; /* segments */

}

