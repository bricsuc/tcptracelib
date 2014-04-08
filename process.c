
#include "tcptrace.h"
#include "file_load.h"
#include "process.h"

Bool
check_packet_type(raw_packet_t *raw_packet,
                  tcptrace_working_file *working_file,
                  tcptrace_state_t *state) {

    /* TODO: need test for this one */
    /* quick sanity check, better be an IPv4/v6 packet */
    if (!PIP_ISV4(raw_packet->pip) && !PIP_ISV6(raw_packet->pip)) {
        static Bool warned = FALSE;

        if (!warned) {
            fprintf(stderr,
                    "Warning: saw at least one non-ip packet\n");
            warned = TRUE;
        }

        if (debug) {
            fprintf(stderr,
                    "Skipping packet %lu, not an IPv4/v6 packet (version:%d)\n",
                    state->pnum, IP_V(raw_packet->pip));
        }
        return(FALSE);
    }

    /* TODO: need test for this one */
#if 0
    /* another sanity check, only understand ETHERNET right now */
    if (phystype != PHYS_ETHER) {
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
                    state->pnum);
        } /* else, just shut up */
        return(FALSE);
    }
#endif

    return(TRUE);
}
