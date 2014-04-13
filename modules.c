/* module action interface */

#include "tcptrace.h"
#include "modules.h"

/* inform all modules of a new file */
void
tcptrace_modules_all_newfile(
    /* TODO: these arguments are sort of redundant, possibly streamline
     * into "state" */
    tcptrace_state_t *state,
    tcptrace_working_file *working_file,
    char *filename)
{
    int i;
    struct module *modules = tcptrace_modules;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!modules[i].module_inuse)
	    continue;  /* module disabled */

	if (modules[i].module_newfile == NULL) {
	    continue;  /* module doesn't want to be notified of new files */
        }

	if (debug>3) {
	    fprintf(stderr,"Calling newfile routine for module \"%s\"\n",
		    modules[i].module_name);
        }

	(*modules[i].module_newfile)(filename, working_file->filesize, CompIsCompressed());
    }
}

void
tcptrace_modules_load(
    tcptrace_state_t *state,
    int argc,
    char *argv[])
{
    int i;
    int enable;

    for (i=0; i < NUM_MODULES; ++i) {
	state->num_modules++;
	if (debug)
	    fprintf(stderr,"Initializing module \"%s\"\n",
		    tcptrace_modules[i].module_name);
	enable = (*tcptrace_modules[i].module_init)(state, argc, argv);
	if (enable) {
	    if (debug)
		fprintf(stderr,"Module \"%s\" enabled\n",
			tcptrace_modules[i].module_name);
	    tcptrace_modules[i].module_inuse = TRUE;
	} else {
	    if (debug)
		fprintf(stderr,"Module \"%s\" not active\n",
			tcptrace_modules[i].module_name);
	    tcptrace_modules[i].module_inuse = FALSE;
	}
    }

}



void
tcptrace_modules_finish(tcptrace_state_t *state)
{
    int i;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!tcptrace_modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (tcptrace_modules[i].module_done == NULL)
	    continue;  /* might not have a cleanup */

	if (debug)
	    fprintf(stderr,"Calling cleanup for module \"%s\"\n",
		    tcptrace_modules[i].module_name);

	(*tcptrace_modules[i].module_done)(state);
    }
}


void
tcptrace_modules_newconn(
    tcptrace_state_t *state,
    tcp_pair *ptp)
{
    int i;
    void *pmodstruct;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!tcptrace_modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (tcptrace_modules[i].module_newconn == NULL)
	    continue;  /* they might not care */

	if (debug>3)
	    fprintf(stderr,"Calling newconn routine for module \"%s\"\n",
		    tcptrace_modules[i].module_name);

	pmodstruct = (*tcptrace_modules[i].module_newconn)(state, ptp);
	if (pmodstruct) {
	    /* make sure the array is there */
	    if (!ptp->pmod_info) {
		ptp->pmod_info = MallocZ(state->num_modules * sizeof(void *));
	    }

	    /* remember this structure */
	    ptp->pmod_info[i] = pmodstruct;
	}
    }
}


void
tcptrace_modules_deleteconn(
                  tcptrace_state_t *state,
		  tcp_pair *ptp)
{
    int i;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!tcptrace_modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (tcptrace_modules[i].module_deleteconn == NULL)
	    continue;  /* they might not care */

	if (debug>3)
	    fprintf(stderr,"Calling delete conn routine for module \"%s\"\n",
		    tcptrace_modules[i].module_name);

	(*tcptrace_modules[i].module_deleteconn)(ptp,
					ptp->pmod_info?ptp->pmod_info[i]:NULL);
    }
}


void
tcptrace_modules_newconn_udp(
    tcptrace_state_t *state,
    udp_pair *pup)
{
    int i;
    void *pmodstruct;
    struct module *modules = tcptrace_modules;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (modules[i].module_udp_newconn == NULL)
	    continue;  /* they might not care */

	if (debug>3)
	    fprintf(stderr,"Calling UDP newconn routine for module \"%s\"\n",
		    modules[i].module_name);

	pmodstruct = (*modules[i].module_udp_newconn)(pup);
	if (pmodstruct) {
	    /* make sure the array is there */
	    if (!pup->pmod_info) {
		pup->pmod_info = MallocZ(state->num_modules * sizeof(void *));
	    }

	    /* remember this structure */
	    pup->pmod_info[i] = pmodstruct;
	}
    }
}

void
tcptrace_modules_readpacket_nottcpudp(
    tcptrace_state_t *state,
    struct ip *pip,
    void *plast)
{
    int i;
    struct module *modules = tcptrace_modules;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!tcptrace_modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (tcptrace_modules[i].module_nontcpudp_read == NULL)
	    continue;  /* they might not care */

	if (debug>3)
	    fprintf(stderr,"Calling nontcp routine for module \"%s\"\n",
		    tcptrace_modules[i].module_name);

	(*tcptrace_modules[i].module_nontcpudp_read)(pip,plast);
    }
}


void
tcptrace_modules_readpacket(
    tcptrace_state_t *state,
    struct ip *pip,
    tcp_pair *ptp,
    void *plast)
{
    int i;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!tcptrace_modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (tcptrace_modules[i].module_read == NULL)
	    continue;  /* they might not care */

	if (debug>3)
	    fprintf(stderr,"Calling read routine for module \"%s\"\n",
		    tcptrace_modules[i].module_name);

	(*tcptrace_modules[i].module_read)(state, pip,ptp,plast,
				  ptp->pmod_info?ptp->pmod_info[i]:NULL);
    }
}


void
tcptrace_modules_readpacket_udp(
    tcptrace_state_t *state,
    struct ip *pip,
    udp_pair *pup,
    void *plast)
{
    int i;

    struct module *modules = tcptrace_modules;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (modules[i].module_udp_read == NULL)
	    continue;  /* they might not care */

	if (debug>3)
	    fprintf(stderr,"Calling read routine for module \"%s\"\n",
		    modules[i].module_name);

	(*modules[i].module_udp_read)(pip,pup,plast,
				      pup->pmod_info?pup->pmod_info[i]:NULL);
    }
}

