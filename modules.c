/* module action interface */

#include "tcptrace.h"
#include "modules.h"

/* inform all modules of a new file */
void
tcptrace_modules_all_newfile(
    tcptrace_context_t *context,
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

	if (tcptrace_debuglevel>3) {
	    fprintf(stderr,"Calling newfile routine for module \"%s\"\n",
		    modules[i].module_name);
        }

	(*modules[i].module_newfile)(filename, working_file->filesize, CompIsCompressed(working_file));
    }
}

void
tcptrace_modules_load(
    tcptrace_context_t *context,
    int argc,
    char *argv[])
{
    int i;
    int enable;
    struct module *modules = tcptrace_modules;

    for (i=0; i < NUM_MODULES; ++i) {
	context->num_modules++;
	if (tcptrace_debuglevel)
	    fprintf(stderr,"Initializing module \"%s\"\n",
		    modules[i].module_name);
	enable = (*modules[i].module_init)(context, argc, argv);
	if (enable) {
	    if (tcptrace_debuglevel)
		fprintf(stderr,"Module \"%s\" enabled\n",
			modules[i].module_name);
	    modules[i].module_inuse = TRUE;
	} else {
	    if (tcptrace_debuglevel)
		fprintf(stderr,"Module \"%s\" not active\n",
			modules[i].module_name);
	    modules[i].module_inuse = FALSE;
	}
    }
}



void
tcptrace_modules_finish(tcptrace_context_t *context)
{
    int i;
    struct module *modules = tcptrace_modules;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (modules[i].module_done == NULL)
	    continue;  /* might not have a cleanup */

	if (tcptrace_debuglevel)
	    fprintf(stderr,"Calling cleanup for module \"%s\"\n",
		    modules[i].module_name);

	(*modules[i].module_done)(context);
    }
}


void
tcptrace_modules_newconn(
    tcptrace_context_t *context,
    tcp_pair *ptp)
{
    int i;
    void *pmodstruct;
    struct module *modules = tcptrace_modules;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (modules[i].module_newconn == NULL)
	    continue;  /* they might not care */

	if (tcptrace_debuglevel>3)
	    fprintf(stderr,"Calling newconn routine for module \"%s\"\n",
		    modules[i].module_name);

	pmodstruct = (*modules[i].module_newconn)(context, ptp);
	if (pmodstruct) {
	    /* make sure the array is there */
	    if (!ptp->pmod_info) {
		ptp->pmod_info = MallocZ(context->num_modules * sizeof(void *));
	    }

	    /* remember this structure */
	    ptp->pmod_info[i] = pmodstruct;
	}
    }
}


void
tcptrace_modules_deleteconn(
                  tcptrace_context_t *context,
		  tcp_pair *ptp)
{
    int i;
    struct module *modules = tcptrace_modules;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (modules[i].module_deleteconn == NULL)
	    continue;  /* they might not care */

	if (tcptrace_debuglevel>3)
	    fprintf(stderr,"Calling delete conn routine for module \"%s\"\n",
		    modules[i].module_name);

	(*modules[i].module_deleteconn)(ptp,
					ptp->pmod_info?ptp->pmod_info[i]:NULL);
    }
}


void
tcptrace_modules_newconn_udp(
    tcptrace_context_t *context,
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

	if (tcptrace_debuglevel>3)
	    fprintf(stderr,"Calling UDP newconn routine for module \"%s\"\n",
		    modules[i].module_name);

	pmodstruct = (*modules[i].module_udp_newconn)(pup);
	if (pmodstruct) {
	    /* make sure the array is there */
	    if (!pup->pmod_info) {
		pup->pmod_info = MallocZ(context->num_modules * sizeof(void *));
	    }

	    /* remember this structure */
	    pup->pmod_info[i] = pmodstruct;
	}
    }
}

void
tcptrace_modules_readpacket_nottcpudp(
    tcptrace_context_t *context,
    struct ip *pip,
    void *plast)
{
    int i;
    struct module *modules = tcptrace_modules;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (modules[i].module_nontcpudp_read == NULL)
	    continue;  /* they might not care */

	if (tcptrace_debuglevel>3)
	    fprintf(stderr,"Calling nontcp routine for module \"%s\"\n",
		    modules[i].module_name);

	(*modules[i].module_nontcpudp_read)(pip,plast);
    }
}


void
tcptrace_modules_readpacket(
    tcptrace_context_t *context,
    struct ip *pip,
    tcp_pair *ptp,
    void *plast)
{
    int i;
    struct module *modules = tcptrace_modules;

    for (i=0; i < NUM_MODULES; ++i) {
	if (!modules[i].module_inuse)
	    continue;  /* might be disabled */

	if (modules[i].module_read == NULL)
	    continue;  /* they might not care */

	if (tcptrace_debuglevel>3)
	    fprintf(stderr,"Calling read routine for module \"%s\"\n",
		    modules[i].module_name);

	(*modules[i].module_read)(context, pip,ptp,plast,
				  ptp->pmod_info?ptp->pmod_info[i]:NULL);
    }
}


void
tcptrace_modules_readpacket_udp(
    tcptrace_context_t *context,
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

	if (tcptrace_debuglevel>3)
	    fprintf(stderr,"Calling read routine for module \"%s\"\n",
		    modules[i].module_name);

	(*modules[i].module_udp_read)(pip,pup,plast,
				      pup->pmod_info?pup->pmod_info[i]:NULL);
    }
}

/* convert a buffer to an argc,argv[] pair */
void
StringToArgv(
    char *buf,
    int *pargc,
    char ***pargv)
{
    char **argv;
    int nargs = 0;

    /* discard the original string, use a copy */
    buf = strdup(buf);

    /* (very pessimistically) make the argv array */
    argv = malloc(sizeof(char *) * ((strlen(buf)/2)+1));

    /* skip leading blanks */
    while ((*buf != '\00') && (isspace((int)*buf))) {
	if (tcptrace_debuglevel > 10)
	    printf("skipping isspace('%c')\n", *buf);	    
	++buf;
    }

    /* break into args */
    for (nargs = 1; *buf != '\00'; ++nargs) {
	char *stringend;
	argv[nargs] = buf;

	/* search for separator */
	while ((*buf != '\00') && (!isspace((int)*buf))) {
	    if (tcptrace_debuglevel > 10)
		printf("'%c' (%d) is NOT a space\n", *buf, (int)*buf);	    
	    ++buf;
	}
	stringend = buf;

	/* skip spaces */
	while ((*buf != '\00') && (isspace((int)*buf))) {
	    if (tcptrace_debuglevel > 10)
		printf("'%c' (%d) IS a space\n", *buf, (int)*buf);	    
	    ++buf;
	}

	*stringend = '\00';  /* terminate the previous string */

	if (tcptrace_debuglevel)
	    printf("  argv[%d] = '%s'\n", nargs, argv[nargs]);
    }

    *pargc = nargs;
    *pargv = argv;
}

