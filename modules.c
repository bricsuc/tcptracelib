
#include "tcptrace.h"
/* #include "modules.h" */

/* in order for this to be moved into this file, the vars in modules.h
 * need to move here */

#if 0
void
tcptrace_modules_all_newfile(
    /* TODO: these arguments are sort of redundant, possibly streamline
     * into "state" */
    tcptrace_state_t *state,
    tcptrace_working_file *working_file,
    char *filename)
{
    int i;

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
#endif

