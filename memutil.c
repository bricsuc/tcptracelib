
#include "tcptrace.h"

/* memory allocation routines */

void *
MallocZ(
  int nbytes)
{
	char *ptr;

	ptr = malloc(nbytes);
	if (ptr == NULL) {
		perror("Malloc failed, fatal\n");
		fprintf(stderr,"\
when memory allocation fails, it's either because:\n\
1) You're out of swap space, talk to your local sysadmin about making more\n\
   (look for system commands 'swap' or 'swapon' for quick fixes)\n\
2) The amount of memory that your OS gives each process is too little\n\
   That's a system configuration issue that you'll need to discuss\n\
   with the system administrator\n\
");
		exit(2);
	}

	memset(ptr,'\00',nbytes);  /* BZERO */

	return(ptr);
}

void *
ReallocZ(
    void *oldptr,
    int obytes,
    int nbytes)
{
	char *ptr;

	ptr = realloc(oldptr,nbytes);
	if (ptr == NULL) {
		fprintf(stderr,
			"Realloc failed (%d bytes --> %d bytes), fatal\n",
			obytes, nbytes);
		perror("realloc");
		exit(2);
	}
	if (obytes < nbytes) {
	    memset((char *)ptr+obytes,'\00',nbytes-obytes);  /* BZERO */
	}

	return(ptr);
}

/* the memcpy() function that gcc likes to stuff into the program has alignment
   problems, so here's MY version.  It's only used for small stuff, so the
   copy should be "cheap", but we can't be too fancy due to alignment boo boos */
void *
MemCpy(void *vp1, void *vp2, size_t n)
{
    char *p1 = vp1;
    char *p2 = vp2;

    while (n-->0)
	*p1++=*p2++;

    return(vp1);
}

