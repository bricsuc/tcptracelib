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
#if 0
static char const GCC_UNUSED copyright[] =
    "@(#)Copyright (c) 2004 -- Ohio University.\n";
static char const GCC_UNUSED rcsid[] =
    "@(#)$Header: /usr/local/cvs/tcptrace/tcptrace.c,v 5.59 2004/10/01 21:42:34 mramadas Exp $";
#endif

#include "tcptrace.h"

/* TODO: have to fix file_formats.h, probably make it into a .c file or
 * incorporate it here, or something */
#include "file_formats.h"

#include "file_load.h"

tcptrace_load_status_t 
tcptrace_load_file(
    char *filename, tcptrace_working_file *working_file)
{
    FILE *header;
    pread_f *ppread;
    int ret;
    int fix;
    struct stat str_stat;

    /* TODO: compressed file support seems somewhat unecessary;
       consider removing feature or moving it elsewhere */

    header = CompOpenHeader(filename, working_file);
#ifdef __WIN32
    /* If the file is compressed, exit (Windows version does not support compressed dump files) */
    if (header == (FILE *)-1) {
        return(TCPTRACE_WONT_UNCOMPRESS);  /* was exit(-1); */
    }
#else
    /* open the file header */
    if (header == NULL) {
        return(TCPTRACE_WONT_UNCOMPRESS);  /* was exit(-1); */
    }
#endif /* __WIN32 */
    
    CompCloseHeader(header, working_file);

    working_file->is_stdin = 0;

    /* see how big the file is */
    if (FileIsStdin(filename)) {
	working_file->filesize = 1;
	working_file->is_stdin = 1;
    } else {
	if (stat(filename,&str_stat) != 0) {
	    perror("stat");
	    return(TCPTRACE_CANT_STAT);  /* was exit(1); */
	}
	working_file->filesize = str_stat.st_size;
    }

    /* determine file format */
    ppread = NULL;
    if (tcptrace_debuglevel > 1) {
	printf("NUM_FILE_FORMATS: %u\n", (unsigned)NUM_FILE_FORMATS);
    }
    for (fix=0; fix < NUM_FILE_FORMATS; ++fix) {
	if (tcptrace_debuglevel) {
	    fprintf(stderr,"Checking for file format '%s' (%s)\n",
		    file_formats[fix].format_name,
		    file_formats[fix].format_descr);
        }
	rewind(stdin);
       	ppread = (*file_formats[fix].test_func)(filename);
	if (ppread) {
	    if (tcptrace_debuglevel) {
                fprintf(stderr,"File format is '%s' (%s)\n",
	                file_formats[fix].format_name,
	                file_formats[fix].format_descr);
            }
	    break;
	} else if (tcptrace_debuglevel) {
	    fprintf(stderr,"File format is NOT '%s'\n",
		    file_formats[fix].format_name);
	}
    }

    working_file->reader_function = ppread;

    /* if we haven't found a reader, then we can't continue */
    if (ppread == NULL) {
	int count = 0;

	fprintf(stderr,"Unknown input file format\n");
	tcptrace_show_formats();

	/* check for ASCII, a common problem */
	rewind(stdin);
	while (1) {
	    int ch;
	    if ((ch = getchar()) == EOF) {
                break;
            }
	    if (!isprint(ch)) {
                break;
            }
	    if (++count >= 20) {
		/* first 20 are all ASCII */
		fprintf(stderr,"\
\n\nHmmmm.... this sure looks like an ASCII input file to me.\n\
The first %d characters are all printable ASCII characters. All of the\n\
packet grabbing formats that I understand output BINARY files that I\n\
like to read.  Could it be that you've tried to give me the readable \n\
output instead?  For example, with tcpdump, you need to use:\n\
\t tcpdump -w outfile.dmp ; tcptrace outfile.dmp\n\
rather than:\n\
\t tcpdump > outfile ; tcptrace outfile\n\n\
", count);
		return(TCPTRACE_UNKNOWN_FORMAT);  /* was exit(1); */
	    }
	}
	
	return(TCPTRACE_UNKNOWN_FORMAT);  /* was exit(1); */
    }

#ifndef __WIN32   
    /* open the file for processing */
    if (CompOpenFile(filename, working_file) == NULL) {
	return(TCPTRACE_WONT_UNCOMPRESS);  /* was exit(-1); */
    }
#endif /* __WIN32 */   

    return(TCPTRACE_LOAD_SUCCESS);
}

void
tcptrace_show_formats(void)
{
    int i;
    
    fprintf(stderr,"Supported Input File Formats:\n");
    for (i=0; i < NUM_FILE_FORMATS; ++i)
	fprintf(stderr,"\t%-15s  %s\n",
		file_formats[i].format_name,
		file_formats[i].format_descr);
    fprintf(stderr, 
           "Try the tethereal program from the ethereal project to see if\n"
           "it can understand this capture format. If so, you may use \n"
           "tethereal to convert it to a tcpdump format file as in :\n"
           "\t tethereal -r inputfile -w outputfile\n"
           "and feed the outputfile to tcptrace\n");
}

