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

#include "tcptrace.h"
#include "modules.h"

/* declare (install) the various module routines */
struct module tcptrace_modules[] = {
#ifdef LOAD_MODULE_HTTP
    /* this example is for the HTTP module */
    {TRUE,			/* make FALSE if you don't want to call it at all */
     "http",			/* name of the module */
     "Http analysis package",	/* description of the module */
     http_init,			/* routine to call to init the module */
     http_read,			/* routine to pass each TCP segment */
     http_done,			/* routine to call at program end */
     http_usage,		/* routine to call to print module usage */
     http_newfile,		/* routine to call on each new file */
     http_newconn,		/* routine to call on each new connection */
     NULL, NULL, NULL, NULL},	/* not interested in non-tcp */
#endif /* LOAD_MODULE_HTTP */

    /* list other modules here ... */
#ifdef LOAD_MODULE_TCPLIB
    /* this example is for the TCPLIB module */
    {TRUE,			/* make FALSE if you don't want to call it at all */
     "tcplib",			/* name of the module */
     "TCPLib analysis package",	/* description of the module */
     tcplib_init,		/* routine to call to init the module */
     tcplib_read,		/* routine to pass each TCP segment */
     tcplib_done,		/* routine to call at program end */
     tcplib_usage,		/* routine to call to print module usage */
     tcplib_newfile,		/* routine to call on each new file */
     tcplib_newconn,		/* routine to call on each new connection */
     NULL, NULL, NULL, NULL},	/* not interested in non-tcp */
#endif /* LOAD_MODULE_TCPLIB */


#ifdef LOAD_MODULE_TRAFFIC
    /* ttl traffic analysis */
    {TRUE,			/* make FALSE if you don't want to call it at all */
     "traffic", "traffic analysis package",
     traffic_init, traffic_read, traffic_done,		
     traffic_usage, NULL, traffic_newconn, NULL, NULL, NULL, NULL},
#endif /* LOAD_MODULE_TRAFFIC */

#ifdef LOAD_MODULE_SLICE
    /* ttl slice analysis */
    {TRUE,			/* make FALSE if you don't want to call it at all */
     "slice", "traffic efficiency data by time slices",
     slice_init, slice_read, slice_done,		
     slice_usage, NULL, slice_newconn, NULL, NULL, NULL, NULL},
#endif /* LOAD_MODULE_SLICE */

#ifdef LOAD_MODULE_RTTGRAPH
    {TRUE,			/* make FALSE if you don't want to call it at all */
     "rttgraph", "round trip time analysis graphs",
     rttgraph_init,		/* routine to call to init the module */
     rttgraph_read,		/* routine to pass each TCP segment */
     rttgraph_done,		/* routine to call at program end */
     rttgraph_usage,		/* routine to call to print module usage */
     NULL,			/* routine to call on each new file */
     rttgraph_newconn,		/* routine to call on each new connection */
     NULL, NULL, NULL, NULL},	/* not interested in non-tcp */
#endif /* LOAD_MODULE_TRAFFIC */

#ifdef LOAD_MODULE_COLLIE
    /* ttl collie analysis */
    {TRUE,			/* make FALSE if you don't want to call it at all */
     "collie", "connection summary package",
     collie_init, NULL /* read */, collie_done,		
     collie_usage, collie_newfile, collie_newconn,
     NULL, collie_newudpconn, NULL, NULL},
#endif /* LOAD_MODULE_COLLIE */

#ifdef LOAD_MODULE_REALTIME
    {TRUE,		         /* make FALSE if you don't want to call it at all */
     "realtime",                 /* name of the module */
     "example real-time package",/* description of the module */
     realtime_init,		 /* routine to call to init the module */
     realtime_read,		 /* routine to pass each TCP segment */
     realtime_done,		 /* routine to call at program end */
     realtime_usage,		 /* routine to call to print module usage */
     NULL,			 /* routine to call on each new file */
     realtime_newconn,		 /* routine to call on each new connection */
     realtime_udp_read,          /* routine to pass each UDP segment */
     NULL,              	 /* routine to call on each new UDP conn */
     realtime_nontcpudp_read, 	 /* routine to pass each non-tcp and non-udp 
				    packets*/
     realtime_deleteconn},
#endif /* LOAD_MODULE_REALTIME */
  
#ifdef LOAD_MODULE_INBOUNDS
    {TRUE,		         /* make FALSE if you don't want to call it at all */
     "inbounds",                 /* name of the module */
     "INBOUNDS analysis package",/* description of the module */
     inbounds_init,		 /* routine to call to init the module */
     inbounds_tcp_read,		 /* routine to pass each TCP segment */
     inbounds_done,		 /* routine to call at program end */
     inbounds_usage,		 /* routine to call to print module usage */
     NULL,			 /* routine to call on each new file */
     inbounds_tcp_newconn,		 /* routine to call on each new connection */
     inbounds_udp_read,          /* routine to pass each UDP segment */
     inbounds_udp_newconn,       /* routine to call on each new UDP conn */
     inbounds_nontcpudp_read, 	 /* routine to pass each non-tcp and non-udp 
				    packets*/
     inbounds_tcp_deleteconn},        /* routine to remove TCP connections */
#endif /* LOAD_MODULE_INBOUNDS */
  
};

int tcptrace_num_modules() {
    return(sizeof(tcptrace_modules) / sizeof(struct module));
}

#define NUM_MODULES tcptrace_num_modules()

