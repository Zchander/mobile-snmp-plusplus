  ############################################################################
  ## 
  ##  Makefile.am  
  ##
  ##  SNMP++ v3.3
  ##  -----------------------------------------------
  ##  Copyright (c) 2001-2013 Jochen Katz, Frank Fock
  ##
  ##  This software is based on SNMP++2.6 from Hewlett Packard:
  ##  
  ##    Copyright (c) 1996
  ##    Hewlett-Packard Company
  ##  
  ##  ATTENTION: USE OF THIS SOFTWARE IS SUBJECT TO THE FOLLOWING TERMS.
  ##  Permission to use, copy, modify, distribute andor sell this software 
  ##  andor its documentation is hereby granted without fee. User agrees 
  ##  to display the above copyright notice and this license notice in all 
  ##  copies of the software and any documentation of the software. User 
  ##  agrees to assume all liability for the use of the software; 
  ##  Hewlett-Packard and Jochen Katz make no representations about the 
  ##  suitability of this software for any purpose. It is provided 
  ##  "AS-IS" without warranty of any kind, either express or implied. User 
  ##  hereby grants a royalty-free license to any and all derivatives based
  ##  upon this software code base. 
  ##  
  ##########################################################################*
AM_CPPFLAGS = -I$(abs_top_srcdir)/include $(PTHREAD_CFLAGS) @CLIBFLAGS@

lib_LTLIBRARIES = libsnmp++.la

libsnmp___la_SOURCES =  address.cpp asn1.cpp auth_priv.cpp counter.cpp \
                        ctr64.cpp eventlist.cpp eventlistholder.cpp \
                        gauge.cpp idea.cpp integer.cpp IPv6Utility.cpp \
                        log.cpp md5c.cpp mp_v3.cpp msec.cpp msgqueue.cpp \
                        notifyqueue.cpp octet.cpp oid.cpp pdu.cpp \
                        reentrant.cpp sha.cpp snmpmsg.cpp target.cpp \
                        timetick.cpp userdefined.cpp usertimeout.cpp \
                        usm_v3.cpp uxsnmp.cpp v3.cpp vb.cpp

libsnmp___la_LDFLAGS =	-version-info @SNMP_PP_MAJOR_VERSION@@SNMP_PP_MINOR_VERSION@:@SNMP_PP_MICRO_VERSION@:0 @LINKFLAGS@

EXTRA_DIST = Makefile.aix5 Makefile.bcc Makefile.dunix Makefile.gcc_solaris Makefile.hpux11 Makefile.linux Makefile.solaris common.mk
