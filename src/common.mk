  ############################################################################
  ## 
  ##  common.mk  
  ##
  ##  SNMP++ v3.4
  ##  -----------------------------------------------
  ##  Copyright (c) 2001-2021 Jochen Katz, Frank Fock
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
  ##  Hewlett-Packard, Frank Fock, and Jochen Katz make no representations 
  ##  about the suitability of this software for any purpose. It is provided 
  ##  "AS-IS" without warranty of any kind, either express or implied. User 
  ##  hereby grants a royalty-free license to any and all derivatives based
  ##  upon this software code base. 
  ##  
  ##########################################################################*

# Versions for shared library
SOVERSION	= 3.3.0
SOVERSION_MAIN	= 3

LIBDESDIR	= ../../libdes
LIBTOMCRYPTDIR	= ../../crypt

PP_INC		= ../include

CINCDIRS	= -I$(PP_INC) -I$(PP_INC)/system -I./ -I$(LIBDESDIR) -I$(LIBTOMCRYPTDIR)/src/headers

# snmp++ lib headers
HEADERS		= $(wildcard $(PP_INC)/snmp_pp/*.h) $(PP_INC)/system/libsnmp.h

# snmp++ lib sources
PP_SRCS		= $(wildcard *.cpp)

#
#  Object Files produced
#
OBJS		= $(PP_SRCS:.cpp=.o)
OBJS_SHARED	= $(PP_SRCS:.cpp=_sh.o)

#
#  Libraries:  dependencies and produced
#
LIBPATH = ../lib
LIBSNMPPLUS_SHARED_SHORT = libsnmp++.so
LIBSNMPPLUS_SHARED = $(LIBPATH)/$(LIBSNMPPLUS_SHARED_SHORT).$(SOVERSION)
LIBSNMPPLUS_SHARED_MAIN = $(LIBPATH)/$(LIBSNMPPLUS_SHARED_SHORT).$(SOVERSION_MAIN)
LIBSNMPPLUS_SHARED_NOVERSION = $(LIBPATH)/$(LIBSNMPPLUS_SHARED_SHORT)

LIBSNMPPLUS = $(LIBPATH)/libsnmp++.a

#
# Installation directories
#
ifndef INSTPREFIX
INSTPREFIX	= /usr/local
endif

ifndef INSTLIBPATH
INSTLIBPATH	= $(INSTPREFIX)/lib
endif

ifndef INSTINCPATH
INSTINCPATH	= $(INSTPREFIX)/include
endif

#
#  Here for a quick sanity check upon completing a build...
#

.SUFFIXES: .cpp .C

%.o:	%.cpp
	$(CC) $(CFLAGS) -o $@ -c $<

%_sh.o:	%.cpp
	$(CC) $(SHARED) $(CFLAGS) -o $@ -c $<

#
#  Build rules
#
all: lib shlib

lib: $(LIBPATH) $(LIBSNMPPLUS)

shlib: $(LIBPATH) $(LIBSNMPPLUS_SHARED)

$(LIBPATH):
	mkdir $(LIBPATH)

$(LIBSNMPPLUS): $(OBJS)
	ar -rv $(LIBSNMPPLUS) $(OBJS)	

$(LIBSNMPPLUS_SHARED): $(OBJS_SHARED)
	$(CC) $(SHARED) $(LDFLAGS) $(OBJS_SHARED) -o $@ 
	rm -f $(LIBSNMPPLUS_SHARED_MAIN) $(LIBSNMPPLUS_SHARED_NOVERSION)
	ln -s $(LIBSNMPPLUS_SHARED) $(LIBSNMPPLUS_SHARED_NOVERSION)
	ln -s $(LIBSNMPPLUS_SHARED)  $(LIBSNMPPLUS_SHARED_MAIN)

clean:
	-rm -f core core.* *.o *.rpo *~ a.out ../include/snmp_pp/*~

clobber: clean
	-rm -f $(LIBSNMPPLUS) $(LIBSNMPPLUS_SHARED)
	-rm -f $(LIBSNMPPLUS_SHARED_MAIN) $(LIBSNMPPLUS_SHARED_NOVERSION)

install-common:
	install -d $(DESTDIR)$(INSTLIBPATH)
	install -d $(DESTDIR)$(INSTINCPATH)/snmp_pp/
	install $(HEADERS) $(DESTDIR)$(INSTINCPATH)/snmp_pp/

install-static: lib install-common
	install $(LIBSNMPPLUS) $(DESTDIR)$(INSTLIBPATH)

install-shared: shlib install-common
	install $(LIBSNMPPLUS_SHARED) $(DESTDIR)$(INSTLIBPATH)

install: install-static install-shared

#
#  Dependency rules
#
$(OBJS): $(HEADERS)

#dependencies:	$(PP_SRCS) $(HEADERS)
#	$(CC) -MM $(PP_SRCS) $(CINCDIRS)      > dependencies
#
#ifneq ($(wildcard dependencies),)
#include dependencies
#endif
