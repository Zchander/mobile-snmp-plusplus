/*_############################################################################
  _## 
  _##  config_snmp_pp.h  
  _##
  _##  SNMP++v3.2.25
  _##  -----------------------------------------------
  _##  Copyright (c) 2001-2010 Jochen Katz, Frank Fock
  _##
  _##  This software is based on SNMP++2.6 from Hewlett Packard:
  _##  
  _##    Copyright (c) 1996
  _##    Hewlett-Packard Company
  _##  
  _##  ATTENTION: USE OF THIS SOFTWARE IS SUBJECT TO THE FOLLOWING TERMS.
  _##  Permission to use, copy, modify, distribute and/or sell this software 
  _##  and/or its documentation is hereby granted without fee. User agrees 
  _##  to display the above copyright notice and this license notice in all 
  _##  copies of the software and any documentation of the software. User 
  _##  agrees to assume all liability for the use of the software; 
  _##  Hewlett-Packard and Jochen Katz make no representations about the 
  _##  suitability of this software for any purpose. It is provided 
  _##  "AS-IS" without warranty of any kind, either express or implied. User 
  _##  hereby grants a royalty-free license to any and all derivatives based
  _##  upon this software code base. 
  _##  
  _##  Stuttgart, Germany, Thu Sep  2 00:07:47 CEST 2010 
  _##  
  _##########################################################################*/

// $Id: config_snmp_pp.h 1823 2010-08-25 21:59:53Z fock $

#ifndef _CONFIG_SNMP_PP_H_
#define _CONFIG_SNMP_PP_H_

#define SNMP_PP_VERSION_STRING "3.2.25"
#define SNMP_PP_VERSION 3
#define SNMP_PP_RELEASE 2
#define SNMP_PP_PATCHLEVEL 25

//! The maximum size of a message that can be sent or received.
#define MAX_SNMP_PACKET 4096

#ifndef DLLOPT
#if defined (WIN32) && defined (SNMP_PP_DLL)
#ifdef SNMP_PP_EXPORTS
#define DLLOPT __declspec(dllexport)
#define DLLOPT_TEMPL
#else
#define DLLOPT __declspec(dllimport)	
#define DLLOPT_TEMPL extern
#endif
#else
#define DLLOPT
#define DLLOPT_TEMPL
#endif
#endif

// define SNMP_PP_IPv6 if you want to use IPv6
// #define SNMP_PP_IPv6

// define SNMP_PP_NAMESPACE to enclose all library names in Snmp_pp namespace
// XIS
#define SNMP_PP_NAMESPACE

// define _NO_SNMPv3 here or in the Makefile if you do not want to use SNMPv3
// (default is to use SNMPv3)
// XIS
#define _NO_SNMPv3

// If you have not disabled SNMPv3, snmp++ will use libdes
// (separate package) as default.
// define _USE_LIBTOMCRYPT if you want to use libtomcrypt instead
// Note that _USE_OPENSSL will override libtomcrypt for SHA1, MD5, DES and AES.
// #define _USE_LIBTOMCRYPT

// If you define _USE_OPENSSL, snmp++ will use OpenSSL for SHA1,
// MD5, DES and AES. Please note that you will have to change the Makefiles
// of the examples: Add -lssl to the link command
// #define _USE_OPENSSL

// If you do not use SNMP++ for commercial purposes or if you
// have licensed IDEA (read README.v3) you may define the following
// to enable IDEA support. (note this is not defined by a rfc)
// #define _USE_IDEA

// Enable 3DES Privacy (note this is not defined by a rfc)
// #define _USE_3DES_EDE

// define _NO_THREADS here or in the Makefile if you do not want thread support
// (default is to include thread support)
// XIS
//#define _NO_THREADS

// define _NO_LOGGING if you do not want any logging output 
// (increases performance drastically and minimizes memory consumption)
//#define _NO_LOGGING

// define _IPX_ADDRESS and/or _MAC_ADDRESS if you want to use the
// classess IpxAddress/IpxSockAddress and/or MacAddress
// #define _IPX_ADDRESS
// #define _MAC_ADDRESS

// define this if you want to send out broadcasts
#define SNMP_BROADCAST


// Not fully tested!
//#define HAVE_POLL_SYSCALL

// Some older(?) compilers need a special declaration of
// template classes
// #define _OLD_TEMPLATE_COLLECTION

// We have inet_aton() function if not compiling with VC++ or Borland C++
#ifndef _MSC_VER
#ifndef __BCPLUSPLUS__
#define HAVE_INET_ATON
#endif
#endif

// If IPv6 is enabled assume that inet_pton() is available
// If IPv6 and gcc then assume gethostbyname2() is available
#ifdef SNMP_PP_IPv6
#define HAVE_INET_PTON
#ifdef __GNUC__
#define HAVE_GETHOSTBYNAME2
#endif
#endif

// can we use the reentrant version of these functions or
// are the standard functions thread safe
#ifdef __CYGWIN32__
#define HAVE_LOCALTIME_R
#define HAVE_REENTRANT_LOCALTIME
#define HAVE_REENTRANT_GETHOSTBYADDR
#define HAVE_REENTRANT_GETHOSTBYNAME
#undef  HAVE_GETHOSTBYNAME2
#elif __MINGW32__
//FIXME: snmp++/src/address.cpp:865: error: `inet_ntop' was not declared in this scope
//FIXME: snmp++/src/address.cpp:988: error: `inet_pton' was not declared in this scope
//FIXME: snmp++/src/notifyqueue.cpp:538: error: `inet_pton' was not declared in this scope
#undef  HAVE_INET_ATON
#undef  HAVE_GETHOSTBYNAME2
#define HAVE_REENTRANT_GETHOSTBYNAME
#define HAVE_REENTRANT_LOCALTIME
#define HAVE_REENTRANT_GETHOSTBYADDR
#elif __APPLE__
#define HAVE_LOCALTIME_R
#define HAVE_REENTRANT_LOCALTIME
#elif __GNUC__
#define HAVE_GETHOSTBYNAME_R
#define HAVE_LOCALTIME_R
#define HAVE_GETHOSTBYADDR_R
#elif __DECCXX
#define HAVE_REENTRANT_GETHOSTBYNAME
#define HAVE_LOCALTIME_R
#define HAVE_REENTRANT_GETHOSTBYADDR
#elif __sun
#define HAVE_GETHOSTBYNAME_R
#define HAVE_LOCALTIME_R
#define HAVE_GETHOSTBYADDR_R
#elif __HP_aCC
#define HAVE_REENTRANT_GETHOSTBYNAME
#define HAVE_LOCALTIME_R
#define HAVE_REENTRANT_GETHOSTBYADDR
#elif _MSC_VER
#define HAVE_REENTRANT_GETHOSTBYNAME
#define HAVE_REENTRANT_LOCALTIME
#define HAVE_REENTRANT_GETHOSTBYADDR
#elif _AIX
#define HAVE_REENTRANT_GETHOSTBYNAME
#define HAVE_LOCALTIME_R
#define HAVE_REENTRANT_GETHOSTBYADDR
#endif

// Define a unsigned 64 bit integer:
#ifdef WIN32
#ifdef SNMP_PP_IPv6
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <windows.h>
#include <winsock.h>
#endif
#ifdef __BCPLUSPLUS__
typedef unsigned __int64 pp_uint64;
#else
typedef ULONGLONG pp_uint64;
#endif
#else // not WIN32
typedef unsigned long long pp_uint64;
#endif

// Define a type used for sockets
#ifdef _MSC_VER
    typedef SOCKET SnmpSocket;
#else
    typedef int SnmpSocket;
#endif

#ifdef HAVE_POLL_SYSCALL
#include <poll.h>
#endif

///////////////////////////////////////////////////////////////////////
// Changes below this line should not be necessary
///////////////////////////////////////////////////////////////////////


// Make use of mutable keyword
//#define SNMP_PP_MUTABLE mutable
#define SNMP_PP_MUTABLE

#define SAFE_INT_CAST(expr)  ((int)(expr))
#define SAFE_UINT_CAST(expr) ((unsigned int)(expr))

// Safe until 32 bit second counter wraps to zero (time functions)
#define SAFE_LONG_CAST(expr)  ((long)(expr))
#define SAFE_ULONG_CAST(expr) ((unsigned long)(expr))

#ifndef _NO_THREADS

#ifndef HAVE_REENTRANT_LOCALTIME
#ifndef HAVE_LOCALTIME_R
// If you see this warning, and your system has a reentrant localtime
// or localtime_r function report your compiler, OS,... to the authors
// of this library, so that these settings can be changed
#warning Threads_defined_but_no_reentrant_LOCALTIME_function
#endif
#endif

#ifndef HAVE_GETHOSTBYADDR_R
#ifndef HAVE_REENTRANT_GETHOSTBYADDR
// If you see this warning, and your system has a reentrant localtime
// or localtime_r function report your compiler, OS,... to the authors
// of this library, so that these settings can be changed
#warning Threads_defined_but_no_reentrant_GETHOSTBYADDR_function
#endif
#endif

#ifndef HAVE_GETHOSTBYNAME_R
#ifndef HAVE_REENTRANT_GETHOSTBYNAME
// If you see this warning, and your system has a reentrant localtime
// or localtime_r function report your compiler, OS,... to the authors
// of this library, so that these settings can be changed
#warning Threads_defined_but_no_reentrant_GETHOSTBYNAME_function
#endif
#endif

#endif // _NO_THREADS


#ifndef _NO_SNMPv3
#ifndef _SNMPv3
#define _SNMPv3
#endif
#endif

#ifndef _NO_THREADS
#ifdef WIN32

#ifndef _THREADS
#define _WIN32THREADS
#define VC_EXTRALEAN
#define _THREADS
#endif

#else  // !WIN32

#ifndef _THREADS
#define _THREADS
#endif

#ifdef __APPLE__
#define __unix
#endif

#ifndef POSIX_THREADS
#ifdef __unix
#define POSIX_THREADS
#endif
#endif

#endif // WIN32
#endif // !_NO_THREADS

#endif // _CONFIG_SNMP_PP_H_
