/*_############################################################################
  _## 
  _##  reentrant.cpp  
  _##
  _##  SNMP++ v3.4
  _##  -----------------------------------------------
  _##  Copyright (c) 2001-2021 Jochen Katz, Frank Fock
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
  _##  Hewlett-Packard, Frank Fock, and Jochen Katz make no representations 
  _##  about the suitability of this software for any purpose. It is provided 
  _##  "AS-IS" without warranty of any kind, either express or implied. User 
  _##  hereby grants a royalty-free license to any and all derivatives based
  _##  upon this software code base. 
  _##  
  _##########################################################################*/
char reentrant_cpp_version[]="#(@) SNMP++ $Id$";

#include <libsnmp.h>

#include "snmp_pp/reentrant.h"

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

SnmpSynchronized::SnmpSynchronized()
{
#ifdef _THREADS
#ifdef WIN32
	InitializeCriticalSection(&_mutex);
#elif defined (CPU) && CPU == PPC603
	_mutex = semMCreate(SEM_Q_PRIORITY | SEM_DELETE_SAFE | SEM_INVERSION_SAFE );
#else
	pthread_mutex_init(&_mutex, 0);
#endif
#endif
}

SnmpSynchronized::~SnmpSynchronized()
{
#ifdef _THREADS
#ifdef WIN32
	DeleteCriticalSection(&_mutex);
#elif defined (CPU) && CPU == PPC603
	semTake(_mutex, WAIT_FOREVER);
	semDelete(_mutex);
#else
	pthread_mutex_destroy(&_mutex);
#endif
#endif
}

void SnmpSynchronized::lock()
{
#ifdef _THREADS
#ifdef WIN32
	EnterCriticalSection(&_mutex);
#elif defined (CPU) && CPU == PPC603
    semTake(_mutex, WAIT_FOREVER);
#else
	pthread_mutex_lock(&_mutex);
#endif
#endif
}	

void SnmpSynchronized::unlock()
{
#ifdef _THREADS
#ifdef WIN32
	LeaveCriticalSection(&_mutex);
#elif defined (CPU) && CPU == PPC603
    semGive(_mutex);
#else
	pthread_mutex_unlock(&_mutex);
#endif
#endif
}	

#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif 

