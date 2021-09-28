/*_############################################################################
  _## 
  _##  usertimeout.h  
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
/*===================================================================

  Copyright (c) 1999
  Hewlett-Packard Company

  ATTENTION: USE OF THIS SOFTWARE IS SUBJECT TO THE FOLLOWING TERMS.
  Permission to use, copy, modify, distribute and/or sell this software
  and/or its documentation is hereby granted without fee. User agrees
  to display the above copyright notice and this license notice in all
  copies of the software and any documentation of the software. User
  agrees to assume all liability for the use of the software; Hewlett-Packard
  makes no representations about the suitability of this software for any
  purpose. It is provided "AS-IS without warranty of any kind,either express
  or implied. User hereby grants a royalty-free license to any and all
  derivatives based upon this software code base.

      U S E R T I M E O U T . H

      CUTEventQueue CLASS DEFINITION

      COPYRIGHT HEWLETT PACKARD COMPANY 1999

      INFORMATION NETWORKS DIVISION

      NETWORK MANAGEMENT SECTION


      DESIGN + AUTHOR:        Tom Murray

      LANGUAGE:        ANSI C++

      DESCRIPTION:
        Queue for holding callback associated with user defined
        timeouts

=====================================================================*/

#ifndef _SNMP_USERTIMEOUT_H_
#define _SNMP_USERTIMEOUT_H_

//----[ includes ]-----------------------------------------------------
#ifndef WIN32
#include <sys/types.h>
#if !(defined CPU && CPU == PPC603)
#include <sys/time.h>           // time stuff and fd_set
#endif
#endif

//----[ snmp++ includes ]----------------------------------------------
#include "snmp_pp/msec.h"
#include "snmp_pp/eventlist.h"

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

//----[ defines ]------------------------------------------------------

typedef unsigned long   UtId;

/* User-defined callback */
typedef void (*ut_callback)(void * callData, UtId id);

class EventListHolder;

//----[ CUTEvent class ]-------------------------------------------


/*-----------------------------------------------------------*/
/* CUTEvent                                                  */
/*   a description of a single MIB access operation.         */
/*-----------------------------------------------------------*/
class DLLOPT CUTEvent
{
 public:
  CUTEvent(const UtId uniqueId, const msec &timeout,
           const ut_callback callBack, const void * callData);
  ~CUTEvent() {};
  UtId GetId() { return m_uniqueId ; };
  void GetTimeout(msec &timeout) { timeout = m_timeout; };

  int Callback();

 protected:
  UtId            m_uniqueId;
  msec            m_timeout;
  ut_callback     m_callBack;
  void *          m_callData;
};


/*-----------------------------------------------------------*/
/* CUTEventQueue                                             */
/*   class describing a collection of outstanding SNMP msgs. */
/*-----------------------------------------------------------*/
class DLLOPT CUTEventQueue: public CEvents
{
 public:
  CUTEventQueue(EventListHolder *holder)
    : m_head(0, 0, 0), m_msgCount(0), m_id(1), my_holder(holder) {};
  ~CUTEventQueue();
    UtId AddEntry(const msec &timeout,
		  const ut_callback callBack,
		  const void * callData);
    CUTEvent *GetEntry(const UtId uniqueId);
    void DeleteEntry(const UtId uniqueId);

    UtId MakeId();

    // find the next msg that will timeout
    CUTEvent *GetNextTimeoutEntry();

    // find the next timeout
    int GetNextTimeout(msec &timeout);

    // set up parameters for select
    void GetFdSets(int &/*maxfds*/, fd_set &/*readfds*/, fd_set &/*writefds*/,
		   fd_set &/*exceptfds*/) {} // we never have any event sources

    // return number of outstanding messages
    int GetCount() { return m_msgCount; };

    int HandleEvents(const int /*maxfds*/,
                     const fd_set &/*readfds*/,
                     const fd_set &/*writefds*/,
                     const fd_set &/*exceptfds*/)
      { msec now; return DoRetries(now); };

    int DoRetries(const msec &sendtime);

    int Done() { return 0; }; // we are never done

  protected:

    /*-----------------------------------------------------------*/
    /* CUTEventQueueElt                                          */
    /*   a container for a single item on a linked lists of      */
    /*  CUTEvents.                                               */
    /*-----------------------------------------------------------*/
    class DLLOPT CUTEventQueueElt
    {
     public:
      CUTEventQueueElt(CUTEvent *utevent,
		       CUTEventQueueElt *next,
		       CUTEventQueueElt *previous);

      ~CUTEventQueueElt();
      CUTEventQueueElt *GetNext() { return m_Next; };
      CUTEvent *GetUTEvent() { return m_utevent; };
      CUTEvent *TestId(const UtId uniqueId);

     private:
      CUTEvent *m_utevent;
      class CUTEventQueueElt *m_Next;
      class CUTEventQueueElt *m_previous;
    };

    CUTEventQueueElt m_head;
    int              m_msgCount;
    UtId             m_id;
    EventListHolder *my_holder;
};

#ifdef SNMP_PP_NAMESPACE
}; // end of namespace Snmp_pp
#endif 

#endif // _SNMP_USERTIMEOUT_H_
