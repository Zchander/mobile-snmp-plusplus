/*_############################################################################
  _## 
  _##  userdefined.h  
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

      U S E R D E F I N E D . H

      CUDEventQueue CLASS DEFINITION

      COPYRIGHT HEWLETT PACKARD COMPANY 1999

      INFORMATION NETWORKS DIVISION

      NETWORK MANAGEMENT SECTION


      DESIGN + AUTHOR:        Tom Murray

      LANGUAGE:        ANSI C++

      DESCRIPTION:
        Queue for holding callback associated with user defined
        input sources

=====================================================================*/

#ifndef _SNMP_USERDEFINED_H_
#define _SNMP_USERDEFINED_H_

//----[ includes ]-----------------------------------------------------
#ifdef WIN32
#include <winsock.h>
#else
#include <sys/types.h>
#if !(defined CPU && CPU == PPC603)
#include <sys/time.h>           // time stuff and fd_set
#endif
#endif

//----[ snmp++ includes ]----------------------------------------------
#include "snmp_pp/eventlist.h"
#include "snmp_pp/snmperrs.h"

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

class msec;
class EventListHolder;

//----[ defines ]------------------------------------------------------

// Modeled after XtInputMask
typedef unsigned long   UdInputMask;
#define UdInputNoneMask         0L
#define UdInputReadMask         (1L<<0)
#define UdInputWriteMask        (1L<<1)
#define UdInputExceptMask       (1L<<2)

typedef unsigned long   UdId;

/* User-defined callback*/
typedef void (*ud_callback)(void * callData, int source, UdId id);


//----[ CUDEvent class ]-----------------------------------------------


class DLLOPT CUDEvent
{
 public:
  CUDEvent (const UdId uniqueId, const int fd,
	    const UdInputMask mask, const ud_callback callBack,
	    const void * callData);
  ~CUDEvent() {};
  UdId          GetId()   const { return m_uniqueId; };
  int           GetFd()   const { return m_fd; };
  UdInputMask   GetMask() const { return m_mask; };

  int Callback();

 protected:
  UdId            m_uniqueId;
  int             m_fd;
  UdInputMask     m_mask;
  ud_callback     m_callBack;
  void *          m_callData;
};

  /*-----------------------------------------------------------*/
  /* CUDEventQueue                                             */
  /*   class describing a collection of outstanding SNMP msgs. */
  /*-----------------------------------------------------------*/
class DLLOPT CUDEventQueue : public CEvents
{
 public:
    CUDEventQueue(EventListHolder *holder)
      : m_head(0, 0, 0), m_msgCount(0), m_id(1), my_holder(holder) {};
    ~CUDEventQueue();
    UdId AddEntry(const int fd, const UdInputMask mask,
                  const ud_callback callBack, const void * callData);
    CUDEvent *GetEntry(const UdId uniqueId);
    void DeleteEntry(const UdId uniqueId);

    UdId MakeId();

    // find the next timeout
    int GetNextTimeout(msec &/*sendTime*/)
      { return SNMP_CLASS_INVALID_OPERATION; }; // We never have a timeout

    // set up parameters for select
    void GetFdSets(int &maxfds, fd_set &readfds, fd_set &writefds,
                   fd_set &exceptfds);
    // return number of user-defined event handlers
    int GetCount() { return m_msgCount; };

    int HandleEvents(const int maxfds, const fd_set &readfds,
                     const fd_set &writefds, const fd_set &exceptfds);

    int DoRetries(const msec &/*sendtime*/)
      { return SNMP_CLASS_SUCCESS; }; // no timeouts, so just return;

    int Done() { return 0; }; // we are never done

  protected:

    /*-----------------------------------------------------------*/
    /* CUDEventQueueElt                                          */
    /*   a container for a single item on a linked lists of      */
    /*  CUDEvents.                                               */
    /*-----------------------------------------------------------*/
    class DLLOPT CUDEventQueueElt
    {
     public:
      CUDEventQueueElt(CUDEvent *udevent,
		       CUDEventQueueElt *next,
		       CUDEventQueueElt *previous);

      ~CUDEventQueueElt();
      CUDEventQueueElt *GetNext() { return m_Next; }
      CUDEvent *GetUDEvent() { return m_udevent ; }
      CUDEvent *TestId(const UdId uniqueId);

     private:

      CUDEvent *m_udevent;
      class CUDEventQueueElt *m_Next;
      class CUDEventQueueElt *m_previous;
    };

    CUDEventQueueElt m_head;
    int              m_msgCount;
    UdId             m_id;
    EventListHolder *my_holder;
};

#ifdef SNMP_PP_NAMESPACE
}; // end of namespace Snmp_pp
#endif 

#endif // _SNMP_USERDEFINED_H_
