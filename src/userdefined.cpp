/*_############################################################################
  _## 
  _##  userdefined.cpp  
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
  purpose. It is provided "AS-IS" without warranty of any kind,either express
  or implied. User hereby grants a royalty-free license to any and all
  derivatives based upon this software code base.

      U S E R D E F I N E D . C P P

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

//----[ snmp++ includes ]----------------------------------------------

#include "snmp_pp/userdefined.h"	// queue for holding user-defined events
#include "snmp_pp/reentrant.h"
#include "snmp_pp/eventlistholder.h"

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

//----[ CUDEvent class ]------------------------------------------------

CUDEvent::CUDEvent(const UdId uniqueId, const int fd,
                   const UdInputMask mask, const ud_callback callBack,
                   const void * callData) :
  m_uniqueId(uniqueId), m_fd(fd), m_mask(mask),
  m_callBack(callBack), m_callData((void *)callData)
{
}

int CUDEvent::Callback()
{
  if (m_callBack)
  {
    m_callBack(m_callData, m_fd, m_uniqueId);
    return 0;
  }
  return 1;
}


//----[ CUDEventQueueElt class ]--------------------------------------

CUDEventQueue::CUDEventQueueElt::CUDEventQueueElt(CUDEvent *udevent,
						  CUDEventQueueElt *next,
						  CUDEventQueueElt *previous)
  : m_udevent(udevent), m_Next(next), m_previous(previous)
{
  /*------------------------------------------*/
  /* Finish insertion into doubly linked list */
  /*------------------------------------------*/
  if (m_Next)     m_Next->m_previous = this;
  if (m_previous) m_previous->m_Next = this;
}

CUDEventQueue::CUDEventQueueElt::~CUDEventQueueElt()
{
  /*-------------------------------------*/
  /* Do deletion form doubly linked list */
  /*-------------------------------------*/
  if (m_Next)     m_Next->m_previous = m_previous;
  if (m_previous) m_previous->m_Next = m_Next;
  if (m_udevent)  delete m_udevent;
}

CUDEvent *CUDEventQueue::CUDEventQueueElt::TestId(const UdId uniqueId)
{
  if (m_udevent && (m_udevent->GetId() == uniqueId))
    return m_udevent;
  return 0;
}

//----[ CUDEventQueue class ]--------------------------------------

CUDEventQueue::~CUDEventQueue()
{
  CUDEventQueueElt *leftOver;
  /*--------------------------------------------------------*/
  /* walk the list deleting any elements still on the queue */
  /*--------------------------------------------------------*/
  lock();
  while ((leftOver = m_head.GetNext()))
    delete leftOver;
  unlock();
}

UdId CUDEventQueue::AddEntry(const int fd,
			     const UdInputMask mask,
			     const ud_callback callBack,
			     const void * callData)
{
  UdId uniqueId = MakeId(); // use a unique ID
  CUDEvent *newEvent = new CUDEvent(uniqueId, fd, mask, callBack, callData);

  /*---------------------------------------------------------*/
  /* Insert entry at head of list, done automagically by the */
  /* constructor function, so don't use the return value.    */
  /*---------------------------------------------------------*/
  lock();
  (void) new CUDEventQueueElt(newEvent, m_head.GetNext(), &m_head);
  m_msgCount++;
  unlock();
  return uniqueId;
}

CUDEvent *CUDEventQueue::GetEntry(const UdId uniqueId) REENTRANT (
{
  CUDEventQueueElt *msgEltPtr = m_head.GetNext();

  while (msgEltPtr)
  {
    CUDEvent *returnVal;
    if ((returnVal = msgEltPtr->TestId(uniqueId)))
      return returnVal;
    msgEltPtr = msgEltPtr->GetNext();
  }
  return 0;
})

void CUDEventQueue::DeleteEntry(const UdId uniqueId)
{
  lock();
  CUDEventQueueElt *msgEltPtr = m_head.GetNext();

  while (msgEltPtr)
  {
    if (msgEltPtr->TestId(uniqueId))
    {
      delete msgEltPtr;
      m_msgCount--;
      break;
    }
    msgEltPtr = msgEltPtr->GetNext();
  }
  unlock();
}

UdId CUDEventQueue::MakeId()
{
  UdId id;
  do {
    lock();
    id = ++m_id;
    unlock();
  } while (GetEntry(id));

  return id;
}

void CUDEventQueue::GetFdSets(int &maxfds,
                              fd_set &readfds,
                              fd_set &writefds,
                              fd_set &exceptfds) REENTRANT (
{
  CUDEventQueueElt *msgEltPtr = m_head.GetNext();

  while (msgEltPtr)
  {
    int fd = msgEltPtr->GetUDEvent()->GetFd();
    UdInputMask mask = msgEltPtr->GetUDEvent()->GetMask();
    if (mask & UdInputReadMask)   FD_SET(fd, &readfds);
    if (mask & UdInputWriteMask)  FD_SET(fd, &writefds);
    if (mask & UdInputExceptMask) FD_SET(fd, &exceptfds);
    if (maxfds < (fd + 1))
      maxfds = fd + 1;
    msgEltPtr = msgEltPtr->GetNext();
  }
})

int CUDEventQueue::HandleEvents(const int maxfds,
				const fd_set &readfds,
				const fd_set &writefds,
				const fd_set &exceptfds) REENTRANT (
{
  CUDEventQueueElt *msgEltPtr = m_head.GetNext();

  while (msgEltPtr)
  {
    int fd = msgEltPtr->GetUDEvent()->GetFd();
    UdInputMask mask = msgEltPtr->GetUDEvent()->GetMask();

    if (((mask & UdInputReadMask)   && FD_ISSET(fd, &readfds))   ||
        ((mask & UdInputWriteMask)  && FD_ISSET(fd, &writefds))  ||
        ((mask & UdInputExceptMask) && FD_ISSET(fd, &exceptfds)))
      msgEltPtr->GetUDEvent()->Callback();

    msgEltPtr = msgEltPtr->GetNext();
  }
  return SNMP_CLASS_SUCCESS;
})

#ifdef SNMP_PP_NAMESPACE
}; // end of namespace Snmp_pp
#endif 
