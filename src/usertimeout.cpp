/*_############################################################################
  _## 
  _##  usertimeout.cpp  
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

      U S E R T I M E O U T . C P P

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

//----[ snmp++ includes ]----------------------------------------------

#include "snmp_pp/usertimeout.h"	// queue for holding user-defined events
#include "snmp_pp/snmperrs.h"
#include "snmp_pp/eventlistholder.h"

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif


//----[ CUTEvent class ]------------------------------------------------

CUTEvent::CUTEvent( const UtId uniqueId, const msec &timeout,
		    const ut_callback callBack, const void * callData) :
  m_uniqueId(uniqueId), m_timeout(timeout), m_callBack(callBack),
  m_callData((void *)callData)
{}

int CUTEvent::Callback()
{
  if (m_callBack)
  {
    m_callBack(m_callData, m_uniqueId);
    return 0;
  }
  return 1;
}


//----[ CUTEventQueueElt class ]--------------------------------------

CUTEventQueue::CUTEventQueueElt::CUTEventQueueElt(CUTEvent *utevent,
						  CUTEventQueueElt *next,
						  CUTEventQueueElt *previous)
  : m_utevent(utevent), m_Next(next), m_previous(previous)
{
  /*------------------------------------------*/
  /* Finish insertion into doubly linked list */
  /*------------------------------------------*/
  if (m_Next)      m_Next->m_previous = this;
  if (m_previous)  m_previous->m_Next = this;
}

CUTEventQueue::CUTEventQueueElt::~CUTEventQueueElt()
{
  /*-------------------------------------*/
  /* Do deletion form doubly linked list */
  /*-------------------------------------*/
  if (m_Next)     m_Next->m_previous = m_previous;
  if (m_previous) m_previous->m_Next = m_Next;
  if (m_utevent)  delete m_utevent;
}

CUTEvent *CUTEventQueue::CUTEventQueueElt::TestId(const UtId uniqueId)
{
  if (m_utevent && (m_utevent->GetId() == uniqueId))
    return m_utevent;
  return 0;
}



//----[ CUTEventQueue class ]--------------------------------------

CUTEventQueue::~CUTEventQueue()
{
  CUTEventQueueElt *leftOver;
  /*--------------------------------------------------------*/
  /* walk the list deleting any elements still on the queue */
  /*--------------------------------------------------------*/
  lock();
  while ((leftOver = m_head.GetNext()))
    delete leftOver;
  unlock();
}

UtId CUTEventQueue::AddEntry(const msec &timeout,
			     const ut_callback callBack,
			     const void * callData)
{
  UtId uniqueId      = MakeId();  // use a unique ID
  CUTEvent *newEvent = new CUTEvent(uniqueId, timeout, callBack, callData);

  /*---------------------------------------------------------*/
  /* Insert entry at head of list, done automagically by the */
  /* constructor function, so don't use the return value.    */
  /*---------------------------------------------------------*/
  lock();
  (void) new CUTEventQueueElt(newEvent, m_head.GetNext(), &m_head);
  m_msgCount++;
  unlock();
  return uniqueId;
}

CUTEvent *CUTEventQueue::GetEntry(const UtId uniqueId) REENTRANT (
{
  CUTEventQueueElt *msgEltPtr = m_head.GetNext();

  while (msgEltPtr)
  {
    CUTEvent *returnVal;
    if ((returnVal = msgEltPtr->TestId(uniqueId)))
      return(returnVal);
    msgEltPtr = msgEltPtr->GetNext();
  }
  return 0;
})

void CUTEventQueue::DeleteEntry(const UtId uniqueId)
{
  lock();
  CUTEventQueueElt *msgEltPtr = m_head.GetNext();

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

UtId CUTEventQueue::MakeId()
{
  UtId id;
  do {
    lock();
    id = ++m_id;
    unlock();
  } while (GetEntry(id));

  return id;
}

CUTEvent * CUTEventQueue::GetNextTimeoutEntry() REENTRANT (
{
  CUTEventQueueElt *msgEltPtr = m_head.GetNext();
  msec bestTime(0, 0); // no need to be initialized...
  msec sendTime(0, 0); // no need to be initialized...
  CUTEvent *bestmsg = 0;

  if (msgEltPtr) {
    bestmsg = msgEltPtr->GetUTEvent();
    bestmsg->GetTimeout(bestTime);
  }

  // This would be much simpler if the queue was an ordered list!
  while (msgEltPtr)
  {
    CUTEvent *msg = msgEltPtr->GetUTEvent();
    msg->GetTimeout(sendTime);
    if (bestTime  > sendTime)
    {
      bestTime = sendTime;
      bestmsg = msg;
    }
    msgEltPtr = msgEltPtr->GetNext();
  }
  return bestmsg;
})

int CUTEventQueue::GetNextTimeout(msec &sendTime)
{
  CUTEvent *msg = GetNextTimeoutEntry();

  if (!msg) return 1;    // nothing in the queue...

  msg->GetTimeout(sendTime);
  return 0;
}

int CUTEventQueue::DoRetries(const msec &sendtime)
{
  CUTEvent *msg;
  msec timeout(0, 0); // no need to be initialized...

  while ((msg = GetNextTimeoutEntry()))
  {
    msg->GetTimeout(timeout);
    if (timeout <= sendtime)
    {
      UtId id = msg->GetId();
      msg->Callback();
      DeleteEntry(id);
    }
    else
      break;
  }
  return SNMP_CLASS_SUCCESS;
}

#ifdef SNMP_PP_NAMESPACE
}; // end of namespace Snmp_pp
#endif 
