/*_############################################################################
  _## 
  _##  eventlistholder.cpp  
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

#include <libsnmp.h>

#include "snmp_pp/eventlistholder.h"
#include "snmp_pp/eventlist.h"
#include "snmp_pp/msgqueue.h"
#include "snmp_pp/notifyqueue.h"
#include "snmp_pp/mp_v3.h"
#include "snmp_pp/v3.h"

#ifndef DEFAULT_MAX_BLOCK_EVENT_TIME
// While waiting for a response, this timeout
// in milli seconds is used for calls to select/poll
#define DEFAULT_MAX_BLOCK_EVENT_TIME 100
#endif

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

EventListHolder::EventListHolder(Snmp *snmp_session)
{
  // Automaticly add the SNMP message queue
  m_snmpMessageQueue = new CSNMPMessageQueue(this, snmp_session);
  m_eventList.AddEntry(m_snmpMessageQueue);

  // Automatically add the SNMP notification queue
  m_notifyEventQueue = new CNotifyEventQueue(this, snmp_session);
  m_eventList.AddEntry(m_notifyEventQueue);

#ifdef _USER_DEFINED_EVENTS
  // Automaticly add the user-defined event queue
  m_udEventQueue = new CUDEventQueue(this);
  m_eventList.AddEntry(m_udEventQueue);
#endif

#ifdef _USER_DEFINED_TIMEOUTS
  // Automaticly add the user-defined timeout queue
  m_utEventQueue = new CUTEventQueue(this);
  m_eventList.AddEntry(m_utEventQueue);
#endif
}

//---------[ Block For Response ]-----------------------------------
// Wait for the completion of an outstanding SNMP event (msg).
// Handle any other events as they occur.
int EventListHolder::SNMPBlockForResponse(const unsigned long req_id,
					  Pdu &pdu)
{
  do {
    SNMPProcessEvents(DEFAULT_MAX_BLOCK_EVENT_TIME);
  } while (!m_snmpMessageQueue->Done(req_id));

  m_snmpMessageQueue->lock();
  CSNMPMessage *msg = m_snmpMessageQueue->GetEntry(req_id);
  if (msg) {
    // we found our response
    int status;
    msg->GetPdu(status, pdu);

    // Dequeue the message
    m_snmpMessageQueue->DeleteEntry(req_id);
    m_snmpMessageQueue->unlock();
    return status;
  }
  else {
    // not in the send queue...must have timed out
    m_snmpMessageQueue->unlock();
    return SNMP_CLASS_TIMEOUT;
  }
}

//---------[ Process Pending Events ]-------------------------------
#ifdef HAVE_POLL_SYSCALL
// Pull all available events out of their sockets - do not block
int EventListHolder::SNMPProcessPendingEvents()
{
  int fdcount;
  int remaining;
  struct pollfd *pollfds = 0;
  int nfound = 0;
  int timeout;
  msec now(0, 0);
  int status;

  pevents_mutex.lock();

  timeout = 1;  // chosen a very small timeout
  // in order to avoid busy looping but keep overall performance

  do
  {
    do
    {
      fdcount = m_eventList.GetFdCount();
      if (pollfds) delete [] pollfds;
      pollfds = new struct pollfd[fdcount + 1];
      memset(pollfds, 0, (fdcount + 1) * sizeof(struct pollfd));
      remaining = fdcount + 1;
    } while (m_eventList.GetFdArray(pollfds, remaining) == false);

    nfound = poll(pollfds, fdcount, timeout);

    now.refresh();

    if (nfound > 0)
    {
      status = m_eventList.HandleEvents(pollfds, fdcount);
      // TM should we do anything with bad status?
    }
#ifdef WIN32
    /* On Win32 select immediately returns -1 if all fd_sets are empty */
    if (maxfds == 0)
      Sleep(1); /* prevent 100% CPU utilization */
#endif
  } while (nfound > 0);

  // go through the message queue and resend any messages
  // which are past the timeout.
  status = m_eventList.DoRetries(now);

  pevents_mutex.unlock();

  if (pollfds) delete [] pollfds;

  return status;
}

// Block until an event shows up - then handle the event(s)
int EventListHolder::SNMPProcessEvents(const int max_block_milliseconds)
{
  int fdcount;
  int remaining;
  struct pollfd *pollfds = 0;
  struct timeval fd_timeout;
  int timeout;
  msec now; // automatcally calls msec::refresh()
  msec sendTime;
  int status = 0;

  m_eventList.GetNextTimeout(sendTime);
  now.GetDelta(sendTime, fd_timeout);

  do
  {
    fdcount = m_eventList.GetFdCount();
    if (pollfds) delete [] pollfds;
    pollfds = new struct pollfd[fdcount + 1];
    memset(pollfds, 0, (fdcount + 1) * sizeof(struct pollfd));
    remaining = fdcount + 1;
  } while (m_eventList.GetFdArray(pollfds, remaining) == false);

  if ((max_block_milliseconds > 0) &&
      ((fd_timeout.tv_sec > max_block_milliseconds / 1000) ||
       ((fd_timeout.tv_sec == max_block_milliseconds / 1000) &&
	(fd_timeout.tv_usec > (max_block_milliseconds % 1000) * 1000))))
  {
    fd_timeout.tv_sec = max_block_milliseconds / 1000;
    fd_timeout.tv_usec = (max_block_milliseconds % 1000) * 1000;
  }

  /* Prevent endless sleep in case no fd is open */
  if ((fdcount == 0) && (fd_timeout.tv_sec > 5))
    fd_timeout.tv_sec = 5; /* sleep at max 5.99 seconds */

  timeout = fd_timeout.tv_sec * 1000 + fd_timeout.tv_usec / 1000;

  poll(pollfds, fdcount, timeout);

  status = SNMPProcessPendingEvents();

  if (pollfds) delete [] pollfds;

  return status;
}

#else

int EventListHolder::SNMPProcessPendingEvents()
{
  int maxfds;
  fd_set readfds;
  fd_set writefds;
  fd_set exceptfds;
  int nfound = 0;
  struct timeval fd_timeout;
  msec now(0, 0);
  int status;

  pevents_mutex.lock();

  do
  {
    // do not allow select to block; chosen a very small timeout
    // in order to avoid busy looping but keep overall performance
    fd_timeout.tv_sec = 0;
    fd_timeout.tv_usec = 10;

    // Set up Select
    m_eventList.GetFdSets(maxfds, readfds, writefds, exceptfds);

    nfound = select(maxfds, &readfds, &writefds, &exceptfds, &fd_timeout);

    now.refresh();

    if (nfound > 0)
    { // found something on select
      status = m_eventList.HandleEvents(maxfds, readfds, writefds, exceptfds);
      // TM should we do anything with bad status?
    }
#ifdef WIN32
    /* On Win32 select immediately returns -1 if all fd_sets are empty */
    if (maxfds == 0)
      Sleep(1); /* prevent 100% CPU utilization */
#endif
  } while (nfound > 0);

  // go through the message queue and resend any messages
  // which are past the timeout.
  status = m_eventList.DoRetries(now);

  pevents_mutex.unlock();

  return status;
}

//---------[ Process Events ]------------------------------------------
// Block until an event shows up - then handle the event(s)
int EventListHolder::SNMPProcessEvents(const int max_block_milliseconds)
{
  int maxfds;
  fd_set readfds;
  fd_set writefds;
  fd_set exceptfds;
  struct timeval fd_timeout;
  msec now; // automatically calls msec::refresh()
  msec sendTime;
  int status = 0;

  m_eventList.GetNextTimeout(sendTime);
  now.GetDelta(sendTime, fd_timeout);

  m_eventList.GetFdSets(maxfds, readfds, writefds, exceptfds);

  if ((max_block_milliseconds > 0) &&
      ((fd_timeout.tv_sec > max_block_milliseconds / 1000) ||
       ((fd_timeout.tv_sec == max_block_milliseconds / 1000) &&
	(fd_timeout.tv_usec > (max_block_milliseconds % 1000) * 1000))))
  {
    fd_timeout.tv_sec = max_block_milliseconds / 1000;
    fd_timeout.tv_usec = (max_block_milliseconds % 1000) * 1000;
  }

  /* Prevent endless sleep in case no fd is open */
  if ((maxfds == 0) && (fd_timeout.tv_sec > 5))
    fd_timeout.tv_sec = 5; /* sleep at max 5.99 seconds */

  select(maxfds, &readfds, &writefds, &exceptfds, &fd_timeout);

  status = SNMPProcessPendingEvents();

  return status;
}

#endif

//---------[ Main Loop ]------------------------------------------
// Infinite loop which blocks when there is nothing to do and handles
// any events as they occur.
void EventListHolder::SNMPMainLoop(const int max_block_milliseconds)
{
  do {
    SNMPProcessEvents(max_block_milliseconds);
  } while (!m_eventList.Done());
}

//---------[ Exit Main Loop ]---------------------------------------
// Force the SNMP Main Loop to terminate immediately
void EventListHolder::SNMPExitMainLoop()
{
   m_eventList.SetDone();
}

#ifdef HAVE_POLL_SYSCALL

int EventListHolder::GetFdCount()
{
  return m_eventList.GetFdCount();
}

bool EventListHolder::GetFdArray(struct pollfd *readfds, int &remaining)
{
    return m_eventList.GetFdArray(readfds, remaining);
}

#else

void EventListHolder::SNMPGetFdSets(int    &maxfds,
				    fd_set &readfds,
				    fd_set &writefds,
				    fd_set &exceptfds)
{
  m_eventList.GetFdSets(maxfds, readfds, writefds, exceptfds);
}

#endif // HAVE_POLL_SYSCALL

unsigned long EventListHolder::SNMPGetNextTimeout()
{
  msec now;
  msec sendTime(now);

//TM: This function used to have an argument of sendTime and
//    would simply call eventList.GetNextTimeout(sendTime) and
//    return the status.  However, to avoid exposing the msec
//    class we now convert the msec to hundreths of seconds
//    and return that as a unsigned long.
// 25-Jan-96 TM

  m_eventList.GetNextTimeout(sendTime);
  if (sendTime.IsInfinite()) {
    return UINT_MAX;
  }
  else {

    // Kludge: When this was first designed the units were millisecs
    // However, later on the units for the target class were changed
    // to hundreths of secs.  Divide millisecs by 10 to create the
    // hundreths of secs which the rest of the objects use.
    // 25-Jan-96 TM

    // 21-May-02 DLD: Add check to avoid returning a negative interval
    // Long eventlists seem to end up with events that are greater
    // than the time when the event loop is started, but less than the
    // time when this function is called.  This check is analagous to
    // what is done in msec::GetDelta() which is used in
    // SNMPProcessEvents(), the library main loop.

    // 21-May-02 DLD: Add 1/100 sec to time out to avoid returning a
    // short time out interval.  A short interval can result due to
    // truncation of the millisec value when dividing by 10.

    if (sendTime > now)
    {
      sendTime -= now;
      return ((((unsigned long) sendTime) / 10) + 1);
    }
    else
      return 0;
  }
}
#ifdef _USER_DEFINED_TIMEOUTS
UtId EventListHolder::SNMPAddTimeOut(const unsigned long interval,
				     const ut_callback callBack,
				     const void * callData)
{
  msec now;
  now += interval;
  return m_utEventQueue->AddEntry(now, callBack, callData);
}
#endif

#ifdef _USER_DEFINED_EVENTS
UdId EventListHolder::SNMPAddInput(const int source,
				   const UdInputMask condition,
				   const ud_callback callBack,
				   const void * callData)
{
  return m_udEventQueue->AddEntry(source, condition, callBack, callData);
}
#endif

#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif 
