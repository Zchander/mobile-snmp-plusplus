/*_############################################################################
  _## 
  _##  eventlistholder.h  
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

#ifndef _SNMP_EVENTLISTHOLDER_H_
#define _SNMP_EVENTLISTHOLDER_H_

//----[ includes ]-----------------------------------------------------
#include <libsnmp.h>
#include "snmp_pp/config_snmp_pp.h"
#include "snmp_pp/snmperrs.h"
#include "snmp_pp/eventlist.h"
#include "snmp_pp/reentrant.h"
#include "snmp_pp/usertimeout.h"
#include "snmp_pp/userdefined.h"

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

class CSNMPMessageQueue;
class CNotifyEventQueue;
class CUDEventQueue;
class CUTEventQueue;
class Pdu;
class Snmp;

class DLLOPT EventListHolder
{
 public:
  EventListHolder(Snmp *snmp_session);
  ~EventListHolder() {};

  CSNMPMessageQueue *&snmpEventList()   { return m_snmpMessageQueue; };
  CNotifyEventQueue *&notifyEventList() { return m_notifyEventQueue; };
#ifdef _USER_DEFINED_EVENTS
  CUDEventQueue     *&udEventList()     { return m_udEventQueue;     };
#endif
#ifdef _USER_DEFINED_TIMEOUTS
  CUTEventQueue     *&utEventList()     { return m_utEventQueue;     };
#endif

  unsigned long SNMPGetNextTimeout();

#ifdef HAVE_POLL_SYSCALL
  int GetFdCount();
  bool GetFdArray(struct pollfd *readfds, int &remaining);
#endif
  void SNMPGetFdSets(int &  maxfds,
		     fd_set & readfds,
		     fd_set & writefds,
		     fd_set & exceptfds);

  //---------[ Main Loop ]------------------------------------------
  /**
   * Infinite loop which blocks when there is nothing to do and handles
   * any events.
   *
   * @note If no messages are outstanding, select() is called with the
   *       given timeout, so any async messages that are sent out later
   *       are not processed until this select call returns.
   */
  void SNMPMainLoop(const int max_block_milliseconds = 0 /* = infinite */);

  //---------[ Exit Main Loop ]---------------------------------------
  // Force the SNMP Main Loop to terminate immediately
  void SNMPExitMainLoop();

  /**
   * Block until an event shows up - then handle the event(s).
   *
   * @note If no messages are outstanding, select() is called with the
   *       given timeout, so any async messages that are sent out later
   *       are not processed until this select call returns.
   */
  int SNMPProcessEvents(const int max_block_milliseconds = 0 /* = infinite */);

  //---------[ Process Pending Events ]-------------------------------
  // Pull all available events out of their sockets - do not block
  int SNMPProcessPendingEvents();

  //---------[ Block For Response ]-----------------------------------
  // Wait for the completion of an outstanding SNMP event (msg).
  // Handle any other events as they occur.
  int SNMPBlockForResponse(const unsigned long req_id,
			   Pdu &    pdu);

  //--------[ usertimeout ]---------------------------------------------------
#ifdef _USER_DEFINED_TIMEOUTS
  UtId SNMPAddTimeOut(const unsigned long interval,
		      const ut_callback callBack,
		      const void * callData);
  void SNMPRemoveTimeOut(const UtId utId) { m_utEventQueue->DeleteEntry(utId);};
#endif

  //--------[ userdefined ]---------------------------------------------------
#ifdef _USER_DEFINED_EVENTS
  UdId SNMPAddInput(const int source,
		    const UdInputMask condition,
		    const ud_callback callBack,
		    const void * callData);
  void SNMPRemoveInput(const UdId udId) { m_udEventQueue->DeleteEntry(udId); };
#endif


 private:

  CSNMPMessageQueue *m_snmpMessageQueue;  // contains all outstanding messages
  CNotifyEventQueue *m_notifyEventQueue; // contains all sessions waiting for notifications
#ifdef _USER_DEFINED_EVENTS
  CUDEventQueue     *m_udEventQueue;  // contains all user-defined events
#endif
#ifdef _USER_DEFINED_TMEOUTS
  CUTEventQueue     *m_utEventQueue;  // contains all user-defined timeouts
#endif
  CEventList   m_eventList;  // contains all expected events

  SnmpSynchronized      pevents_mutex;
};

#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif 

#endif // _SNMP_EVENTLISTHOLDER_H_
