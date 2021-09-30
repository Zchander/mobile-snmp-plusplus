/*_############################################################################
  _## 
  _##  mp_v3.cpp  
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
char mp_v3_cpp_version[]="@(#) SNMP++ $Id$";

#include <libsnmp.h>

#include "snmp_pp/config_snmp_pp.h"

#ifdef _SNMPv3
#include "snmp_pp/v3.h"
#include "snmp_pp/mp_v3.h"
#include "snmp_pp/usm_v3.h"
#include "snmp_pp/notifyqueue.h"
#include "snmp_pp/snmpmsg.h"
#include "snmp_pp/uxsnmp.h"
#include "snmp_pp/eventlistholder.h"
#include "snmp_pp/asn1.h"
#include "snmp_pp/vb.h"
#include "snmp_pp/log.h"

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

static const char *loggerModuleName = "snmp++.mp_v3";

#define MAX_MPMSGID 2147483647

#define CACHE_LOCAL_REQ true
#define CACHE_REMOTE_REQ false

v3MP *v3MP::I = 0;

// Use locking on access methods in an multithreaded environment.
#ifdef _THREADS
#define BEGIN_REENTRANT_CODE_BLOCK SnmpSynchronize auto_lock(lock)
#define BEGIN_REENTRANT_CODE_BLOCK_CONST  \
          SnmpSynchronize auto_lock(*(PP_CONST_CAST(SnmpSynchronized*, &lock)))
#else
#define BEGIN_REENTRANT_CODE_BLOCK
#define BEGIN_REENTRANT_CODE_BLOCK_CONST
#endif

// ========================[ Engine id table ]=============================

// Construct engine id table
v3MP::EngineIdTable::EngineIdTable(int initial_size)
 : upper_limit_entries(MAX_ENGINE_ID_CACHE_SIZE)
{
  if (initial_size < 1)
    initial_size = 10;

  if (!initialize_table(initial_size))
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 0);
    LOG("v3MP::EngineIdTable: Error creating empty table.");
    LOG_END;
  }
}

// Destruct engine id table
v3MP::EngineIdTable::~EngineIdTable()
{
  if (table)
    delete [] table;
  table = 0;
}

// Add an entry to the table.
int v3MP::EngineIdTable::add_entry(const OctetStr &engine_id,
                                   const OctetStr &host, int port)
{
  if (!table)
    return SNMPv3_MP_NOT_INITIALIZED;

  if (entries >= upper_limit_entries) {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 0);
    LOG("v3MP::EngineIdTable: rejected new entry because upper limit reached (id) (host) (port) (limit)");
    LOG(engine_id.get_printable());
    LOG(host.get_printable());
    LOG(port);
    LOG(upper_limit_entries);
    LOG_END;
    return SNMPv3_MP_ERROR;  
  }
  
  LOG_BEGIN(loggerModuleName, INFO_LOG | 9);
  LOG("v3MP::EngineIdTable: adding new entry (id) (host) (port)");
  LOG(engine_id.get_printable());
  LOG(host.get_printable());
  LOG(port);
  LOG_END;

  BEGIN_REENTRANT_CODE_BLOCK;

  for (int i = 0; i < entries; i++)
    if (((table[i].port == port) &&
         (table[i].host == host)) ||
	(table[i].engine_id == engine_id))
    {
      LOG_BEGIN(loggerModuleName, INFO_LOG | 2);
      LOG("v3MP::EngineIdTable: replace entry (old id) (old host) (old port) (id) (host) (port)");
      LOG(table[i].engine_id.get_printable());
      LOG(table[i].host.get_printable());
      LOG(table[i].port);
      LOG(engine_id.get_printable());
      LOG(host.get_printable());
      LOG(port);
      LOG_END;

      table[i].engine_id = engine_id;
      table[i].host = host;
      table[i].port = port;

      return SNMPv3_MP_OK;         // host is in table
    }

  table[entries].engine_id = engine_id;
  table[entries].host = host;
  table[entries].port = port;

  entries++;
  if (entries == max_entries)
  {
    // resize Table
    struct Entry_T *tmp;
    tmp = new struct Entry_T[2 * max_entries];
    if (!tmp)
    {
      entries--;
      return SNMPv3_MP_ERROR;
    }
    for (int i = 0; i < entries; i++)
      tmp[i] = table[i];

    delete [] table;
    table = tmp;
    max_entries *= 2;
  }

  return SNMPv3_MP_OK;
}

// Get the engine_id of the SNMP entity at the given host/port.
int v3MP::EngineIdTable::get_entry(OctetStr &engine_id,
                                   const OctetStr &hostport) const
{
  int port;
  char host[MAX_HOST_NAME_LENGTH + 1];
  char *ptr;

  /* Check length */
  if (hostport.len() > MAX_HOST_NAME_LENGTH)
    return SNMPv3_MP_ERROR;

  /* split up port from hostport */
  strcpy(host, hostport.get_printable());

  ptr = strstr((char*)host,"/");
  if (!ptr)
    return SNMPv3_MP_ERROR;

  *ptr = '\0';
  port = atol(ptr + 1);

  /* Check for IPv6 address with [] */
  if (host[0] == '[')
  {
    if (*(ptr -1) == ']')
    {
      *(ptr-1) = '\0';
      return get_entry(engine_id, &(host[1]), port);
    }
    else
      return SNMPv3_MP_ERROR;
  }
  return get_entry(engine_id, host, port);
}

// Get the engineID of the SNMP entity at the given host/port.
int v3MP::EngineIdTable::get_entry(OctetStr &engine_id,
                                   const OctetStr &host, int port) const
{
  if (!table)
    return SNMPv3_MP_NOT_INITIALIZED;

  BEGIN_REENTRANT_CODE_BLOCK_CONST;

  int i, found = 0;

  for (i = 0; i < entries; i++)
    if ((table[i].port == port) &&
        (table[i].host == host))
    {
      found=1;
      break;
    }
  if (!found)
  {
    LOG_BEGIN(loggerModuleName, INFO_LOG | 4);
    LOG("v3MP::EngineIdTable: Dont know engine id for (host) (port)");
    LOG(host.get_printable());
    LOG(port);
    LOG_END;

    return SNMPv3_MP_ERROR;
  }

  engine_id = table[i].engine_id;

  return SNMPv3_MP_OK;
}

// Remove all entries from the engine id table.
int v3MP::EngineIdTable::reset()
{
  if (!table)
    return SNMPv3_MP_NOT_INITIALIZED;

  LOG_BEGIN(loggerModuleName, INFO_LOG | 1);
  LOG("v3MP::EngineIdTable: Resetting table.");
  LOG_END;

  BEGIN_REENTRANT_CODE_BLOCK;

  entries = 0;

  return SNMPv3_MP_OK;
}

// Remove the given engine id from the table.
int v3MP::EngineIdTable::delete_entry(const OctetStr &engine_id)
{
  if (!table)
    return SNMPv3_MP_NOT_INITIALIZED;

  int i, found = 0;

  BEGIN_REENTRANT_CODE_BLOCK;

  for (i = 0; i < entries; i++)
    if (table[i].engine_id == engine_id)
    {
      found=1;
      break;
    }
  if (!found)
  {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 4);
    LOG("v3MP::EngineIdTable: cannot remove nonexisting entry (engine id)");
    LOG(engine_id.get_printable());
    LOG_END;

    return SNMPv3_MP_ERROR;
  }

  /* i is the entry to remove */
  if (i != entries - 1)
    table[i] = table[entries-1];

  entries--;

  return SNMPv3_MP_OK;
}

// Remove the entry for the given address/port from the table.
int v3MP::EngineIdTable::delete_entry(const OctetStr &host, int port)
{
  if (!table)
    return SNMPv3_MP_NOT_INITIALIZED;

  int i, found = 0;

  BEGIN_REENTRANT_CODE_BLOCK;

  for (i = 0; i < entries; i++)
    if ((table[i].port == port) &&
        (table[i].host == host))
    {
      found=1;
      break;
    }
  if (!found)
  {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 4);
    LOG("v3MP::EngineIdTable: cannot remove nonexisting entry (host) (port)");
    LOG(host.get_printable());
    LOG(port);
    LOG_END;

    return SNMPv3_MP_ERROR;
  }

  /* i is the entry to remove */
  if (i != entries - 1)
    table[i] = table[entries-1];

  entries--;

  return SNMPv3_MP_OK;
}

bool v3MP::EngineIdTable::initialize_table(const int size)
{
  table = new struct Entry_T[size];
  entries = 0;
  if (!table)
  {
    max_entries = 0;
    return false;
  }
  max_entries = size;
  return true;
}

// ===============================[ Cache ]==================================

v3MP::Cache::Cache()
{
  // init cache
  table = new struct Entry_T[5];
  if (!table)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("v3MP::Cache: could not create empty table.");
    LOG_END;

    max_entries = 0;
  }
  else
    max_entries = 5;

  entries = 0;
}

v3MP::Cache::~Cache()
{
  if (table)
  {
    if (entries > 0)
    {
      LOG_BEGIN(loggerModuleName, WARNING_LOG | 3);
      LOG("v3MP::Cache: Cache not empty in destructor (entries)");
      LOG(entries);
      LOG_END;
    }

    for (int i = 0; i < entries; i++)
      usm->delete_sec_state_reference(table[i].sec_state_ref);
    entries = 0;
    delete [] table;
    table = 0;
    max_entries = 0;
  }
}

// Add an entry to the cache.
int v3MP::Cache::add_entry(int msg_id, unsigned long req_id,
                           const OctetStr &sec_engine_id,
                           int sec_model,
                           const OctetStr &sec_name,
                           int sec_level,
                           const OctetStr &context_engine_id,
                           const OctetStr &context_name,
                           struct SecurityStateReference *sec_state_ref,
                           int error_code, bool local_request)
{
  if (!table)
    return SNMPv3_MP_ERROR;

  LOG_BEGIN(loggerModuleName, INFO_LOG | 8);
  LOG("v3MP::Cache: adding new entry (n) (msg id) (req id) (type)");
  LOG(entries);
  LOG(msg_id);
  LOG(req_id);
  LOG(local_request ? "local" : "remote");
  LOG_END;

  BEGIN_REENTRANT_CODE_BLOCK;

  for (int i = 0; i < entries; i++)
    if ((table[i].msg_id == msg_id) &&
        (table[i].req_id == req_id) &&
        (table[i].local_request == local_request) &&
        (table[i].sec_engine_id == sec_engine_id) &&
        (table[i].sec_model == sec_model) &&
        (table[i].sec_name == sec_name) &&
        (table[i].sec_level == sec_level) &&
        (table[i].context_engine_id == context_engine_id) &&
        (table[i].context_name == context_name))
    {
      LOG_BEGIN(loggerModuleName, WARNING_LOG | 3);
      LOG("v3MP::Cache: Dont add doubled entry (msg id) (req id)");
      LOG(msg_id);
      LOG(req_id);
      LOG_END;

      return SNMPv3_MP_DOUBLED_MESSAGE;
    }

  table[entries].msg_id            = msg_id;
  table[entries].req_id            = req_id;
  table[entries].local_request     = local_request;
  table[entries].sec_engine_id     = sec_engine_id;
  table[entries].sec_model         = sec_model;
  table[entries].sec_name          = sec_name;
  table[entries].sec_level         = sec_level;
  table[entries].context_engine_id = context_engine_id;
  table[entries].context_name      = context_name;
  table[entries].sec_state_ref     = sec_state_ref;
  table[entries].error_code        = error_code;

  entries++;
  if (entries == max_entries)
  {
    // resize Table
    struct Entry_T *tmp;
    tmp = new struct Entry_T[2 * max_entries];
    if (!tmp)
    {
      entries--;
      return SNMPv3_MP_ERROR;
    }
    for (int i=0; i<entries;i++)
      tmp[i] = table[i];
    delete [] table;
    table = tmp;
    max_entries *= 2;
  }
  return SNMPv3_MP_OK;
}

// Search the cache for a message id, return the error code and
int v3MP::Cache::get_entry(int msg_id, bool local_request, int *error_code,
                           struct SecurityStateReference **sec_state_ref)
{
  if (!table) return SNMPv3_MP_ERROR;

  BEGIN_REENTRANT_CODE_BLOCK;

  for (int i=0; i < entries; i++)
  {
    if ((msg_id == table[i].msg_id) &&
        (local_request == table[i].local_request))
    {
      *error_code = table[i].error_code;
      *sec_state_ref = table[i].sec_state_ref;
      entries--;

      LOG_BEGIN(loggerModuleName, INFO_LOG | 8);
      LOG("v3MP::Cache: Found entry (n) (msg id) (type)");
      LOG(i);
      LOG(msg_id);
      LOG(local_request ? "local" : "remote");
      LOG_END;

      if (entries > i)
      {
        table[i] = table[entries];

	LOG_BEGIN(loggerModuleName, INFO_LOG | 10);
	LOG("v3MP::Cache: Moving entry (from) (to)");
	LOG(entries);
	LOG(i);
	LOG_END;
      }
      return SNMPv3_MP_OK;
    }
  }

  LOG_BEGIN(loggerModuleName, WARNING_LOG | 5);
  LOG("v3MP::Cache: Entry not found (msg id) (type)");
  LOG(msg_id);
  LOG(local_request ? "local" : "remote");
  LOG_END;

  return SNMPv3_MP_ERROR;
}

// Delete the entry with the given request id from the cache.
void v3MP::Cache::delete_entry(unsigned long req_id, bool local_request)
{
  if (!table) return;

  BEGIN_REENTRANT_CODE_BLOCK;

  for (int i=0; i<entries; i++)
    if ((table[i].req_id == req_id) &&
        (table[i].local_request == local_request))
    {
      LOG_BEGIN(loggerModuleName, INFO_LOG | 8);
      LOG("v3MP::Cache: Delete unprocessed entry (n) (req id) (type)");
      LOG(i);
      LOG(req_id);
      LOG(local_request ? "local" : "remote");
      LOG_END;

      usm->delete_sec_state_reference(table[i].sec_state_ref);
      entries--;
      if (entries > i)
      {
        table[i] = table[entries];

	LOG_BEGIN(loggerModuleName, INFO_LOG | 10);
	LOG("v3MP::Cache: Moving entry (from) (to)");
	LOG(entries);
	LOG(i);
	LOG_END;
      }
      return;
    }

  LOG_BEGIN(loggerModuleName, INFO_LOG | 8);
  LOG("v3MP::Cache: Entry to delete not found (req id) (type)");
  LOG(req_id);
  LOG(local_request ? "local" : "remote");
  LOG_END;

  return;
}

// Delete the entry with the given request ans message id from the cache.
void v3MP::Cache::delete_entry(unsigned long req_id, int msg_id,
			       bool local_request)
{
  if (!table) return;

  BEGIN_REENTRANT_CODE_BLOCK;

  for (int i=0; i<entries; i++)
    if ((table[i].req_id == req_id) &&
	(table[i].msg_id == msg_id) &&
        (table[i].local_request == local_request))
    {
      LOG_BEGIN(loggerModuleName, INFO_LOG | 8);
      LOG("v3MP::Cache: Delete unprocessed entry (n) (req id) (msg id) (type)");
      LOG(i);
      LOG(req_id);
      LOG(msg_id);
      LOG(local_request ? "local" : "remote");
      LOG_END;

      usm->delete_sec_state_reference(table[i].sec_state_ref);
      entries--;
      if (entries > i)
      {
        table[i] = table[entries];

	LOG_BEGIN(loggerModuleName, INFO_LOG | 10);
	LOG("v3MP::Cache: Moving entry (from) (to)");
	LOG(entries);
	LOG(i);
	LOG_END;
      }
      return;
    }

  LOG_BEGIN(loggerModuleName, INFO_LOG | 8);
  LOG("v3MP::Cache: Entry to delete not found (req id) (msg id) (type)");
  LOG(req_id);
  LOG(msg_id);
  LOG(local_request ? "local" : "remote");
  LOG_END;

  return;
}

// Search the cache for a message id, return it and remove it from the cache
int v3MP::Cache::get_entry(int searchedID, bool local_request,
                           struct Cache::Entry_T *res)
{
  if ((!table) || (!res)) return SNMPv3_MP_ERROR;

  BEGIN_REENTRANT_CODE_BLOCK;

  for (int i=0; i < entries; i++)
    if ((table[i].msg_id == searchedID) &&
        (table[i].local_request == local_request))
    {
      res->msg_id            = table[i].msg_id;
      res->req_id            = table[i].req_id;
      res->local_request     = table[i].local_request;
      res->sec_engine_id     = table[i].sec_engine_id;
      res->sec_model         = table[i].sec_model;
      res->sec_name          = table[i].sec_name;
      res->sec_level         = table[i].sec_level;
      res->context_engine_id = table[i].context_engine_id;
      res->context_name      = table[i].context_name;
      res->sec_state_ref     = table[i].sec_state_ref;
      res->error_code        = table[i].error_code;

      LOG_BEGIN(loggerModuleName, INFO_LOG | 8);
      LOG("v3MP::Cache: Found entry (n) (msg id) (type)");
      LOG(i);
      LOG(searchedID);
      LOG(local_request ? "local" : "remote");
      LOG_END;

      entries--;

      if (entries > i)
      {
        table[i] = table[entries];

	LOG_BEGIN(loggerModuleName, INFO_LOG | 10);
	LOG("v3MP::Cache: Moving entry (from) (to)");
	LOG(entries);
	LOG(i);
	LOG_END;
      }
      return SNMPv3_MP_OK;
    }

  LOG_BEGIN(loggerModuleName, WARNING_LOG | 5);
  LOG("v3MP::Cache: Entry not found (msg id) (type)");
  LOG(searchedID);
  LOG(local_request ? "local" : "remote");
  LOG_END;

  return SNMPv3_MP_ERROR;
}

void v3MP::Cache::delete_content(struct v3MP::Cache::Entry_T &ce)
{
  if (ce.sec_state_ref)
    usm->delete_sec_state_reference(ce.sec_state_ref);
}

// ==========================[ class v3MP ]===============================

// Initialize the v3MP.
v3MP::v3MP(const OctetStr& snmpEngineID,
           unsigned int engineBoots, int &construct_status)
  : own_engine_id(0), usm(0)
{
  I = this;

  snmpUnknownSecurityModels = 0;
  snmpInvalidMsgs = 0;
  snmpUnknownPDUHandlers = 0;

  int length = snmpEngineID.len();
  if (length > MAXLENGTH_ENGINEID)
    length = MAXLENGTH_ENGINEID;

  own_engine_id = v3strcpy(snmpEngineID.data(), length);
  own_engine_id_len = length;
  own_engine_id_oct = snmpEngineID;

  int result;
  usm = new USM(engineBoots, snmpEngineID, this, &cur_msg_id, result);

  if (cur_msg_id >= MAX_MPMSGID)
    cur_msg_id = 1;

  if ((!own_engine_id) || (!usm) || (result != SNMPv3_USM_OK))
  {
    construct_status = SNMPv3_MP_ERROR;
    return;
  }

  cache.set_usm(usm);
  construct_status = SNMPv3_MP_OK;
}

// Free all allocated resources of the v3MP.
v3MP::~v3MP()
{
  if (own_engine_id)
    delete [] own_engine_id;
  own_engine_id = 0;

  if (usm)
  {
    delete usm;
    usm = 0;
  }

  I = 0;
}

// Remove all occurrences of this engine id from v3MP and USM.
int v3MP::remove_engine_id(const OctetStr &engine_id)
{
  int retval1 = engine_id_table.delete_entry(engine_id);
  int retval2 = usm->remove_engine_id(engine_id);

  if ((retval1 == SNMPv3_MP_NOT_INITIALIZED) ||
      (retval2 == SNMPv3_USM_ERROR))
    return SNMPv3_MP_NOT_INITIALIZED;

  return SNMPv3_MP_OK;
}

// Send a report message.
int v3MP::send_report(unsigned char* scopedPDU, int scopedPDULength,
		      struct snmp_pdu *pdu, int errorCode, int sLevel,
		      int sModel, OctetStr &sName,
		      UdpAddress &destination, Snmp *snmp_session)
{
  debugprintf(2, "v3MP::send_report: Sending report message.");

  int pdu_type = 0;
  unsigned char cEngineID[MAXLENGTH_ENGINEID+1];
  unsigned char cName[MAXLENGTH_CONTEXT_NAME+1];
  int cEngineIDLength = MAXLENGTH_ENGINEID+1;
  int cNameLength = MAXLENGTH_CONTEXT_NAME+1;

  debugprintf(2, "v3MP::send_report: securityLevel %d",sLevel);

  if (scopedPDULength != MAX_SNMP_PACKET)
  {
    // try to get scopedPDU and PDU
    unsigned char *data = asn1_parse_scoped_pdu(scopedPDU, &scopedPDULength,
                                                cEngineID, &cEngineIDLength,
                                                cName, &cNameLength);
    if (!data)
    {
      debugprintf(1, "mp: Error while trying to parse  scopedPDU!");
      cEngineID[0] = '\0';
      cEngineIDLength = 0;
      cName[0] = '\0';
      cNameLength = 0;
      // Dont send encrypted report if decryption failed:
      //if (sLevel == SNMP_SECURITY_LEVEL_AUTH_PRIV)
     //   sLevel = SNMP_SECURITY_LEVEL_AUTH_NOPRIV;
    }
    else
    {
      int dataLength = scopedPDULength;

      // parse data of scopedPDU
      snmp_parse_data_pdu(pdu, data, dataLength);
      pdu_type = pdu->command;

      if (!data) {
        debugprintf(0, "mp: Error while trying to parse PDU!");
      }
    } // end of: if (data == NULL)
  } // end if (scopedPDULength != MAX_SNMP_PACKET)
  else { // scopedPDULength == MAX_SNMP_PACKET
    cEngineID[0] = '\0';
    cEngineIDLength = 0;
    cName[0] = '\0';
    cNameLength = 0;
    pdu->reqid = 0;
  }

  clear_pdu(pdu);   // Clear pdu and free all content

  debugprintf(4, "pdu->reqid = %ld",pdu->reqid);
  pdu->errstat = 0;
  pdu->errindex = 0;
  pdu->command = REPORT_MSG;

  Vb counterVb;
  Oid counterOid;
  SmiLPOID smioid;
  SmiVALUE smival;

  switch (errorCode) {
    case SNMPv3_MP_INVALID_MESSAGE:
    case SNMPv3_USM_PARSE_ERROR: {
      counterVb.set_oid(oidSnmpInvalidMsgs);
      counterVb.set_value(Counter32(get_stats_invalid_msgs()));
      break;
    }
    case SNMPv3_USM_NOT_IN_TIME_WINDOW:
    case SNMPv3_MP_NOT_IN_TIME_WINDOW: {
      counterVb.set_oid(oidUsmStatsNotInTimeWindows);
      counterVb.set_value(Counter32(usm->get_stats_not_in_time_windows()));
      break;
    }
    case SNMPv3_USM_DECRYPTION_ERROR: {
      counterVb.set_oid(oidUsmStatsDecryptionErrors);
      counterVb.set_value(Counter32(usm->get_stats_decryption_errors()));
      //sLevel = SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV;
      break;
    }
    case SNMPv3_USM_AUTHENTICATION_ERROR:
    case SNMPv3_USM_AUTHENTICATION_FAILURE: {
      counterVb.set_oid(oidUsmStatsWrongDigests);
      counterVb.set_value(Counter32(usm->get_stats_wrong_digests()));
      //sLevel = SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV;
      break;
    }
    case SNMPv3_USM_UNKNOWN_ENGINEID:
    case SNMPv3_MP_INVALID_ENGINEID: {
      //sLevel = SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV;
      counterVb.set_oid(oidUsmStatsUnknownEngineIDs);
      counterVb.set_value(Counter32(usm->get_stats_unknown_engine_ids()));
      break;
    }
    case SNMPv3_MP_UNSUPPORTED_SECURITY_MODEL: {
      counterVb.set_oid(oidSnmpUnknownSecurityModels);
      counterVb.set_value(Counter32(get_stats_unknown_security_models()));
      sModel = SNMP_SECURITY_MODEL_USM;
      sLevel = SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV;
    break;
    }
    case SNMPv3_USM_UNKNOWN_SECURITY_NAME: {
      counterVb.set_oid(oidUsmStatsUnknownUserNames);
      counterVb.set_value(Counter32(usm->get_stats_unknown_user_names()));
      sLevel = SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV;
      debugprintf(2, "Report: SecurityName: %s",sName.get_printable());
      break;
    }
    case SNMPv3_USM_UNSUPPORTED_SECURITY_LEVEL: {
      counterVb.set_oid(oidUsmStatsUnsupportedSecLevels);
      counterVb.set_value(Counter32(usm->get_stats_unsupported_sec_levels()));
      sLevel = SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV;
      break;
    }
    default: {
      counterVb.set_oid(oidSnmpInvalidMsgs);
      counterVb.set_value(Counter32(get_stats_invalid_msgs()));
      sModel = SNMP_SECURITY_MODEL_USM;
      sLevel = SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV;
      sName.set_data(0, 0);

      debugprintf(2, "ErrorCode was %i in snmp_parse", errorCode);
    }
  } // end switch

  counterVb.get_oid(counterOid);
  smioid = counterOid.oidval();

  int status = convertVbToSmival(counterVb, &smival);
  if (status != SNMP_CLASS_SUCCESS) {
    return SNMPv3_MP_ERROR;
  }
  snmp_add_var(pdu, smioid->ptr,
               (int) smioid->len, &smival);
  freeSmivalDescriptor(&smival);

  Buffer<unsigned char> sendbuffer(MAX_SNMP_PACKET);
  int sendbufferlen= MAX_SNMP_PACKET;
  status = snmp_build( pdu, sendbuffer.get_ptr(), &sendbufferlen,
		       own_engine_id_oct, sName, sModel, sLevel,
		       OctetStr(cEngineID, cEngineIDLength),
		       OctetStr(cName, cNameLength));
  if (status != SNMPv3_MP_OK) {
    debugprintf(2, "v3MP::send_report: error serializing message (mpSnmpBuild returns: %i).", status);
    return SNMPv3_MP_ERROR;
  }
  SnmpSocket send_fd = INVALID_SOCKET;
  if (pdu_type == sNMP_PDU_INFORM)
  {
    debugprintf(4, "Received a snmpInform pdu.");
    if (snmp_session->get_eventListHolder()->notifyEventList())
      send_fd = snmp_session->get_eventListHolder()->notifyEventList()->get_notify_fd();
  }

  status = snmp_session->send_raw_data(sendbuffer.get_ptr(),
                                       (size_t)sendbufferlen,// pdu to send
			               destination,          // target address
			               send_fd);             // the fd to use
  if ( status != 0)
  {
    debugprintf(1, "v3MP::send_report: error sending message (%i)", status);
    return SNMPv3_MP_ERROR;
  }
  debugprintf(3, "v3MP::send_report: Report sent.");
  return SNMPv3_MP_OK;
}

// Parse the given buffer as a SNMPv3-Message.
int v3MP::snmp_parse(Snmp *snmp_session,
                     struct snmp_pdu *pdu,
                     unsigned char *inBuf,
                     int inBufLength,
                     OctetStr &securityEngineID,
                     OctetStr &securityName,
                     OctetStr &contextEngineID,
                     OctetStr &contextName,
                     long     &securityLevel,
                     long     &msgSecurityModel,
                     snmp_version &spp_version,
                     UdpAddress from_address)
{
  debugprintf(3, "mp is parsing incoming message:");
  debughexprintf(25, inBuf, inBufLength);

  if (inBufLength > MAX_SNMP_PACKET)
    return  SNMPv3_MP_ERROR;

  unsigned char type;
  long version;
  int origLength = inBufLength;
  unsigned char *inBufPtr = inBuf;
  long msgID, msgMaxSize;
  unsigned char msgFlags;
  Buffer<unsigned char> msgSecurityParameters(MAX_SNMP_PACKET);
  Buffer<unsigned char> msgData(MAX_SNMP_PACKET);
  int msgSecurityParametersLength = inBufLength,   msgDataLength = inBufLength;
  Buffer<unsigned char> scopedPDU(MAX_SNMP_PACKET);
  int scopedPDULength = MAX_SNMP_PACKET;
  long  maxSizeResponseScopedPDU = 0;
  struct SecurityStateReference *securityStateReference = NULL;
  int securityParametersPosition;
  int rc;
  int errorCode = 0;

  // get the type
  inBuf = asn_parse_header( inBuf, &inBufLength, &type);
  if (inBuf == NULL){
    debugprintf(0, "snmp_parse: bad header");
    return SNMPv3_MP_PARSE_ERROR;
  }

  if (type != (ASN_SEQ_CON)){
    debugprintf(0, "snmp_parse: wrong auth header type");
    return SNMPv3_MP_PARSE_ERROR;
  }

  if (origLength != inBufLength + (inBuf - inBufPtr)) {
    debugprintf(0, "snmp_parse: wrong length of received packet");
    return SNMPv3_MP_PARSE_ERROR;
  }

  // get the version
  inBuf = asn_parse_int(inBuf, &inBufLength, &type, &version);
  if (inBuf == NULL){
    debugprintf(0, "snmp_parse: bad parse of version");
    return SNMPv3_MP_PARSE_ERROR;
  }

  debugprintf(3, "Parsed length(%x), version(0x%lx)", inBufLength, version);

  if ( version != SNMP_VERSION_3 )
    return SNMPv3_MP_PARSE_ERROR;

  spp_version = (snmp_version) version;

  inBuf = asn1_parse_header_data(inBuf, &inBufLength,
				 &msgID, &msgMaxSize,
				 &msgFlags, &msgSecurityModel);

  if (inBuf == NULL){
    debugprintf(0, "snmp_parse: bad parse of msgHeaderData");
    return SNMPv3_MP_PARSE_ERROR;
  }

  pdu->msgid = msgID;
  if ((msgMaxSize < 484) || (msgMaxSize > 0x7FFFFFFF)) {
    debugprintf(0, "snmp_parse: bad parse of msgMaxSize");
    return SNMPv3_MP_PARSE_ERROR;
  }

  // do not allow larger messages than this entity can handle
  if (msgMaxSize > MAX_SNMP_PACKET) msgMaxSize = MAX_SNMP_PACKET;
  pdu->maxsize_scopedpdu = msgMaxSize;

  inBuf = asn_parse_string( inBuf, &inBufLength, &type,
                            msgSecurityParameters.get_ptr(),
                            &msgSecurityParametersLength);

  if (inBuf == NULL){
    debugprintf(0, "snmp_parse: bad parse of msgSecurityParameters");
    return SNMPv3_MP_PARSE_ERROR;
  }

  securityParametersPosition= SAFE_INT_CAST(inBuf - inBufPtr) - msgSecurityParametersLength;

  // the rest of the message is passed directly to the security module

  msgDataLength = origLength - SAFE_INT_CAST(inBuf - inBufPtr);
  memcpy(msgData.get_ptr(), inBuf, msgDataLength);

  debugprintf(3, "Parsed msgdata length(0x%x), "
	      "msgSecurityParameters length(0x%x)", msgDataLength,
	      msgSecurityParametersLength);

  switch (msgFlags & 0x03) {
    case 3:  { securityLevel = SNMP_SECURITY_LEVEL_AUTH_PRIV;     break;}
    case 0:  { securityLevel = SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV; break;}
    case 1:  { securityLevel = SNMP_SECURITY_LEVEL_AUTH_NOPRIV;   break;}
    default: { securityLevel = SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV;
               snmpInvalidMsgs++;
               // do not send back report
               return SNMPv3_MP_INVALID_MESSAGE;
               //break;
             }
  }

  bool reportableFlag = ((msgFlags & 0x04) != 0);

  securityStateReference = usm->get_new_sec_state_reference();
  if (!securityStateReference)
    return SNMPv3_MP_ERROR;

  switch (msgSecurityModel) {
    case SNMP_SECURITY_MODEL_USM:
      {
        rc = usm->process_msg(
                           msgMaxSize,
                           msgSecurityParameters.get_ptr(),
			   msgSecurityParametersLength,
                           securityParametersPosition,
                           securityLevel,
                           inBufPtr, origLength, //wholeMsg
                           msgData.get_ptr(), msgDataLength,
                           securityEngineID,
                           securityName,
                           scopedPDU.get_ptr(), &scopedPDULength,
                           &maxSizeResponseScopedPDU,
                           securityStateReference,
			   from_address);
        pdu->maxsize_scopedpdu = maxSizeResponseScopedPDU;
        if (rc != SNMPv3_USM_OK) {
          if (rc == SNMPv3_USM_NOT_IN_TIME_WINDOW) {
            errorCode = SNMPv3_MP_NOT_IN_TIME_WINDOW;
          }
          else {
            // error handling! rfc2262 page 31
            debugprintf(0, "mp: error while executing USM::process_msg");
            errorCode = rc;
          }
        }
        if (errorCode != SNMPv3_USM_PARSE_ERROR)
          if (securityEngineID.len() == 0)
            errorCode = SNMPv3_MP_INVALID_ENGINEID;
        break;
      }
    default: {
        snmpUnknownSecurityModels++;
	usm->delete_sec_state_reference(securityStateReference);
        debugprintf(0, "SecurityModel of incomming Message not supported!");
        // Message should be dropped without a report
        return SNMPv3_MP_UNSUPPORTED_SECURITY_MODEL;
      }
  }
  // process scopedPDU
  debughexcprintf(21, "scoped PDU", scopedPDU.get_ptr(), scopedPDULength);

  unsigned char *scopedPDUPtr= scopedPDU.get_ptr();
  unsigned char tmp_contextEngineID[MAXLENGTH_ENGINEID];
  unsigned char tmp_contextName[MAXLENGTH_CONTEXT_NAME];
  int tmp_contextEngineIDLength = MAXLENGTH_ENGINEID;
  int tmp_contextNameLength     = MAXLENGTH_CONTEXT_NAME;

  debugprintf(1,"ErrorCode is %i",errorCode);

  if (!errorCode) {
    unsigned char *data = asn1_parse_scoped_pdu(scopedPDUPtr, &scopedPDULength,
                                                tmp_contextEngineID,
                                                &tmp_contextEngineIDLength,
                                                tmp_contextName, &tmp_contextNameLength);
    if (!data)
    {
      debugprintf(0, "mp: Error Parsing scopedPDU!");
      usm->delete_sec_state_reference(securityStateReference);
      return SNMPv3_MP_PARSE_ERROR;
    }
    int dataLength = scopedPDULength;
    contextEngineID.set_data(tmp_contextEngineID, tmp_contextEngineIDLength);
    contextName.set_data(tmp_contextName, tmp_contextNameLength);

    // parse data of scopedPDU
    if (snmp_parse_data_pdu(pdu, data, dataLength) != SNMP_CLASS_SUCCESS) {
      debugprintf(0, "mp: Error parsing PDU!");
      usm->delete_sec_state_reference(securityStateReference);
      return SNMPv3_MP_PARSE_ERROR;
    }
    if (SNMP_CLASS_SUCCESS != snmp_parse_vb(pdu, data, dataLength)) {
      debugprintf(0, "mp: Error parsing Vb");
      usm->delete_sec_state_reference(securityStateReference);
      return SNMPv3_MP_PARSE_ERROR;
    }
    if ((tmp_contextEngineIDLength == 0) &&
        ((pdu->command == GET_REQ_MSG) || (pdu->command == GETNEXT_REQ_MSG) ||
         (pdu->command == SET_REQ_MSG) || (pdu->command == GETBULK_REQ_MSG) ||
         (pdu->command == TRP_REQ_MSG) || (pdu->command == INFORM_REQ_MSG)  ||
         (pdu->command == TRP2_REQ_MSG)))
    {
      //  RFC 2572 ch. 4.2.2.1 (2a)
      debugprintf(2, "mp: received request message with zero length"
                  " contextEngineID -> unknownPduHandlers.");
      inc_stats_unknown_pdu_handlers();
      errorCode = SNMPv3_MP_UNKNOWN_PDU_HANDLERS;
    }
  }
  if (errorCode) {
    if ((reportableFlag) && (errorCode != SNMPv3_USM_PARSE_ERROR)) {
      // error occured: prepare reportpdu in agent
      cache.add_entry(msgID, pdu->reqid, securityEngineID,
                      msgSecurityModel,
                      securityName, securityLevel, "", "",
                      securityStateReference, errorCode, CACHE_REMOTE_REQ);

      send_report(scopedPDUPtr, scopedPDULength, pdu, errorCode,
		  securityLevel, msgSecurityModel, securityName,
		  from_address, snmp_session);
      clear_pdu(pdu, true);   // Clear pdu and free all content AND IDs!
    }
    else {
      usm->delete_sec_state_reference(securityStateReference);
    }
    return errorCode;
  }

  struct Cache::Entry_T centry;

  if ((pdu->command == GET_RSP_MSG) || (pdu->command == REPORT_MSG)) {
    rc = cache.get_entry(msgID, true, &centry);
    if (rc != SNMPv3_MP_OK) {
      // RFC 2572 ch. 4
      debugprintf(2, "Received rspMsg without outstanding request."
                  " -> SnmpUnknownPduHandler");
      usm->delete_sec_state_reference(securityStateReference);
      inc_stats_unknown_pdu_handlers();
      return SNMPv3_MP_UNKNOWN_PDU_HANDLERS;
    }
    if (((pdu->reqid == 0) || (pdu->reqid == 0x7fffffff))
	&& (pdu->command == REPORT_MSG))
      pdu->reqid = centry.req_id;
#ifdef BUGGY_REPORT_REQID
    if ((pdu->reqid != centry.req_id) && (pdu->command == REPORT_MSG))
    {
      debugprintf(0, "WARNING: setting reqid of REPORT PDU (from) (to): (%ld) (%ld)",  pdu->reqid, centry.req_id);
      pdu->reqid = centry.req_id;
    }
#endif
  }

  if (pdu->command == REPORT_MSG) {
    // !! rfc2262 page 33

    debugprintf(2, "*** Receiving a ReportPDU ***");
    if (/*((securityEngineID != centry.sec_engine_id)
	  && (centry.sec_engine_id.len() != 0)) ||*/
        ((msgSecurityModel != centry.sec_model)
         && (msgSecurityModel != SNMP_SECURITY_MODEL_USM)) ||
        ((securityName != centry.sec_name)
         && (securityName.len() != 0)))
    {
      debugprintf(0, "Received report message doesn't match sent message!");
      usm->delete_sec_state_reference(securityStateReference);
      return SNMPv3_MP_MATCH_ERROR;
    }
    usm->delete_sec_state_reference(securityStateReference);
    cache.delete_content(centry);
    debugprintf(1, "mp finished (OK)");
    return SNMPv3_MP_OK;
  }

  if (pdu->command == GET_RSP_MSG) {
    if (((securityEngineID != centry.sec_engine_id)
         && (centry.sec_engine_id.len() != 0)) ||
        (msgSecurityModel != centry.sec_model) ||
        (securityName != centry.sec_name) ||
        (securityLevel != centry.sec_level) ||
        ((contextEngineID != centry.context_engine_id)
         && (centry.context_engine_id.len() != 0))||
        ((contextName != centry.context_name)
         && (centry.context_name.len() != 0))) {
      debugprintf(0, "Received response message doesn't match sent message!");
      usm->delete_sec_state_reference(securityStateReference);
      cache.delete_content(centry);
      return SNMPv3_MP_MATCH_ERROR;
    }
    usm->delete_sec_state_reference(securityStateReference);
    cache.delete_content(centry);
    debugprintf(1, "mp finished (OK)");
    return SNMPv3_MP_OK;
  }

  if ((pdu->command == GET_REQ_MSG) || (pdu->command == GETNEXT_REQ_MSG) ||
      (pdu->command == SET_REQ_MSG) || (pdu->command == GETBULK_REQ_MSG) ||
      (pdu->command == INFORM_REQ_MSG)) {
    if (securityEngineID.len() == 0) {
      debugprintf(2, "Received Message with engineID = 0.");
    }
    else {
      if (!(unsignedCharCompare(securityEngineID.data(), securityEngineID.len(),
                                own_engine_id, own_engine_id_len))) {
        debugprintf(0, "snmp_parse: securityEngineID doesn't match own_engine_id.");
	/* we are authoritative but engine id of message is wrong
	   if discovery in USM is enabled:
	   - remove automatically added illegal engine id from USM tables
	   - send a report
	*/
	if (usm->is_discovery_enabled())
	{
	  // TODO: try to remove engine id from USM
	  if (reportableFlag)
	  {
	    cache.add_entry(msgID, pdu->reqid, securityEngineID,
			    msgSecurityModel,
			    securityName, securityLevel, "", "",
			    securityStateReference,
			    SNMPv3_MP_INVALID_ENGINEID,
			    CACHE_REMOTE_REQ);

	    send_report(0, MAX_SNMP_PACKET, pdu, SNMPv3_MP_INVALID_ENGINEID,
			SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV, msgSecurityModel,
			securityName, from_address, snmp_session);
	    clear_pdu(pdu, true);  // Clear pdu and free all content AND IDs!
	  }
	  else
	  {
	    usm->delete_sec_state_reference(securityStateReference);
	  }
	  return SNMPv3_MP_INVALID_ENGINEID;
	}

        usm->delete_sec_state_reference(securityStateReference);
        return SNMPv3_MP_MATCH_ERROR;
      }
    }
    int ret = cache.add_entry(msgID, pdu->reqid, securityEngineID,
                              msgSecurityModel, securityName,
                              securityLevel, contextEngineID,
                              contextName, securityStateReference,
                              SNMPv3_MP_OK, CACHE_REMOTE_REQ);
    if (ret == SNMPv3_MP_DOUBLED_MESSAGE) {
      debugprintf(0, "*** received doubled message ***");
      // message will be ignored so return OK
      usm->delete_sec_state_reference(securityStateReference);
    }

    debugprintf(1, "mp: parsing finished (ok).");
    return SNMPv3_MP_OK;
  }

  if ((pdu->command == TRP_REQ_MSG) || (pdu->command == TRP2_REQ_MSG))
  {
    usm->delete_sec_state_reference(securityStateReference);
    return SNMPv3_MP_OK;
  }

  debugprintf(0, "mp error: This line should not be executed.");
  usm->delete_sec_state_reference(securityStateReference);
  return SNMPv3_MP_ERROR;
}


// Tests if the given buffer contains a SNMPv3-Message.
bool v3MP::is_v3_msg(unsigned char *buffer, int length)
{
  unsigned char type;
  long version;

  // get the type
  buffer = asn_parse_header(buffer, &length, &type);
  if (!buffer)
  {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 1);
    LOG("Testing for v3 message: Bad header");
    LOG_END;

    return false;
  }

  if (type != ASN_SEQ_CON)
  {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 1);
    LOG("Testing for v3 message: Wrong auth header type");
    LOG((int)type);
    LOG_END;

    return false;
  }

  // get the version
  buffer = asn_parse_int(buffer, &length, &type, &version);
  if (!buffer)
  {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 1);
    LOG("Testing for v3 message: Bad parse of version");
    LOG_END;

    return 0;
  }

  return (version == SNMP_VERSION_3);
}



// Do the complete process of encoding the given values into the buffer
// ready to send to the target.
int v3MP::snmp_build(struct snmp_pdu *pdu,
		     unsigned char *packet,
		     int *out_length,             // maximum Bytes in packet
		     const OctetStr &securityEngineID,
		     const OctetStr &securityName,
		     int securityModel,
		     int securityLevel,
		     const OctetStr &contextEngineID,
		     const OctetStr &contextName)
{
  Buffer<unsigned char> scopedPDU(MAX_SNMP_PACKET);
  unsigned char *scopedPDUPtr = scopedPDU.get_ptr();
  unsigned char globalData[MAXLENGTH_GLOBALDATA];
  int globalDataLength = MAXLENGTH_GLOBALDATA;
  int scopedPDULength, maxLen = *out_length;
  Buffer<unsigned char> buf(MAX_SNMP_PACKET);
  unsigned char *bufPtr = buf.get_ptr();
  long bufLength = 0, rc;
  int msgID;
  int cachedErrorCode = SNMPv3_MP_OK;
  struct SecurityStateReference *securityStateReference = NULL;
  int isRequestMessage = 0;

  if ((pdu->command == GET_REQ_MSG) || (pdu->command == GETNEXT_REQ_MSG) ||
      (pdu->command == SET_REQ_MSG) || (pdu->command == GETBULK_REQ_MSG) ||
      (pdu->command == TRP_REQ_MSG) || (pdu->command == INFORM_REQ_MSG)  ||
      (pdu->command == TRP2_REQ_MSG))
    isRequestMessage = 1;

  if (isRequestMessage) {
    if (securityEngineID.len() == 0) {
      // First Contact => use user  noAuthNoPriv and USM
      securityLevel = SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV;
      securityModel = SNMP_SECURITY_MODEL_USM;
    }

    cur_msg_id_lock.lock();
    msgID = cur_msg_id;
    cur_msg_id++;
    if (cur_msg_id >= MAX_MPMSGID)
      cur_msg_id = 1;
    cur_msg_id_lock.unlock();

#ifdef INVALID_MSGID
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("*** WARNING: Using constant MessageID! ***");
    LOG_END;

    msgID = 0xdead;
#endif

    if (securityEngineID.len() == 0) {
      // length==0 => SecurityLevel == noAuthNoPriv
      //  => we do not send any management information
      //  => delete VariableBinding
      clear_pdu(pdu);
    }
  }
  else {
    // it is a response => search for request
    debugprintf(3, "Looking up cache");
    msgID = pdu->msgid;
    rc = cache.get_entry(msgID, CACHE_REMOTE_REQ,
                         &cachedErrorCode, &securityStateReference);

    if (rc != SNMPv3_MP_OK) {

      debugprintf(0, "mp: Cache lookup error");
      return SNMPv3_MP_MATCH_ERROR;
    }
  }

  LOG_BEGIN(loggerModuleName, DEBUG_LOG | 5);
  LOG("v3MP: Building message with (SecurityEngineID) (securityName) (securityLevel) (contextEngineID) (contextName)");
  LOG(securityEngineID.get_printable());
  LOG(securityName.get_printable());
  LOG(securityLevel);
  LOG(contextEngineID.get_printable());
  LOG(contextName.get_printable());
  LOG_END;

  // encode vb in buf
  scopedPDUPtr = build_vb(pdu, scopedPDUPtr, &maxLen);
  if (!scopedPDUPtr)
  {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 1);
    LOG("v3MP: Error encoding vbs into buffer");
    LOG_END;

    return SNMPv3_MP_BUILD_ERROR;
  }
  scopedPDULength = SAFE_INT_CAST(scopedPDUPtr - scopedPDU.get_ptr());

  //build dataPDU in buf
  maxLen = *out_length;
  scopedPDUPtr = scopedPDU.get_ptr();
  bufPtr = build_data_pdu(pdu, bufPtr, &maxLen, scopedPDUPtr, scopedPDULength);

  if (!bufPtr)
  {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 1);
    LOG("v3MP: Error encoding data pdu into buffer");
    LOG_END;

    return SNMPv3_MP_BUILD_ERROR;
  }

  bufLength = SAFE_INT_CAST(bufPtr - buf.get_ptr());

  //  serialize scopedPDU
  maxLen = *out_length;
  scopedPDUPtr = asn1_build_scoped_pdu(scopedPDUPtr, &maxLen,
				       contextEngineID.data(),
				       contextEngineID.len(),
				       contextName.data(), contextName.len(),
				       buf.get_ptr(), bufLength);

  if (!scopedPDUPtr)
  {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 1);
    LOG("v3MP: Error encoding scoped pdu into buffer");
    LOG_END;

    return SNMPv3_MP_BUILD_ERROR;
  }

  scopedPDULength = SAFE_INT_CAST(scopedPDUPtr - scopedPDU.get_ptr());

  // build msgGlobalData
  unsigned char *globalDataPtr = (unsigned char *)&globalData;
  unsigned char msgFlags;
  switch (securityLevel) {
    case SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV:
      { msgFlags = 0 ; break;}
    case SNMP_SECURITY_LEVEL_AUTH_NOPRIV:
      { msgFlags = SNMPv3_AUTHFLAG; break;}
    case SNMP_SECURITY_LEVEL_AUTH_PRIV:
      { msgFlags = SNMPv3_AUTHFLAG | SNMPv3_PRIVFLAG; break;}
    default:
    {
      LOG_BEGIN(loggerModuleName, WARNING_LOG | 1);
      LOG("v3MP: Unknown security level requested, will use authPriv");
      LOG(securityLevel);
      LOG_END;

      msgFlags = SNMPv3_AUTHFLAG | SNMPv3_PRIVFLAG;
    }
  }

  if ((pdu->command == GET_REQ_MSG) || (pdu->command == GETNEXT_REQ_MSG) ||
      (pdu->command == SET_REQ_MSG) || (pdu->command == GETBULK_REQ_MSG) ||
      (pdu->command == INFORM_REQ_MSG))
    msgFlags = msgFlags | SNMPv3_REPORTABLEFLAG;

  globalDataPtr = asn1_build_header_data(globalDataPtr, &globalDataLength,
					 msgID, *out_length,  // maxMessageSize
					 msgFlags, securityModel);
  if (!globalDataPtr)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("v3MP: Error building header data");
    LOG_END;

    return SNMPv3_MP_BUILD_ERROR;
  }
  globalDataLength = SAFE_INT_CAST(globalDataPtr - (unsigned char *)&globalData);

  switch (securityModel) {
    case SNMP_SECURITY_MODEL_USM: {
      int use_own_engine_id = 0;
      if ((pdu->command == TRP_REQ_MSG) || (pdu->command == GET_RSP_MSG) ||
          (pdu->command == REPORT_MSG)  || (pdu->command == TRP2_REQ_MSG)) {
        use_own_engine_id = 1;
      }

      rc = usm->generate_msg(globalData, globalDataLength, *out_length,
                             (use_own_engine_id ?
                                        own_engine_id_oct : securityEngineID),
                             securityName, securityLevel,
                             scopedPDU.get_ptr(), scopedPDULength,
                             securityStateReference, packet, out_length);

      if ( rc == SNMPv3_USM_OK ) {
        // build cache
        if (!((pdu->command == TRP_REQ_MSG) || (pdu->command == GET_RSP_MSG) ||
              (pdu->command == REPORT_MSG) || (pdu->command == TRP2_REQ_MSG)))
          cache.add_entry(msgID, pdu->reqid, securityEngineID,
                          securityModel, securityName, securityLevel,
                          contextEngineID, contextName, securityStateReference,
                          SNMPv3_MP_OK, CACHE_LOCAL_REQ);

	LOG_BEGIN(loggerModuleName, INFO_LOG | 3);
	LOG("v3MP: Message built OK");
	LOG_END;

        return SNMPv3_MP_OK;
      }
      else
      {
	LOG_BEGIN(loggerModuleName, WARNING_LOG | 1);
	LOG("v3MP: Returning error for building message");
	LOG(rc);
	LOG_END;

        return rc;
      }
    }
    default:
    {
      LOG_BEGIN(loggerModuleName, WARNING_LOG | 1);
      LOG("v3MP: Should build message with unsupported securityModel");
      LOG(securityModel);
      LOG_END;

      return SNMPv3_MP_UNSUPPORTED_SECURITY_MODEL;
    }
  }
}

#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif 

#endif
