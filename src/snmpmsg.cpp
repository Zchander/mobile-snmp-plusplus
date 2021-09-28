/*_############################################################################
  _## 
  _##  snmpmsg.cpp  
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

  Copyright (c) 1996
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

  SNMP++ S N M P M S G . C P P

  SNMPMESSAGE CLASS DEFINITION

  DESIGN + AUTHOR:  Peter E Mellquist

  DESCRIPTION:      ASN.1	encoding / decoding class
=====================================================================*/
char snmpmsg_cpp_version[]="#(@) SNMP++ $Id$";

#include <libsnmp.h>

#include <snmp_pp/uxsnmp.h>
#include "snmp_pp/config_snmp_pp.h"
#include "snmp_pp/snmpmsg.h"                    // header file for SnmpMessage
#include "snmp_pp/oid_def.h"                    // changed (Frank Fock)
#include "snmp_pp/log.h"
#include "snmp_pp/vb.h"
#include "snmp_pp/usm_v3.h"

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

static const char *loggerModuleName = "snmp++.snmpmsg";

#define MAX_LEN_COMMUNITY 254

const coldStartOid coldStart;
const warmStartOid warmStart;
const linkDownOid linkDown;
const linkUpOid linkUp;
const authenticationFailureOid authenticationFailure;
const egpNeighborLossOid egpNeighborLoss;
const snmpTrapEnterpriseOid snmpTrapEnterprise;

//------------[ convert SNMP++ VB to WinSNMP smiVALUE ]----------------
int convertVbToSmival(const Vb &tempvb, SmiVALUE *smival)
{
  smival->syntax = tempvb.get_syntax();
  switch (smival->syntax) {

    // case sNMP_SYNTAX_NULL
  case sNMP_SYNTAX_NULL:
  case sNMP_SYNTAX_NOSUCHOBJECT:
  case sNMP_SYNTAX_NOSUCHINSTANCE:
  case sNMP_SYNTAX_ENDOFMIBVIEW:
    break;

    // case sNMP_SYNTAX_INT32:
  case sNMP_SYNTAX_INT:
    tempvb.get_value(smival->value.sNumber);
    break;

    //    case sNMP_SYNTAX_UINT32:
  case sNMP_SYNTAX_GAUGE32:
  case sNMP_SYNTAX_CNTR32:
  case sNMP_SYNTAX_TIMETICKS:
    //  case sNMP_SYNTAX_UINT32:
    tempvb.get_value(smival->value.uNumber);
    break;

    // case Counter64
  case sNMP_SYNTAX_CNTR64:
    {
      Counter64 c64;
      tempvb.get_value(c64);
      smival->value.hNumber.hipart = c64.high();
      smival->value.hNumber.lopart = c64.low();
    }
    break;

  case sNMP_SYNTAX_BITS:
  case sNMP_SYNTAX_OCTETS:
  case sNMP_SYNTAX_OPAQUE:
  case sNMP_SYNTAX_IPADDR:
    {
      OctetStr os;
      tempvb.get_value(os);
      smival->value.string.ptr = NULL;
      smival->value.string.len = os.len();
      if (smival->value.string.len > 0)
      {
        smival->value.string.ptr
          = (SmiLPBYTE) new  unsigned char [smival->value.string.len];
        if (smival->value.string.ptr)
        {
          for (int i=0; i<(int) smival->value.string.len ; i++)
            smival->value.string.ptr[i] = os[i];
        }
        else
        {
          smival->syntax = sNMP_SYNTAX_NULL;  // invalidate the smival
          return SNMP_CLASS_RESOURCE_UNAVAIL;
        }
      }
    }
    break;

  case sNMP_SYNTAX_OID:
    {
      Oid oid;
      tempvb.get_value(oid);
      smival->value.oid.ptr = NULL;
      smival->value.oid.len = oid.len();
      if (smival->value.oid.len > 0)
      {
        smival->value.oid.ptr
          = (SmiLPUINT32) new unsigned long [ smival->value.oid.len];
        if (smival->value.oid.ptr)
        {
          for (int i=0; i<(int)smival->value.oid.len ; i++)
            smival->value.oid.ptr[i] = oid[i];
        }
        else
        {
          smival->syntax = sNMP_SYNTAX_NULL;  // invalidate the smival
          return SNMP_CLASS_RESOURCE_UNAVAIL;
        }
      }
    }
    break;

  default:
    return SNMP_CLASS_INTERNAL_ERROR;
  }
  return SNMP_CLASS_SUCCESS;
}

// free a SMI value
void freeSmivalDescriptor(SmiVALUE *smival)
{
  switch (smival->syntax) {
  case sNMP_SYNTAX_OCTETS:
  case sNMP_SYNTAX_OPAQUE:
  case sNMP_SYNTAX_IPADDR:
  case sNMP_SYNTAX_BITS:		    // obsoleted in SNMPv2 Draft Std
    delete [] smival->value.string.ptr;
    break;

  case sNMP_SYNTAX_OID:
    delete [] smival->value.oid.ptr;
    break;
  }
  smival->syntax = sNMP_SYNTAX_NULL;
}

#ifdef _SNMPv3

int SnmpMessage::unloadv3(Pdu &pdu,                // Pdu returned
                          snmp_version &version,   // version
                          OctetStr &engine_id,     // optional v3
                          OctetStr &security_name, // optional v3
                          long int &security_model,
                          UdpAddress &from_addr,
			  Snmp &snmp_session)
{
  OctetStr tmp;
  return unload(pdu, tmp, version, &engine_id,
                &security_name, &security_model, &from_addr, &snmp_session);
}

#endif

int SnmpMessage::load(
#ifdef _SNMPv3
                      v3MP* mpv3, 
#endif
                      const Pdu &cpdu,
                      const OctetStr &community,
                      const snmp_version version,
                      const OctetStr* engine_id,
                      const OctetStr* security_name,
                      const int security_model)
{
  int status;
  const Pdu *pdu = &cpdu;
  Pdu temppdu;

  // make sure pdu is valid
  if (!pdu->valid())
    return SNMP_CLASS_INVALID_PDU;

  // create a raw pdu
  snmp_pdu *raw_pdu;
  raw_pdu = snmp_pdu_create((int) pdu->get_type());

  Oid enterprise;

  // load it up
  raw_pdu->reqid = pdu->get_request_id();
#ifdef _SNMPv3
  raw_pdu->msgid = pdu->get_message_id();
#endif
  raw_pdu->errstat= (unsigned long) pdu->get_error_status();
  raw_pdu->errindex= (unsigned long) pdu->get_error_index();

  // if its a V1 trap then load up other values
  // for v2, use normal pdu format
  if (raw_pdu->command == sNMP_PDU_V1TRAP)
  {
    // DON'T forget about the v1 trap agent address (changed by Frank Fock)
    GenAddress gen_addr;
    IpAddress ip_addr;
    bool addr_set = false;

    if (pdu->get_v1_trap_address(gen_addr))
    {
      /* User did set the v1 trap address */
      if ((gen_addr.get_type() != Address::type_ip) &&
          (gen_addr.get_type() != Address::type_udp))
      {
	LOG_BEGIN(loggerModuleName, ERROR_LOG | 4);
        LOG("SNMPMessage: Bad v1 trap address type in pdu");
        LOG(gen_addr.get_type());
        LOG_END;

        snmp_free_pdu(raw_pdu);
        return SNMP_CLASS_INVALID_PDU;
      }

      ip_addr = gen_addr;
      if (!ip_addr.valid())
      {
	LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
        LOG("SNMPMessage: Copied v1 trap address not valid");
        LOG_END;

        snmp_free_pdu(raw_pdu);
        return SNMP_CLASS_RESOURCE_UNAVAIL;
      }
      addr_set = true;
    }
    else
    {
      /* User did not set the v1 trap address */
      char addrString[256];
      if (gethostname(addrString, 255) == 0)
      {
          ip_addr = addrString;
          addr_set = true;
      }
    }
    struct sockaddr_in agent_addr;  // agent address socket struct
    // prepare the agent address
    memset(&agent_addr, 0, sizeof(agent_addr));
    agent_addr.sin_family = AF_INET;
    if (addr_set)
    {
      agent_addr.sin_addr.s_addr
        = inet_addr(((IpAddress &)ip_addr).IpAddress::get_printable());
      LOG_BEGIN(loggerModuleName, INFO_LOG | 7);
      LOG("SNMPMessage: Setting v1 trap address");
      LOG(((IpAddress &)ip_addr).IpAddress::get_printable());
      LOG_END;
    }
    raw_pdu->agent_addr = agent_addr;

    //-----[ compute generic trap value ]-------------------------------
    // determine the generic value
    // 0 - cold start
    // 1 - warm start
    // 2 - link down
    // 3 - link up
    // 4 - authentication failure
    // 5 - egpneighborloss
    // 6 - enterprise specific
    Oid trapid;
    pdu->get_notify_id(trapid);
    if (!trapid.valid() || trapid.len() < 2)
    {
        snmp_free_pdu( raw_pdu);
        return SNMP_CLASS_INVALID_NOTIFYID;
    }
    raw_pdu->specific_type=0;
    if (trapid == coldStart)
      raw_pdu->trap_type = 0;  // cold start
    else if (trapid == warmStart)
      raw_pdu->trap_type = 1;  // warm start
    else if (trapid == linkDown)
      raw_pdu->trap_type = 2;  // link down
    else if (trapid == linkUp)
      raw_pdu->trap_type = 3;  // link up
    else if (trapid == authenticationFailure)
      raw_pdu->trap_type = 4;  // authentication failure
    else if (trapid == egpNeighborLoss)
      raw_pdu->trap_type = 5;  // egp neighbor loss
    else {
      raw_pdu->trap_type = 6;     // enterprise specific
      // last oid subid is the specific value
      // if 2nd to last subid is "0", remove it
      // enterprise is always the notify oid prefix
      raw_pdu->specific_type = (int) trapid[(int) (trapid.len()-1)];

      trapid.trim(1);
      if (trapid[(int)(trapid.len()-1)] == 0)
        trapid.trim(1);
      enterprise = trapid;
    }

    if (raw_pdu->trap_type != 6)
      pdu->get_notify_enterprise(enterprise);
    if (enterprise.len() >0) {
      // note!!
      // these are hooks into an SNMP++ oid
      // and therefor the raw_pdu enterprise
      // should not free them. null them out!!
      SmiLPOID rawOid;
      rawOid = enterprise.oidval();
      raw_pdu->enterprise = rawOid->ptr;
      raw_pdu->enterprise_length = (int) rawOid->len;
    }

    // timestamp
    TimeTicks timestamp;
    pdu->get_notify_timestamp(timestamp);
    raw_pdu->time = (unsigned long) timestamp;
  }

  // if its a v2 trap then we need to make a few adjustments
  // vb #1 is the timestamp
  // vb #2 is the id, represented as an Oid
  if ((raw_pdu->command == sNMP_PDU_TRAP) ||
      (raw_pdu->command == sNMP_PDU_INFORM))
  {
    Vb tempvb;

    temppdu = *pdu;
    temppdu.trim(temppdu.get_vb_count());

    // vb #1 is the timestamp
    TimeTicks timestamp;
    tempvb.set_oid(SNMP_MSG_OID_SYSUPTIME);   // sysuptime
    pdu->get_notify_timestamp(timestamp);
    tempvb.set_value(timestamp);
    temppdu += tempvb;

    // vb #2 is the id
    Oid trapid;
    tempvb.set_oid(SNMP_MSG_OID_TRAPID);
    pdu->get_notify_id(trapid);
    tempvb.set_value(trapid);
    temppdu += tempvb;

    // append the remaining vbs
    for (int z=0; z<pdu->get_vb_count(); z++) {
      pdu->get_vb(tempvb,z);
      temppdu += tempvb;
    }

    pdu = &temppdu;          // reassign the pdu to the temp one
  }
  // load up the payload
  // for all Vbs in list, add them to the pdu
  int vb_count;
  Vb tempvb;
  Oid tempoid;
  SmiLPOID smioid;
  SmiVALUE smival;

  vb_count = pdu->get_vb_count();
  for (int z=0;z<vb_count;z++) {
    pdu->get_vb(tempvb,z);
    tempvb.get_oid(tempoid);
    smioid = tempoid.oidval();
    // clear the value portion, in case its
    // not already been done so by the app writer
    // only do it in the case its a get,next or bulk
    if ((raw_pdu->command == sNMP_PDU_GET) ||
        (raw_pdu->command == sNMP_PDU_GETNEXT) ||
        (raw_pdu->command == sNMP_PDU_GETBULK))
      tempvb.set_null();
    status = convertVbToSmival(tempvb, &smival);
    if (status != SNMP_CLASS_SUCCESS) {
      snmp_free_pdu(raw_pdu);
      return status;
    }
    // add the vb to the raw pdu
    snmp_add_var(raw_pdu, smioid->ptr, (int) smioid->len, &smival);

    freeSmivalDescriptor(&smival);
  }

  // ASN1 encode the pdu
#ifdef _SNMPv3
  if (version == version3)
  {
    if ((!engine_id) || (!security_name))
    {
      LOG_BEGIN(loggerModuleName, ERROR_LOG | 4);
      LOG("SNMPMessage: Need security name and engine id for v3 message");
      LOG_END;

      // prevention of SNMP++ Enterprise Oid death
      if (enterprise.len() >0) {
        raw_pdu->enterprise = 0;
        raw_pdu->enterprise_length=0;
      }
      snmp_free_pdu(raw_pdu);
      return SNMP_CLASS_INVALID_TARGET;
    }

    status = mpv3->snmp_build(raw_pdu, databuff, (int *)&bufflen,
                                 *engine_id, *security_name, security_model,
                                 pdu->get_security_level(),
                                 pdu->get_context_engine_id(),
                                 pdu->get_context_name());
    if (status == SNMPv3_MP_OK) {
      if ((pdu->get_type() == sNMP_PDU_RESPONSE) &&
          ((int)pdu->get_maxsize_scopedpdu() < pdu->get_asn1_length())) {

	LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
        LOG("SNMPMessage: *BUG*: Serialized response pdu is too big (len) (max)");
        LOG(pdu->get_asn1_length());
        LOG(pdu->get_maxsize_scopedpdu());
        LOG_END;

        // prevention of SNMP++ Enterprise Oid death
        if (enterprise.len() >0) {
          raw_pdu->enterprise = 0;
          raw_pdu->enterprise_length=0;
        }
        snmp_free_pdu(raw_pdu);
        return SNMP_ERROR_TOO_BIG;
      }
    }
  }
  else
#endif
  status = snmp_build(raw_pdu, databuff, (int *) &bufflen, version,
                      community.data(), (int) community.len());

  LOG_BEGIN(loggerModuleName, DEBUG_LOG | 4);
  LOG("SNMPMessage: return value for build message");
  LOG(status);
  LOG_END;

  if ((status != 0)
#ifdef _SNMPv3
      && ((version != version3) || (status != SNMPv3_MP_OK))
#endif
      ) {
    valid_flag = false;
    // prevention of SNMP++ Enterprise Oid death
    if (enterprise.len() >0) {
      raw_pdu->enterprise = 0;
      raw_pdu->enterprise_length=0;
    }
    snmp_free_pdu(raw_pdu);
#ifdef _SNMPv3
    if (version == version3)
      return status;
    else
#endif
      // NOTE: This is an assumption - in most cases during normal
      // operation the reason is a tooBig - another could be a
      // damaged variable binding.
      return SNMP_ERROR_TOO_BIG;
  }
  valid_flag = true;

  // prevention of SNMP++ Enterprise Oid death
  if (enterprise.len() >0) {
    raw_pdu->enterprise = 0;
    raw_pdu->enterprise_length=0;
  }

  snmp_free_pdu(raw_pdu);

  return SNMP_CLASS_SUCCESS;
}

// load up a SnmpMessage
int SnmpMessage::load(unsigned char *data,
                       unsigned long len)
{
  bufflen = MAX_SNMP_PACKET;
  valid_flag = false;

  if (len <= MAX_SNMP_PACKET)
  {
    memcpy((unsigned char *) databuff, (unsigned char *) data,
            (unsigned int) len);
    bufflen = len;
    valid_flag = true;
  }
  else
    return SNMP_ERROR_WRONG_LENGTH;

  return SNMP_CLASS_SUCCESS;
}

// unload the data into SNMP++ objects
int SnmpMessage::unload(Pdu &pdu,                 // Pdu object
			OctetStr &community,      // community object
			snmp_version &version,    // SNMP version #
                        OctetStr *engine_id,      // optional v3
                        OctetStr *security_name,  // optional v3
                        long int *security_model,
                        UdpAddress *from_addr,
                        Snmp *snmp_session)
{
  pdu.clear();

  if (!valid_flag)
    return SNMP_CLASS_INVALID;

  snmp_pdu *raw_pdu = snmp_pdu_create(0); // free with snmp_free_pdu(raw_pdu)
  int status;

#ifdef _SNMPv3
  if ((security_model) && (security_name) && (engine_id) && (snmp_session))
  {
    long int security_level = SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV;
    OctetStr context_name;
    OctetStr context_engine_id;
    status = snmp_session->get_mpv3()->snmp_parse(snmp_session, raw_pdu,
                         databuff, (int)bufflen, *engine_id,
                         *security_name, context_engine_id, context_name,
                         security_level, *security_model, version, *from_addr);
    if (status != SNMPv3_MP_OK)
    {
      pdu.set_request_id(raw_pdu->reqid);
      pdu.set_type(raw_pdu->command);
      snmp_free_pdu(raw_pdu);
      return status;
    }
    pdu.set_context_engine_id(context_engine_id);
    pdu.set_context_name(context_name);
    pdu.set_security_level(security_level);
    pdu.set_message_id(raw_pdu->msgid);
    pdu.set_maxsize_scopedpdu(raw_pdu->maxsize_scopedpdu);
  }
  else
#endif
  {
    unsigned char community_name[MAX_LEN_COMMUNITY + 1];
    int           community_len = MAX_LEN_COMMUNITY + 1;

    status = snmp_parse(raw_pdu, databuff, (int) bufflen,
                        community_name, community_len, version);
    if (status != SNMP_CLASS_SUCCESS)
    {
      snmp_free_pdu(raw_pdu);
      return status;
    }
    community.set_data(community_name, community_len);
  }

  // load up the SNMP++ variables
  pdu.set_request_id(raw_pdu->reqid);
  pdu.set_error_status((int) raw_pdu->errstat);
  pdu.set_error_index((int) raw_pdu->errindex);
  pdu.set_type(raw_pdu->command);

  // deal with traps a little different
  if (raw_pdu->command == sNMP_PDU_V1TRAP) {
    // timestamp
    TimeTicks timestamp;
    timestamp = raw_pdu->time;
    pdu.set_notify_timestamp(timestamp);

    // set the agent address
    IpAddress agent_addr(inet_ntoa(raw_pdu->agent_addr.sin_addr));
    if (agent_addr != "0.0.0.0")
    {
      pdu.set_v1_trap_address(agent_addr);

      LOG_BEGIN(loggerModuleName, DEBUG_LOG | 4);
      LOG("SNMPMessage: Trap address of received v1 trap");
      LOG(agent_addr.get_printable());
      LOG_END;
    }

    // set enterprise, notifyid
    Oid enterprise;

    if (raw_pdu->enterprise_length >0) {
      for (int i=0; i< raw_pdu->enterprise_length; i++) {
        enterprise += (int) (raw_pdu->enterprise[i]);
      }
      pdu.set_notify_enterprise(enterprise);
    }
    switch (raw_pdu->trap_type) {
    case 0:
      pdu.set_notify_id(coldStart);
      break;

    case 1:
      pdu.set_notify_id(warmStart);
      break;

    case 2:
      pdu.set_notify_id(linkDown);
      break;

    case 3:
      pdu.set_notify_id(linkUp);
      break;

    case 4:
      pdu.set_notify_id(authenticationFailure);
      break;

    case 5:
      pdu.set_notify_id(egpNeighborLoss);
      break;

    case 6: { // enterprise specific
      // base id + specific #
      Oid eOid = enterprise;
      eOid += 0ul;
      eOid += raw_pdu->specific_type;
      pdu.set_notify_id(eOid);
      break;
      }
    default:
      {
	LOG_BEGIN(loggerModuleName, WARNING_LOG | 3);
	LOG("SNMPMessage: Received trap with illegal trap type");
	LOG(raw_pdu->trap_type);
	LOG_END;
      }
    }
  }

  // vbs
  Vb tempvb;
  Oid tempoid;
  struct   variable_list *vp;
  int vb_nr = 1;

  for(vp = raw_pdu->variables; vp; vp = vp->next_variable, vb_nr++) {

    // extract the oid portion
    tempoid.set_data((unsigned long *)vp->name,
                     (unsigned int) vp->name_length);
    tempvb.set_oid(tempoid);

    // extract the value portion
    switch(vp->type){

      // octet string
    case sNMP_SYNTAX_OCTETS:
      {
	OctetStr octets((unsigned char *) vp->val.string,
			 (unsigned long) vp->val_len);
	tempvb.set_value(octets);
      }
      break;
    case sNMP_SYNTAX_OPAQUE:
      {
	OpaqueStr octets((unsigned char *) vp->val.string,
		         (unsigned long) vp->val_len);
	tempvb.set_value(octets);
      }
      break;

      // object id
    case sNMP_SYNTAX_OID:
      {
	Oid oid((unsigned long*) vp->val.objid,
		(int) vp->val_len);
	tempvb.set_value(oid);
        if ((vb_nr == 2) &&
            ((raw_pdu->command == sNMP_PDU_TRAP) ||
             (raw_pdu->command == sNMP_PDU_INFORM)) &&
            (tempoid == SNMP_MSG_OID_TRAPID))
        {
          // set notify_id
          pdu.set_notify_id(oid);
	  continue; // don't add vb to pdu
        }
      }
      break;

      // timeticks
    case sNMP_SYNTAX_TIMETICKS:
      {
	TimeTicks timeticks((unsigned long) *(vp->val.integer));
	tempvb.set_value(timeticks);
        if ((vb_nr == 1) &&
            ((raw_pdu->command == sNMP_PDU_TRAP) ||
             (raw_pdu->command == sNMP_PDU_INFORM)) &&
            (tempoid == SNMP_MSG_OID_SYSUPTIME))
        {
          // set notify_timestamp
          pdu.set_notify_timestamp(timeticks);
	  continue; // don't add vb to pdu
        }
      }
      break;

      // 32 bit counter
    case sNMP_SYNTAX_CNTR32:
      {
	Counter32 counter32((unsigned long) *(vp->val.integer));
	tempvb.set_value(counter32);
      }
      break;

      // 32 bit gauge
    case sNMP_SYNTAX_GAUGE32:
      {
	Gauge32 gauge32((unsigned long) *(vp->val.integer));
	tempvb.set_value(gauge32);
      }
      break;

      // ip address
    case sNMP_SYNTAX_IPADDR:
      {
	char buffer[42];
	buffer[0] = 0; // in case we receive an inavlid length IP

	if (vp->val_len == 16)
	  sprintf(buffer, "%02x%02x:%02x%02x:%02x%02x:%02x%02x:"
		  "%02x%02x:%02x%02x:%02x%02x:%02x%02x",
		  vp->val.string[ 0], vp->val.string[ 1], vp->val.string[ 2],
		  vp->val.string[ 3], vp->val.string[ 4], vp->val.string[ 5],
		  vp->val.string[ 6], vp->val.string[ 7], vp->val.string[ 8],
		  vp->val.string[ 9], vp->val.string[10], vp->val.string[11],
		  vp->val.string[12], vp->val.string[13], vp->val.string[14],
		  vp->val.string[15]);
	else if (vp->val_len == 4)
	  sprintf(buffer,"%d.%d.%d.%d",
		  vp->val.string[0], vp->val.string[1],
		  vp->val.string[2], vp->val.string[3]);
	IpAddress ipaddress(buffer);
	tempvb.set_value(ipaddress);
      }
      break;

      // 32 bit integer
    case sNMP_SYNTAX_INT:
      {
	SnmpInt32 int32((long) *(vp->val.integer));
	tempvb.set_value(int32);
      }
      break;

      // 32 bit unsigned integer
/* Not distinguishable from Gauge32
    case sNMP_SYNTAX_UINT32:
      {
	SnmpUInt32 uint32((unsigned long) *(vp->val.integer));
	tempvb.set_value(uint32);
      }
      break;
*/
      // v2 counter 64's
    case sNMP_SYNTAX_CNTR64:
      { // Frank Fock (was empty before)
	Counter64 c64(((counter64*)vp->val.counter64)->high,
		      ((counter64*)vp->val.counter64)->low);
	tempvb.set_value(c64);
	break;
      }
    case sNMP_SYNTAX_NULL:
	    tempvb.set_null();
	    break;
	
	    // v2 vb exceptions
    case sNMP_SYNTAX_NOSUCHOBJECT:
    case sNMP_SYNTAX_NOSUCHINSTANCE:
    case sNMP_SYNTAX_ENDOFMIBVIEW:
      tempvb.set_exception_status(vp->type);
      break;

    default:
      tempvb.set_null();

    } // end switch

    // append the vb to the pdu
    pdu += tempvb;
  }

  snmp_free_pdu(raw_pdu);

  return SNMP_CLASS_SUCCESS;
}

#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif 
