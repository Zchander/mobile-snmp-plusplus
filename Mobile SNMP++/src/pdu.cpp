/*_############################################################################
  _## 
  _##  pdu.cpp  
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


  P D U . C P P

  PDU CLASS IMPLEMENTATION

  DESIGN + AUTHOR:  Peter E Mellquist

  DESCRIPTION:
  Pdu class implementation. Encapsulation of an SMI Protocol
  Data Unit (PDU) in C++.

=====================================================================*/
char pdu_cpp_version[]="@(#) SNMP++ $Id: pdu.cpp 209 2006-01-07 20:02:34Z katz $";

#include "snmp_pp/pdu.h"       // include Pdu class definition
#include "snmp_pp/usm_v3.h"
#include "snmp_pp/vb.h"
#include "snmp_pp/v3.h"

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

#define PDU_INITIAL_SIZE 25

//=====================[ constructor no args ]=========================
Pdu::Pdu()
  : vbs(0), vbs_size(0), vb_count(0), error_status(0), error_index(0),
    validity(true), request_id(0), pdu_type(0), notify_timestamp(0),
    v1_trap_address_set(false)
#ifdef _SNMPv3
    , security_level(SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV),
    message_id(0), maxsize_scopedpdu(0)
#endif
{
}

//=====================[ constructor with vbs and count ]==============
Pdu::Pdu(Vb* pvbs, const int pvb_count)
  : vbs(0), vbs_size(0), vb_count(0), error_status(0), error_index(0),
    validity(true), request_id(0), pdu_type(0), notify_timestamp(0),
    v1_trap_address_set(false)
#ifdef _SNMPv3
    , security_level(SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV),
    message_id(0), maxsize_scopedpdu(0)
#endif
{
  if (pvb_count == 0) return;    // zero is ok

  vbs = new Vb*[pvb_count];
  if (vbs)
    vbs_size = pvb_count;
  else
  {
    vbs_size = 0;
    validity = false;
    return;
  }

  // loop through and assign internal vbs
  for (int z = 0; z < pvb_count; ++z)
  {
    if (pvbs[z].valid())
      vbs[z] = new Vb(pvbs[z]);
    else
      vbs[z] = 0;

    if ((vbs[z]) && !vbs[z]->valid())
    {
      delete vbs[z];
      vbs[z] = 0;
    }

    if (vbs[z] == 0)     // check for new fail
    {
      for (int y = 0; y < z; ++y) delete vbs[y]; // free vbs
      validity = false;
      return;
    }
  }

  vb_count = pvb_count;   // assign the vb count
}

//=====================[ destructor ]====================================
Pdu::~Pdu()
{
  for (int z = 0; z < vb_count; ++z)
  {
    delete vbs[z];
    vbs[z] = 0;
  }

  if (vbs)
  {
    delete [] vbs;
    vbs = 0;
    vbs_size = 0;
  }
}

//=====================[ assignment to another Pdu object overloaded ]===
Pdu& Pdu::operator=(const Pdu &pdu)
{
  if (this == &pdu) return *this; // check for self assignment

  // Initialize all mv's
  error_status      = pdu.error_status;
  error_index       = pdu.error_index;
  request_id        = pdu.request_id;
  pdu_type          = pdu.pdu_type;
  notify_id         = pdu.notify_id;
  notify_timestamp  = pdu.notify_timestamp;
  notify_enterprise = pdu.notify_enterprise;
#ifdef _SNMPv3
  security_level    = pdu.security_level;
  message_id        = pdu.message_id;
  context_name      = pdu.context_name;
  context_engine_id = pdu.context_engine_id;
  maxsize_scopedpdu = pdu.maxsize_scopedpdu;
#endif
  if (pdu.v1_trap_address_set)
  {
    v1_trap_address = pdu.v1_trap_address;
    v1_trap_address_set = true;
  }
  else
    v1_trap_address_set = false;

  validity = true;

  // free up old vbs
  for (int z = 0; z < vb_count; ++z)  delete vbs[z];
  vb_count = 0;

  // check for zero case
  if (pdu.vb_count == 0) return *this;

  // allocate array
  if (vbs_size < pdu.vb_count)
  {
    delete [] vbs;
    vbs = new Vb*[pdu.vb_count];
    if (vbs)
      vbs_size = pdu.vb_count;
    else
    {
      vbs_size = 0;
      validity = false;
      return *this;
    }
  }

  // loop through and fill em up
  for (int y = 0; y < pdu.vb_count; ++y)
  {
    vbs[y] = new Vb(*(pdu.vbs[y]));

    if ((vbs[y]) && !vbs[y]->valid())
    {
      delete vbs[y];
      vbs[y] = 0;
    }

    if (!vbs[y])
    {
      for (int x = 0; x < y; ++x) delete vbs[x]; // free vbs
      validity = false;
      return *this;
    }
  }

  vb_count = pdu.vb_count;
  return *this;
}

// append operator, appends a variable binding
Pdu& Pdu::operator+=(const Vb &vb)
{
  if (!vb.valid())                return *this; // dont add invalid Vbs

  if (vb_count + 1 > vbs_size)
  {
    if (!extend_vbs()) return *this;
  }

  vbs[vb_count] = new Vb(vb);  // add the new one

  if (vbs[vb_count])   // up the vb count on success
  {
    if (vbs[vb_count]->valid())
    {
      ++vb_count;
      validity = true;   // set up validity
    }
    else
    {
      delete vbs[vb_count];
      vbs[vb_count] = 0;
    }
  }

  return *this;        // return self reference
}

//=====================[ extract Vbs from Pdu ]==========================
int Pdu::get_vblist(Vb* pvbs, const int pvb_count) const
{
  if ((!pvbs) || (pvb_count < 0) || (pvb_count > vb_count))
    return false;

  // loop through all vbs and assign to params
  for (int z = 0; z < pvb_count; ++z)
  {
    pvbs[z] = *vbs[z];
    if (!pvbs[z].valid())
      return false;
  }

  return true;
}

//=====================[ deposit Vbs ]===================================
int Pdu::set_vblist(Vb* pvbs, const int pvb_count)
{
  // if invalid then don't destroy
  if (((!pvbs) && (pvb_count > 0)) ||
      (pvb_count < 0))
    return false;

  // free up current vbs
  for (int z = 0; z < vb_count; ++z)  delete vbs[z];
  vb_count = 0;

  // check for zero case
  if (pvb_count == 0)
  {
    validity = true;
    error_status = 0;
    error_index = 0;
    request_id = 0;
    return false;
  }

  // allocate array
  if (vbs_size < pvb_count)
  {
    delete [] vbs;
    vbs = new Vb*[pvb_count];
    if (vbs)
      vbs_size = pvb_count;
    else
    {
      vbs_size = 0;
      validity = false;
      return false;
    }
  }

  // loop through all vbs and reassign them
  for (int y = 0; y < pvb_count; ++y)
  {
    if (pvbs[y].valid())
    {
      vbs[y] = new Vb(pvbs[y]);
      if ((vbs[y]) && !vbs[y]->valid())
      {
	delete vbs[y];
	vbs[y] = 0;
      }
    }
    else
      vbs[y] = 0;

    // check for errors
    if (!vbs[y])
    {
      for (int x = 0; x < y; ++x) delete vbs[x]; // free vbs
      validity = false;
      return false;
    }
  }

  vb_count = pvb_count;

  // clear error status and index since no longer valid
  // request id may still apply so don't reassign it
  error_status = 0;
  error_index = 0;
  validity = true;

  return true;
}

//===================[ get a particular vb ]=============================
// here the caller has already instantiated a vb object
// index is zero based
int Pdu::get_vb(Vb &vb, const int index) const
{
   if (index < 0)         return false; // can't have an index less than 0
   if (index >= vb_count) return false; // can't ask for something not there

   vb = *vbs[index];   // asssign it

   return vb.valid();
}

//===================[ set a particular vb ]=============================
int Pdu::set_vb(Vb &vb, const int index)
{
  if (index < 0)         return false; // can't have an index less than 0
  if (index >= vb_count) return false; // can't ask for something not there
  if (!vb.valid())       return false; // don't set invalid vbs

  Vb *victim = vbs[index]; // save in case new fails
  vbs[index] = new Vb(vb);
  if (vbs[index])
  {
    if (vbs[index]->valid())
    {
      delete victim;
    }
    else
    {
      delete vbs[index];
      vbs[index] = victim;
      return false;
    }
  }
  else
  {
    vbs[index] = victim;
    return false;
  }
  return true;
}

// trim off the last vb
int Pdu::trim(const int count)
{
  // verify that count is legal
  if ((count < 0) || (count > vb_count)) return false;

  int lp = count;

  while (lp != 0)
  {
    if (vb_count > 0)
    {
      delete vbs[vb_count-1];
      vbs[vb_count-1] = 0;
      vb_count--;
    }
    lp--;
  }
  return true;
}

// delete a Vb anywhere within the Pdu
int Pdu::delete_vb(const int p)
{
  // position has to be in range
  if ((p<0) || (p > vb_count - 1)) return false;

  delete vbs[p];   // safe to remove it

  for (int z = p; z < vb_count - 1; ++z)
    vbs[z] = vbs[z+1];

  vb_count--;

  return true;
}


// Get the SNMPv1 trap address
int Pdu::get_v1_trap_address(GenAddress &address) const
{
  if (v1_trap_address_set == false)
    return false;

  address = v1_trap_address;
  return true;
}

// Set the SNMPv1 trap address
int Pdu::set_v1_trap_address(const Address &address)
{
  v1_trap_address = address;
  v1_trap_address_set = (v1_trap_address.valid() == true);

  return v1_trap_address_set;
}

int Pdu::get_asn1_length() const
{
  int length = 0;

  // length for all vbs
  for (int i = 0; i < vb_count; ++i)
    length += vbs[i]->get_asn1_length();

  // header for vbs
  if      (length < 0x80)      length += 2;
  else if (length <= 0xFF)     length += 3;
  else if (length <= 0xFFFF)   length += 4;
  else if (length <= 0xFFFFFF) length += 5;
  else                         length += 6;

  // req id, error status, error index
  SnmpInt32 i32(request_id ? request_id : PDU_MAX_RID);
  length += i32.get_asn1_length();
  i32 = error_status;
  length += i32.get_asn1_length();
  i32 = error_index;
  length += i32.get_asn1_length();
    
  // header for data_pdu
  if      (length < 0x80)      length += 2;
  else if (length <= 0xFF)     length += 3;
  else if (length <= 0xFFFF)   length += 4;
  else if (length <= 0xFFFFFF) length += 5;
  else                         length += 6;

#ifdef _SNMPv3
  // now the scopedpdu part sequence (4), context engine, id context name
  length += 4 + 2 + context_engine_id.len() + 2 + context_name.len();

  // An encrypted message is transported as an octet string 
  if (security_level == SNMP_SECURITY_LEVEL_AUTH_PRIV)
  {
    // assume that encryption increases the data to a multiple of 16
    int mod = length % 16;
    if (mod) length += 16 - mod;

    length += 4;
  }
#endif

  return length;
}

// extend the vbs array
bool Pdu::extend_vbs()
{
  if (vbs_size == 0)
  {
    vbs = new Vb*[PDU_INITIAL_SIZE];
    if (vbs)
    {
      vbs_size = PDU_INITIAL_SIZE;
      return true;
    }
    else
       return false;
  }

  Vb **tmp = vbs;
  vbs = new Vb*[vbs_size * 2];
  if (!vbs)
  {
    vbs = tmp;
    return false;
  }

  for (int y = 0; y < vb_count; ++y)
    vbs[y] = tmp[y];
  vbs_size *= 2;
  delete [] tmp;
  return true;
}

// Clear all members of the object
void Pdu::clear()
{
  error_status        = 0;
  error_index         = 0;
  request_id          = 0;
  pdu_type            = 0;
  notify_timestamp    = 0;
  notify_id.clear();
  notify_enterprise.clear();
  v1_trap_address_set = false;
  validity            = true;

  for (int z = 0; z < vb_count; ++z)  delete vbs[z];
  vb_count = 0;

#ifdef _SNMPv3
  security_level    = SNMP_SECURITY_LEVEL_NOAUTH_NOPRIV;
  message_id        = 0;
  maxsize_scopedpdu = 0;
  context_name.clear();
  context_engine_id.clear();
#endif // _SNMPv3
}

// Does the type of response match the type of request
bool Pdu::match_type(const int request, const int response)
{
  switch (request)
  {
    case sNMP_PDU_GET:
    case sNMP_PDU_GETNEXT:
    case sNMP_PDU_SET:
    case sNMP_PDU_GETBULK:
    case sNMP_PDU_INFORM:
    {
      if ((response == sNMP_PDU_RESPONSE) ||
	  (response == sNMP_PDU_REPORT))
	return true;
      if ((response == sNMP_PDU_GET) ||
	  (response == sNMP_PDU_GETNEXT) ||
	  (response == sNMP_PDU_SET) ||
	  (response == sNMP_PDU_GETBULK) ||
	  (response == sNMP_PDU_INFORM) ||
	  (response == sNMP_PDU_V1TRAP) ||
	  (response == sNMP_PDU_TRAP))
      {
	debugprintf(0, "Unknown response pdu type (%d).", response);
      }
      return false;
    }
    case sNMP_PDU_REPORT:
    case sNMP_PDU_RESPONSE:
    case sNMP_PDU_V1TRAP:
    case sNMP_PDU_TRAP:
    {
      return false;
    }
    default:
    {
      debugprintf(0, "Unknown request pdu type (%d).", request);
      return false;
    }
  }
}

#ifdef SNMP_PP_NAMESPACE
}; // end of namespace Snmp_pp
#endif 
