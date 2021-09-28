/*_############################################################################
  _## 
  _##  vb.cpp  
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


  V B . C P P

  VARIABLE BINDING CLASS IMPLEMENTATION

  DESCRIPTION:
  This module contains the class implementation of the VB class.
  The Vb class is an encapsulation of the snmp variable binding.

  DESIGN + AUTHOR:  Peter E Mellquist
=====================================================================*/
char vb_cpp_version[]="#(@) SNMP++ $Id$";

#include <libsnmp.h>

#include "snmp_pp/vb.h"            // include vb class defs

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

#define IP_ADDR_SIZE  4
#define IPX_ADDR_SIZE 10
#define MAC_ADDR_SIZE 6

//--------------[ Vb::valid() ]-----------------------------------------
// returns validity of a Vb object
// must have a valid oid and value
bool Vb::valid() const
{
  if (iv_vb_oid.valid() &&
      ((iv_vb_value == NULL) || (iv_vb_value && iv_vb_value->valid())))
    return true;
  return false;
}

//---------------[ Vb& Vb::operator=(const Vb &vb) ]--------------------
// overloaded assignment allows assigning one Vb to another
// this involves deep memory thus target vb needs to be freed
// before assigning source
Vb& Vb::operator=(const Vb &vb)
{
  if (this == &vb) return *this;  // check for self assignment

  free_vb(); // free up target to begin with

  //-----[ reassign the Oid portion 1st ]
  vb.get_oid(iv_vb_oid);

  //-----[ next set the vb value portion ]
  if (vb.iv_vb_value)
    iv_vb_value = vb.iv_vb_value->clone();

  exception_status = vb.exception_status;

  return *this; // return self reference
}

//----------------[ void Vb::free_vb() ]--------------------------------
// protected method to free memory
// this method is used to free memory when assigning new vbs
// or destructing
// in the case of oids and octets, we need to do a deep free
void Vb::free_vb()
{
  if (iv_vb_value)
  {
    delete iv_vb_value;
    iv_vb_value = NULL;
  }
  exception_status = SNMP_CLASS_SUCCESS;
}

//---------------------[ Vb::get_value(int &i) ]----------------------
// get value int
// returns 0 on success and value
int Vb::get_value(int &i) const
{
   if (iv_vb_value &&
       iv_vb_value->valid() &&
       (iv_vb_value->get_syntax() == sNMP_SYNTAX_INT32 ))
   {
     long lval;
     lval = *((SnmpInt32 *)iv_vb_value);// SnmpInt32 includes cast to long,
     i = (int) lval;                    // but not to int.
     return SNMP_CLASS_SUCCESS;
   }
   return SNMP_CLASS_INVALID;
}

// get the unsigned int
// returns 0 on success and a value
int Vb::get_value(unsigned int &i) const
{
  if (iv_vb_value &&
      iv_vb_value->valid() &&
      ((iv_vb_value->get_syntax() == sNMP_SYNTAX_UINT32 ) ||
       (iv_vb_value->get_syntax() == sNMP_SYNTAX_CNTR32 ) ||
       (iv_vb_value->get_syntax() == sNMP_SYNTAX_GAUGE32 ) ||
       (iv_vb_value->get_syntax() == sNMP_SYNTAX_TIMETICKS )))
  {
    unsigned long lval;
    lval = *((SnmpUInt32 *)iv_vb_value);
    i = (unsigned int)lval;
    return SNMP_CLASS_SUCCESS;
  }
  return SNMP_CLASS_INVALID;
}


//--------------[ Vb::get_value(long int &i) ]-------------------------
// get the signed long int
// returns 0 on success and a value
int Vb::get_value(long &i) const
{
   if (iv_vb_value &&
       iv_vb_value->valid() &&
       (iv_vb_value->get_syntax() == sNMP_SYNTAX_INT32 ))
   {
     i = *((SnmpInt32 *)iv_vb_value);	// SnmpInt32 has cast to long
     return SNMP_CLASS_SUCCESS;
   }
   return SNMP_CLASS_INVALID;
}


//-----------------[  Vb::get_value(unsigned long int &i) ]--------------
// get the unsigned long int
// returns 0 on success and a value
int Vb::get_value(unsigned long &i) const
{
  if (iv_vb_value &&
      iv_vb_value->valid() &&
      ((iv_vb_value->get_syntax() == sNMP_SYNTAX_UINT32 ) ||
       (iv_vb_value->get_syntax() == sNMP_SYNTAX_CNTR32 ) ||
       (iv_vb_value->get_syntax() == sNMP_SYNTAX_GAUGE32 ) ||
       (iv_vb_value->get_syntax() == sNMP_SYNTAX_TIMETICKS )))
  {
    i = *((SnmpUInt32 *)iv_vb_value);	// SnmpUint32 has cast to ulong
    return SNMP_CLASS_SUCCESS;
  }
  return SNMP_CLASS_INVALID;
}

//-----------------[  Vb::get_value(pp_uint64 &i) ]--------------
// get the pp_uint64
// returns 0 on success and a value
int Vb::get_value(pp_uint64 &i) const
{
  if (iv_vb_value &&
      iv_vb_value->valid() &&
      (iv_vb_value->get_syntax() == sNMP_SYNTAX_CNTR64 ))
  {
    i = *((Counter64*)iv_vb_value);
    return SNMP_CLASS_SUCCESS;
  }
  return SNMP_CLASS_INVALID;
}

//--------------[ Vb::get_value(unsigned char WINFAR * ptr, unsigned long &len)
// get a unsigned char string value
// destructive, copies into given ptr
// also returned is the length
//
// Note!! The user must provide a target string
// which is big enough to hold the string
int Vb::get_value(unsigned char *ptr, unsigned long &len) const
{
  if (iv_vb_value &&
      iv_vb_value->valid() &&
      (iv_vb_value->get_syntax() == sNMP_SYNTAX_OCTETS))
  {
    OctetStr *p_os = (OctetStr *)iv_vb_value;
    len = p_os->len();
    memcpy(ptr, p_os->data(), len);
    ptr[len] = 0;
    return SNMP_CLASS_SUCCESS;
  }

  if (ptr) ptr[0] = 0;
  len = 0;
  return SNMP_CLASS_INVALID;
}

//---------------[ Vb::get_value ]-------------------------------------
// get an unsigned char array
// caller specifies max len of target space
int Vb::get_value(unsigned char *ptr, unsigned long &len,
		  const unsigned long maxlen,
		  const bool add_null_byte) const
{
  if (iv_vb_value &&
      iv_vb_value->valid() &&
      (iv_vb_value->get_syntax() == sNMP_SYNTAX_OCTETS) &&
      (maxlen > 0))
  {
    OctetStr *p_os = (OctetStr *)iv_vb_value;
    len = p_os->len();
    if (len > maxlen) len = maxlen;
    memcpy(ptr, p_os->data(), len);
    if (add_null_byte)
    {
      if (len == maxlen)
	ptr[len-1] = 0;
      else
	ptr[len] = 0;
    }
    return SNMP_CLASS_SUCCESS;
  }

  if (ptr) ptr[0] = 0;
  len = 0;
  return SNMP_CLASS_INVALID;
}


//---------------[ Vb::get_value(Value &val) ]--------
int Vb::get_value(SnmpSyntax &val) const
{
  if (iv_vb_value)
  {
    val = *iv_vb_value;
    if (val.valid())
      return SNMP_CLASS_SUCCESS;
    return SNMP_CLASS_INVALID;
  }
  // TM: should set val to be invalid
  return SNMP_CLASS_INVALID;
}

//--------------[ Vb::get_value(char WINFAR *ptr) ]-------------------
// get a char * from an octet string
// the user must provide space or
// memory will be stepped on
int Vb::get_value(char *ptr) const
{
  if (iv_vb_value &&
      iv_vb_value->valid() &&
      (iv_vb_value->get_syntax() == sNMP_SYNTAX_OCTETS))
  {
    OctetStr *p_os = (OctetStr *)iv_vb_value;
    unsigned long len = p_os->len();
    memcpy(ptr, p_os->data(), len);
    ptr[len] = 0;
    return SNMP_CLASS_SUCCESS;
  }

  if (ptr) ptr[0] = 0;
  return SNMP_CLASS_INVALID;
}



//-----[ misc]--------------------------------------------------------

// return the current syntax
// This method violates Object Orientation but may be useful if
// the caller has a vb object and does not know what it is.
// This would be useful in the implementation of a browser.
SmiUINT32 Vb::get_syntax() const
{
  if (exception_status != SNMP_CLASS_SUCCESS)
    return exception_status;
  else
    return (iv_vb_value ? iv_vb_value->get_syntax() : sNMP_SYNTAX_NULL);
}

void Vb::set_syntax(const SmiUINT32 syntax)
{
	free_vb(); // setting to SNMP_SYNTAX_NULL

	exception_status = SNMP_CLASS_SUCCESS;

	switch (syntax) {
	case sNMP_SYNTAX_INT32:
	  	iv_vb_value = new SnmpInt32();
		break;
	case sNMP_SYNTAX_TIMETICKS:
		iv_vb_value = new TimeTicks();
		break;
	case sNMP_SYNTAX_CNTR32:
		iv_vb_value = new Counter32();
		break;
	case sNMP_SYNTAX_GAUGE32:
		iv_vb_value = new Gauge32();
		break;
/* Not distinguishable from Gauge32
	case sNMP_SYNTAX_UINT32:
	  	iv_vb_value = new SnmpUInt32();
		break;
*/
	case sNMP_SYNTAX_CNTR64:
	  	iv_vb_value = new Counter64();
		break;
	case sNMP_SYNTAX_BITS:
	case sNMP_SYNTAX_OCTETS:
	  	iv_vb_value = new OctetStr();
		break;
	case sNMP_SYNTAX_OPAQUE:
	  	iv_vb_value = new OpaqueStr();
		break;
	case sNMP_SYNTAX_IPADDR:
	  	iv_vb_value = new IpAddress();
		break;
	case sNMP_SYNTAX_OID:
	  	iv_vb_value = new Oid();
		break;
	case sNMP_SYNTAX_NULL:
		break;
	case sNMP_SYNTAX_NOSUCHINSTANCE:
		exception_status = sNMP_SYNTAX_NOSUCHINSTANCE;
		break;
	case sNMP_SYNTAX_NOSUCHOBJECT:
		exception_status = sNMP_SYNTAX_NOSUCHOBJECT;
		break;
	case sNMP_SYNTAX_ENDOFMIBVIEW:
		exception_status = sNMP_SYNTAX_ENDOFMIBVIEW;
		break;
	case sNMP_SYNTAX_SEQUENCE:
		break;
	}
}

static char blank_string[] = "";

// return the printabel value
const char *Vb::get_printable_value() const
{
  if (iv_vb_value)
    return iv_vb_value->get_printable();
  return blank_string;
}

int Vb::get_asn1_length() const
{
  // Header for vbs is always 4 Bytes! FIXME
  if (iv_vb_value)
    return iv_vb_oid.get_asn1_length() + iv_vb_value->get_asn1_length() + 4;

  return iv_vb_oid.get_asn1_length() + 2 + 4;
}

#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif 
