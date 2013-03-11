/*_############################################################################
  _## 
  _##  integer.cpp  
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

  I N T E G E R . C P P

  SMI INTEGER CLASS IMPLEMTATION

  DESIGN + AUTHOR: Jeff Meyer

  DESCRIPTION:
  Class implemtation for SMI Integer classes.
=====================================================================*/
char integer_cpp_version[]="#(@) SNMP++ $Id: integer.cpp 1542 2009-05-29 11:38:48Z katz $";

#include <stdio.h>             // for sprintf()
#include "snmp_pp/integer.h"   // header file for gauge class

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

// constructor no value
SnmpUInt32::SnmpUInt32() : valid_flag(true), m_changed(true)
{
  smival.value.uNumber = 0;
  smival.syntax = sNMP_SYNTAX_UINT32;
}

// constructor with value
SnmpUInt32::SnmpUInt32 (const unsigned long i)
  : valid_flag(true), m_changed(true)
{
  smival.value.uNumber = i;
  smival.syntax = sNMP_SYNTAX_UINT32;
}

// copy constructor
SnmpUInt32::SnmpUInt32(const SnmpUInt32 &c) : valid_flag(true), m_changed(true)
{
  smival.value.uNumber=c.smival.value.uNumber;
  smival.syntax = sNMP_SYNTAX_UINT32;
}

// overloaded assignment
SnmpUInt32& SnmpUInt32::operator=(const unsigned long i)
{
  smival.value.uNumber = i;
  valid_flag = true;
  m_changed = true;
  return *this;
}

// general assignment from any Value
SnmpSyntax& SnmpUInt32::operator=(const SnmpSyntax &in_val)
{
  if (this == &in_val) return *this; // handle assignement from itself

  valid_flag = false;		// will get set true if really valid
  if (in_val.valid())
  {
    switch (in_val.get_syntax())
    {
      case sNMP_SYNTAX_UINT32:
   // case sNMP_SYNTAX_GAUGE32:  	.. indistinquishable from UINT32
      case sNMP_SYNTAX_CNTR32:
      case sNMP_SYNTAX_TIMETICKS:
      case sNMP_SYNTAX_INT32:		// implied cast int -> uint
	  smival.value.uNumber =
	      ((SnmpUInt32 &)in_val).smival.value.uNumber;
  	  valid_flag = true;
	  break;
    }
  }
  m_changed = true;
  return *this;
}

// overloaded assignment
SnmpUInt32& SnmpUInt32::operator=(const SnmpUInt32 &uli)
{
  if (this == &uli) return *this;  // check for self assignment

  smival.value.uNumber = uli.smival.value.uNumber;
  valid_flag = uli.valid_flag;
  m_changed = true;
  return *this;
}

// ASCII format return
const char *SnmpUInt32::get_printable() const
{
  if (m_changed == false) return output_buffer;

  SnmpUInt32 *nc_this = PP_CONST_CAST(SnmpUInt32*, this);
  sprintf(nc_this->output_buffer, "%lu", smival.value.uNumber);

  nc_this->m_changed = false;

  return output_buffer;
}

// Return the space needed for serialization
int SnmpUInt32::get_asn1_length() const
{
  if (smival.value.uNumber < 0x80)
    return 3;
  else if (smival.value.uNumber < 0x8000)
    return 4;
  else if (smival.value.uNumber < 0x800000)
    return 5;
  else if (smival.value.uNumber < 0x80000000)
    return 6;
  return 7;
}

//====================================================================
//  INT 32 Implementation
//====================================================================

// constructor no value
SnmpInt32::SnmpInt32() : valid_flag(true), m_changed(true)
{
  smival.value.sNumber = 0;
  smival.syntax = sNMP_SYNTAX_INT32;
}

// constructor with value
SnmpInt32::SnmpInt32(const long i) : valid_flag(true), m_changed(true)
{
  smival.value.sNumber = i;
  smival.syntax = sNMP_SYNTAX_INT32;
}

// constructor with value
SnmpInt32::SnmpInt32(const SnmpInt32 &c) : valid_flag(true), m_changed(true)
{
  smival.value.sNumber = c.smival.value.sNumber;
  smival.syntax = sNMP_SYNTAX_INT32;
}

// overloaded assignment
SnmpInt32& SnmpInt32::operator=(const long i)
{
  smival.value.sNumber = (unsigned long) i;
  valid_flag = true;
  m_changed = true;
  return *this;
}

// overloaded assignment
SnmpInt32& SnmpInt32::operator=(const SnmpInt32 &uli)
{
  if (this == &uli) return *this;  // check for self assignment

  smival.value.sNumber = uli.smival.value.sNumber;
  valid_flag = uli.valid_flag;
  m_changed = true;
  return *this;
}

// general assignment from any Value
SnmpSyntax& SnmpInt32::operator=(const SnmpSyntax &in_val)
{
  if (this == &in_val) return *this; // handle assignement from itself

  valid_flag = false;		// will get set true if really valid
  if (in_val.valid())
  {
    switch (in_val.get_syntax())
    {
      case sNMP_SYNTAX_INT32:
      case sNMP_SYNTAX_UINT32:		// implied cast uint -> int
   // case sNMP_SYNTAX_GAUGE32:  	.. indistinquishable from UINT32
      case sNMP_SYNTAX_CNTR32:		// implied cast uint -> int
      case sNMP_SYNTAX_TIMETICKS:	// implied cast uint -> int
	  smival.value.sNumber =
		((SnmpInt32 &)in_val).smival.value.sNumber;
  	  valid_flag = true;
	  break;
    }
  }
  m_changed = true;
  return *this;
}

// ASCII format return
const char *SnmpInt32::get_printable() const
{
  if (m_changed == false) return output_buffer;

  SnmpInt32 *nc_this = PP_CONST_CAST(SnmpInt32*, this);
  sprintf(nc_this->output_buffer, "%ld", (long)smival.value.sNumber);

  nc_this->m_changed = false;

  return output_buffer;
}

// Return the space needed for serialization
int SnmpInt32::get_asn1_length() const
{
  if ((smival.value.sNumber <   0x80) &&
      (smival.value.sNumber >= -0x80))
    return 3;
  else if ((smival.value.sNumber <   0x8000) &&
	   (smival.value.sNumber >= -0x8000))
    return 4;
  else if ((smival.value.sNumber <   0x800000) &&
	   (smival.value.sNumber >= -0x800000))
    return 5;
  return 6;
}

#ifdef SNMP_PP_NAMESPACE
}; // end of namespace Snmp_pp
#endif 
