/*_############################################################################
  _## 
  _##  counter.h  
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
  purpose. It is provided "AS-IS without warranty of any kind,either express
  or implied. User hereby grants a royalty-free license to any and all
  derivatives based upon this software code base.


  SNMP++ C O U N T E R. H

  COUNTER32 CLASS DEFINITION

  DESIGN + AUTHOR:  Peter E Mellquist

  DESCRIPTION:
  Class definition for SMI Counter32 class.

=====================================================================*/
// $Id: counter.h 1541 2009-05-29 11:29:22Z katz $

#ifndef _COUNTER
#define _COUNTER

#include "snmp_pp/integer.h"

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

//------------[ Counter32 Class ]------------------------------------------
/**
 * The counter class allows all the functionality of unsigned
 * integers but is recognized as a distinct SMI type. Counter32
 * class objects may be set or get into Vb objects.
 */
class DLLOPT Counter32: public SnmpUInt32
{
 public:
  /**
   * Constructor to create a Counter object with value zero.
   */
  Counter32() : SnmpUInt32() { smival.syntax = sNMP_SYNTAX_CNTR32; };

  /**
   * Constructor with a value.
   *
   * @param i - unsigned 32 bit value
   */
  Counter32(const unsigned long i) : SnmpUInt32(i)
    { smival.syntax = sNMP_SYNTAX_CNTR32; };

  /**
   * Copy constructor.
   *
   * @param c - Object to copy from
   */
  Counter32(const Counter32 &c);

  /**
   * Return the syntax.
   *
   * @return Returns always sNMP_SYNTAX_CNTR32
   */
  SmiUINT32 get_syntax() const { return sNMP_SYNTAX_CNTR32; };

  /**
   * Clone operator.
   *
   * @return Pointer to a newly created copy of the object.
   */
  SnmpSyntax *clone() const { return (SnmpSyntax *)new Counter32(*this); };

  /**
   * Map other SnmpSyntax objects to Counter32.
   */
  SnmpSyntax& operator=(const SnmpSyntax &val);

  /**
   * Overloaded assignment for Counter32.
   *
   * @param uli - new value
   * @return self reference
   */
  Counter32& operator=(const Counter32 &uli)
    { smival.value.uNumber = uli.smival.value.uNumber;
      m_changed = true; return *this;};

  /**
   * Overloaded assignment for unsigned longs.
   *
   * @param i - new value
   * @return self reference
   */
  Counter32& operator=(const unsigned long i)
    { smival.value.uNumber = i; m_changed = true; return *this;};

  /**
   * Casting to unsigned long.
   *
   * @return Current value as an unsigned long
   */
  operator unsigned long() { return smival.value.uNumber; };
};

#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif 

#endif // _COUNTER
