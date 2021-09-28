/*_############################################################################
  _## 
  _##  ctr64.h  
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
  purpose. It is provided "AS-IS without warranty of any kind,either express
  or implied. User hereby grants a royalty-free license to any and all
  derivatives based upon this software code base.

		
  SNMP++ C O U N T E R 6 4 . H

  COUNTER64 CLASSES DEFINITION

  DESIGN + AUTHOR:    Peter E Mellquist

  DESCRIPTION:        SNMP Counter64 class definition.

=====================================================================*/
// $Id$

#ifndef _SNMP_CTR64_H_
#define _SNMP_CTR64_H_

#include "snmp_pp/smival.h"

#ifndef UINT32_MAX
# define UINT32_MAX (4294967295U)
#endif

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

#define CTR64OUTBUF 30  //!< maximum ascii string for a 64-bit counter

//---------[ 64 bit Counter Class ]--------------------------------
/**
 * Counter64 Class encapsulates two unsigned integers into a
 * a single entity. This type has is available in SNMPv2 but
 * may be used anywhere where needed.
 */
class DLLOPT Counter64: public SnmpSyntax
{
 public:

  //-----------[ Constructors and Destructor ]----------------------

  /**
   * Constructs a valid Counter64 with the given values.
   *
   * @param hi - value for the high 32 bits (0..MAX_UINT32)
   * @param lo - value for the low  32 bits (0..MAX_UINT32)
   */
  Counter64(unsigned long hi, unsigned long lo)
    : m_changed(true)
  {
    smival.syntax = sNMP_SYNTAX_CNTR64;
    smival.value.hNumber.hipart = hi;
    smival.value.hNumber.lopart = lo;
  }

  /**
   * Constructs a valid Counter64 with the given value (default 0).
   *
   * @param val - value (full 64-bit)
   */
  Counter64(pp_uint64 val = 0)
    : m_changed(true)
  {
    smival.syntax = sNMP_SYNTAX_CNTR64;
    smival.value.hNumber.hipart = val >> 32;
    smival.value.hNumber.lopart = val & UINT32_MAX;
  }

  /**
   * Copy constructor.
   *
   * @param ctr64 - value
   */
  Counter64(const Counter64 &ctr64)
    : m_changed(true)
  {
    smival.syntax = sNMP_SYNTAX_CNTR64;
    smival.value.hNumber = ctr64.smival.value.hNumber;
  }

  /**
   * Destructor (ensure that SnmpSyntax::~SnmpSyntax() is overridden).
   */
  ~Counter64() {}

  operator pp_uint64 () const
  {
    pp_uint64 v = ((pp_uint64)smival.value.hNumber.hipart) << 32;
    v += smival.value.hNumber.lopart;
    return v;
  }

  //-----------[ get/set using 32 bit variables ]----------------------

  /**
   * Get the high 32 bit part.
   *
   * @return The high part of the Counter64
   */
  unsigned long high() const { return smival.value.hNumber.hipart; }

  /**
   * Get the low 32 bit part.
   *
   * @return The low part of the Counter64
   */
  unsigned long low() const { return smival.value.hNumber.lopart; }

  /**
   * Set the high 32 bit part. The low part will stay unchanged.
   *
   * @param h - The new high part of the Counter64
   */
  void set_high(const unsigned long h)
    { smival.value.hNumber.hipart = h; m_changed = true; }

  /**
   * Set the low 32 bit part. The high part will stay unchanged.
   *
   * @param l - The new low part of the Counter64
   */
  void set_low(const unsigned long l)
    { smival.value.hNumber.lopart = l; m_changed = true; }


  //-----------[ SnmpSyntax methods ]----------------------

  /**
   * Get a printable ASCII string representing the current value.
   *
   * @note The returned string is valid as long as the object is not
   *       modified.
   *
   * @return Null terminated string.
   */
  const char *get_printable() const;

  /**
   * Get the Syntax of the object.
   *
   * @return This method always returns sNMP_SYNTAX_CNTR64.
   */
  SmiUINT32 get_syntax() const { return sNMP_SYNTAX_CNTR64; }

  /**
   * Clone the object.
   *
   * @return A cloned Counter64 object allocated through new.
   */
  SnmpSyntax *clone() const { return (SnmpSyntax *) new Counter64(*this); }

  /**
   * Overloaded assignment operator.
   *
   * @param val - Try to map the given value to a Counter64 and assign it
   * @return Always *this with the new value.
   */
  SnmpSyntax& operator=(const SnmpSyntax &val);

  /**
   * Return validity of the object.
   *
   * @return Always true
   */
  bool valid() const { return true; }

  /**
   * Return the space needed for serialization.
   *
   * @return The needed space that depends on the current value.
   */
  int get_asn1_length() const;

  /**
   * Reset the object.
   */
  void clear()
    { smival.value.hNumber.hipart = 0; smival.value.hNumber.lopart = 0;
      m_changed = true; };
  
  //-----------[ overloaded operators ]----------------------

  /**
   * Assign a Counter64 to a Counter64.
   */
  Counter64& operator=(const Counter64 &ctr64)
  {
    if (this == &ctr64)
      return *this;  // check for self assignment

    smival.value.hNumber.hipart = ctr64.high();
    smival.value.hNumber.lopart = ctr64.low();
    m_changed = true;
    return *this;
  }

  /**
   * Assign a unsigned long to a Counter64.
   *
   * @param i - The new low part. The high part is cleared.
   */
  Counter64& operator = (const pp_uint64 i)
  {
    m_changed = true;
    smival.value.hNumber.hipart = i >> 32;
    smival.value.hNumber.lopart = i & UINT32_MAX;
    return *this;
  }

 protected:

  SNMP_PP_MUTABLE char output_buffer[CTR64OUTBUF];
  SNMP_PP_MUTABLE bool m_changed;
};

#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif 

#endif // _SNMP_CTR64_H_
