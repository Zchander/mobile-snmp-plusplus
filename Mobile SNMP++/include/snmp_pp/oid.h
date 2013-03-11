/*_############################################################################
  _## 
  _##  oid.h  
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

		
  SNMP++ O I D. H

  OID CLASS DEFINITION

  DESIGN + AUTHOR:   Peter E Mellquist

  DESCRIPTION:
  This class is fully contained and does not rely on or any other
  SNMP libraries. This class is portable across any platform
  which supports C++.

=====================================================================*/
// $Id: oid.h 1775 2010-07-11 09:59:28Z katz $

#ifndef _OID_H_
#define _OID_H_

//------------------------------------------------------------------------

#include "snmp_pp/smival.h"                // derived class for all values
#include "snmp_pp/collect.h"

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif


/**
 * The Object Identifier Class.
 *
 * The Object Identification (Oid) class is the encapsulation of an
 * SMI object identifier. The SMI object is a data identifier for a
 * data element found in a Management Information Base (MIB), as
 * defined by a MIB definition. The SMI Oid, its related structures
 * and functions, are a natural fit for object orientation. In fact,
 * the Oid class shares many common features to the C++ String
 * class. For those of you familiar with the C++ String class or
 * Microsoft's Foundation Classes (MFC) CString class, the Oid class
 * will be familiar and easy to use. The Oid class is designed to be
 * efficient and fast. The Oid class allows definition and
 * manipulation of object identifiers. 
 *
 * @note Oid holds two internal buffers for get_printable() functions.
 *       The buffer returned by get_printable() is valid until the
 *       Oid object is modified. The functions get_printable(len) and
 *       get_printable(start, len) share the same buffer which is
 *       freed and newly allocated for each call.
 */
class DLLOPT Oid : public SnmpSyntax
{
 public:

  /**
   * Construct an invalid Oid.
   */
  Oid();

  /**
   * Construct an Oid from a string.
   *
   * Depending on the second param, the oid_string can either be
   * - a dotted oid string (like "1.3.6.1.6"). An arbitrary part
   *   of the oid can be given as a string value enclosed in
   *   '$' characters. For example the oid string
   *   "1.3.6.1.6.1.12.1.3.$public0$" will result to the oid
   *   1.3.6.1.6.1.12.1.3.112.117.98.108.105.99.95.48
   * - a normal string (like "public"). The Oid will have the
   *   ASCII values of the string characters. So "public" will
   *   result to the oid 112.117.98.108.105.99
   * 
   * @param oid_string - for example "1.3.1.6.1.10"
   * @param is_dotted_oid_string - Select format within oid_string
   */
  Oid(const char *oid_string, const bool is_dotted_oid_string = true);

  /**
   * Constructor using another oid object (copy constructor).
   *
   * @param oid - Source Oid
   */
  Oid(const Oid &oid);

  /**
   * Constructor from array.
   *
   * @param raw_oid - array of oid values
   * @param oid_len - length of array
   */
  Oid(const unsigned long *raw_oid, int oid_len);

  /**
   * Destructor.
   */
  virtual ~Oid();

  /**
   * Return the current syntax.
   *
   * @return always sNMP_SYNTAX_OID
   */
  SmiUINT32 get_syntax() const { return sNMP_SYNTAX_OID; };

  /**
   * Assignment from a string.
   *
   * @param dotted_oid_string - New value (for example "1.3.6.1.6.0");
   */
  virtual Oid& operator=(const char *dotted_oid_string);

  /**
   * Assign one Oid to another.
   */
  virtual Oid& operator=(const Oid &oid);

  /**
   * Return the space needed for serialization.
   */
  int get_asn1_length() const;

  /**
   * Overloaded equal operator.
   */
  DLLOPT friend int operator==(const Oid &lhs, const Oid &rhs);

  /**
   * Overloaded not equal operator.
   */
  DLLOPT friend int operator!=(const Oid &lhs, const Oid &rhs)
      { return (!(lhs == rhs)); };  // just invert ==

  /**
   * Overloaded less than < operator.
   */
  DLLOPT friend int operator<(const Oid &lhs, const Oid &rhs);

  /**
   * Overloaded less than <= operator.
   */
  DLLOPT friend int operator<=(const Oid &lhs, const Oid &rhs)
      { return ((lhs < rhs) || (lhs == rhs)); };

  /**
   * Overloaded greater than > operator.
   */
  DLLOPT friend int operator>(const Oid &lhs, const Oid &rhs)
      { return (!(lhs <= rhs)); };  // just invert existing <=

  /**
   * Overloaded greater than >= operator.
   */
  DLLOPT friend int operator>=(const Oid &lhs, const Oid &rhs)
      { return (!(lhs < rhs)); };  // just invert existing <

  /**
   * Overloaded equal operator operator.
   */
  DLLOPT friend int operator==(const Oid &lhs, const char *rhs);

  /**
   * Overloaded not equal operator.
   */
  DLLOPT friend int operator!=(const Oid &lhs, const char *rhs);

  /**
   * Overloaded less than < operator.
   */
  DLLOPT friend int operator<(const Oid &lhs, const char *rhs);

  /**
   * Overloaded less than <= operator.
   */
  DLLOPT friend int operator<=(const Oid &lhs, char *rhs);

  /**
   * Overloaded greater than > operator.
   */
  DLLOPT friend int operator>(const Oid &lhs, const char *rhs);

  /**
   * Overloaded greater than >= operator.
   */
  DLLOPT friend int operator>=(const Oid &lhs, const char *rhs);

  /**
   * Overloaded operator +, Concatenate two Oids.
   */
  DLLOPT friend Oid operator +(const Oid &lhs, const Oid &rhs)
    { Oid tmp(lhs); tmp += rhs; return tmp;};

  /**
   * Append operator, appends the dotted oid string.
   *
   * @param a - dotted oid string, for example "5.192.14.6"
   */
  Oid& operator+=(const char *a);

  /**
   * Appends an int.
   *
   * @param i - Value to add at the end of the Oid
   */
  Oid& operator+=(const unsigned long i);

  /**
   * Appends an Oid.
   *
   * @param o - Oid to add at the end
   */
  Oid& operator+=(const Oid &o);

  /**
   * Allows element access as an array.
   * This method behaves like real array: if your index
   * is out of bounds, you're lost!
   *
   * @param index - valid index -- 0 to (len() - 1)
   *
   * @return Value on the given index
   */
  unsigned long &operator[](const unsigned int index)
    { m_changed = true; return smival.value.oid.ptr[index]; };

  /**
   * Allows element access as an array for const objects.
   * This method behaves like real array: if your index
   * is out of bounds, you're lost!
   *
   * @param index - valid index -- 0 to (len() - 1)
   *
   * @return Value on the given position
   */
  unsigned long operator[](const unsigned int index) const
    { return (index >= len()) ? 0 : smival.value.oid.ptr[index]; };

  /**
   * Get the WinSnmp oid part.
   * @note This method returns a pointer to internal data.
   *       If it is modified, the Oid changes too.
   *
   * @return pointer to the internal oid structure.
   */
  SmiLPOID oidval() { return (SmiLPOID) &smival.value.oid; };

  /**
   * Set the data from raw form.
   *
   * @param raw_oid - Array of new values
   * @param oid_len - Length of the array raw_oid
   */
  void set_data(const unsigned long *raw_oid, const unsigned int oid_len);

  /**
   * Set the data from raw form.
   *
   * @param str     - Array of new values (a string)
   * @param str_len - Length of the array raw_oid
   */
  void set_data(const char *str, const unsigned int str_len);

  /**
   * Get the length of the oid.
   */
  unsigned long len() const { return smival.value.oid.len; };

  /**
   * Trim off the rightmost values of an oid.
   *
   * @param n - Trim off n values from the right (default is one)
   */
  void trim(const unsigned long n = 1);

  /**
   * Compare two Oids from the left in direction left-to-right.
   *
   * @param n - Subvalues to compare
   * @param o - The Oid to compare with
   *
   * @return 0 if equal / -1 if less / 1 if greater
   */
  int nCompare(const unsigned long n, const Oid &o) const;

  /**
   * Return validity of the object.
   */
  bool valid() const { return (smival.value.oid.ptr ? true : false); };

  /**
   * Get a printable ASCII string of the whole value.
   *
   * @return Dotted oid string (for example "1.3.6.1.6.0")
   */
  const char *get_printable() const
    { return get_printable(1, smival.value.oid.len, (char*&)iv_str); };

  /**
   * Get a printable ASCII string of the right part of the value.
   *
   * @param n - positions to print, counted from right.
   *
   * @return Dotted oid string (for example "6.0")
   */
  const char *get_printable(const unsigned long n) const
    { return get_printable(smival.value.oid.len - n + 1, n, (char*&)iv_part_str); };

  /**
   * Get a printable ASCII string of a part of the value.
   *
   * @param start - First position to print, starting with 1 (not zero!)
   * @param n - positions to print.
   * @param buffer - pointer to the returned buffer
   *
   * @note If buffer is not NULL, this function calls "delete [] buffer",
   *       a new buffer is allocated using "new" and the caller has
   *       to delete it.
   *
   * @return Dotted oid string (for example "3.6.1.6")
   */
  const char *get_printable(const unsigned long start,
			    const unsigned long n,
			    char *&buffer) const;

  /**
   * Get a printable ASCII string of a part of the value.
   *
   * @param start - First position to print, starting with 1 (not zero!)
   * @param n - positions to print.
   *
   * @return Dotted oid string (for example "3.6.1.6")
   */
  const char *get_printable(const unsigned long start,
			    const unsigned long n) const
    { return get_printable(start, n, (char*&)iv_part_str); };

  /**
   * Clone this object.
   *
   * @return Pointer to the newly created object (allocated through new).
   */
  SnmpSyntax *clone() const { return (SnmpSyntax *) new Oid(*this); };

  /**
   * Map other SnmpSyntax objects to Oid.
   */
  SnmpSyntax& operator=(const SnmpSyntax &val);

  /**
   * Clear the Oid.
   */
  void clear() { delete_oid_ptr(); };

 protected:
  /**
   * Convert a string to an smi oid.
   *
   * @param string - input string
   * @param dstOid - destination oid
   */
  virtual int StrToOid(const char *string, SmiLPOID dstOid) const;

  /**
   * Clone an smi oid.
   *
   * @param srcOid - source oid
   * @param dstOid - destination oid
   */
  virtual int OidCopy(SmiLPOID srcOid, SmiLPOID dstOid) const;

  /**
   * Convert an smi oid to its string representation.
   *
   * @param srcOid - source oid
   * @param size   - size of string
   * @param string - pointer to string
   */
  virtual int OidToStr(const SmiOID *srcOid,
		       SmiUINT32 size,
		       char *string) const;

  /**
   * Free the internal oid pointer and set the pointer and the length to zero.
   */
  inline void delete_oid_ptr();

  //----[ instance variables ]

  SNMP_PP_MUTABLE char *iv_str;      // used for returning complete oid string
  SNMP_PP_MUTABLE char *iv_part_str; // used for returning part oid string
  SNMP_PP_MUTABLE bool m_changed;
};

//-----------[ End Oid Class ]-------------------------------------

// create OidCollection type
typedef SnmpCollection <Oid> OidCollection;

inline void Oid::delete_oid_ptr()
{
  // delete the old value
  if (smival.value.oid.ptr)
  {
    delete [] smival.value.oid.ptr;
    smival.value.oid.ptr = 0;
  }
  smival.value.oid.len = 0;
  m_changed = true;
}

#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif 

#endif //_OID_H_
