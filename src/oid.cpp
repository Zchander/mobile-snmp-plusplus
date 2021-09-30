/*_############################################################################
  _## 
  _##  oid.cpp  
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

  O I D. C P P

  OID CLASS IMPLEMENTATION

  DESIGN + AUTHOR:         Peter E. Mellquist

  DESCRIPTION:
  This module contains the implementation of the oid class. This
  includes all protected and public member functions. The oid class
  may be compiled stand alone without the use of any other library.
=====================================================================*/
char oid_cpp_version[]="#(@) SNMP++ $Id$";

#include <libsnmp.h>

#include "snmp_pp/oid.h"                  // include def for oid class

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

#define  SNMPBUFFSIZE 11          // size of scratch buffer
#define  SNMPCHARSIZE 11          // an individual oid instance as a string

/* Borlands isdigit has a bug */
/* XXX with a neat test this could be handled universal in configure and libsnmp.h */
#if defined(__BCPLUSPLUS__) || !defined(HAVE_ISDIGIT)
#define my_isdigit(c) ((c) >= '0' && (c) <= '9')
#else
#define my_isdigit isdigit
#endif

//=============[Oid::Oid(const char *dotted_string ]=====================
// constructor using a dotted string
//
// do a string to oid using the string passed in
Oid::Oid(const char *oid_string, const bool is_dotted_oid_string)
  : iv_str(0), iv_part_str(0), m_changed(true)
{
  smival.syntax = sNMP_SYNTAX_OID;
  smival.value.oid.len = 0;
  smival.value.oid.ptr = 0;

  if (is_dotted_oid_string)
    StrToOid(oid_string, &smival.value.oid);
  else
    set_data(oid_string, oid_string ? strlen(oid_string) : 0);
}

//=============[Oid::operator = const char * dotted_string ]==============
// assignment to a string operator overloaded
//
// free the existing oid
// create the new oid from the string
// return this object
Oid& Oid::operator=(const char *dotted_oid_string)
{
  delete_oid_ptr();

  // assign the new value
  StrToOid(dotted_oid_string, &smival.value.oid);
  return *this;
}

//==============[Oid:: operator += const char *a ]=========================
// append operator, appends a string
//
// allocate some space for a max oid string
// extract current string into space
// concat new string
// free up existing oid
// make a new oid from string
// delete allocated space
Oid& Oid::operator+=(const char *a)
{
  unsigned int n;

  if (!a) return *this;

  if (*a == '.') ++a;

  n = (smival.value.oid.len * SNMPCHARSIZE) + (smival.value.oid.len)
       + 1 + SAFE_UINT_CAST(strlen(a));
  char *ptr = new char[n];
  if (ptr)
  {
    /// @todo optimize this function (avoid conversion to string)
    OidToStr(&smival.value.oid, n, ptr);
    if (ptr[0])
      strcat(ptr,".");
    strcat(ptr,a);

    delete_oid_ptr();

    StrToOid(ptr, &smival.value.oid);
    delete [] ptr;
  }
  return *this;
}

//===============[Oid::set_data ]==---=====================================
// copy data from raw form...
void Oid::set_data(const unsigned long *raw_oid,
                   const unsigned int oid_len)
{
  if (smival.value.oid.len < oid_len)
  {
    delete_oid_ptr();

    smival.value.oid.ptr = (SmiLPUINT32) new unsigned long[oid_len];
    if (!smival.value.oid.ptr) return;
  }
  memcpy((SmiLPBYTE) smival.value.oid.ptr,
         (SmiLPBYTE) raw_oid,
         (size_t) (oid_len*sizeof(SmiUINT32)));
  smival.value.oid.len = oid_len;
  m_changed = true;
}

// Set the data from raw form.
void Oid::set_data(const char *str, const unsigned int str_len)
{
  if (smival.value.oid.len < str_len)
  {
    delete_oid_ptr();

    smival.value.oid.ptr = (SmiLPUINT32) new unsigned long[str_len];
    if (!smival.value.oid.ptr) return;
  }

  if ((!str) || (str_len == 0))
    return;

  for (unsigned int i=0; i<str_len; i++)
    smival.value.oid.ptr[i] = str[i];

  smival.value.oid.len = str_len;
  m_changed = true;
}

//==============[Oid::get_printable(unsigned int start, n) ]=============
// return a dotted string starting at start,
// going n positions to the left
// NOTE, start is 1 based (the first id is at position #1)
const char *Oid::get_printable(const unsigned long start,
                               const unsigned long n,
                               char *&buffer) const
{
  if (!m_changed && (buffer == iv_str))  return buffer;

  unsigned long nz;
  unsigned long my_start = start - 1;
  unsigned long my_end   = my_start + n;

  nz = (smival.value.oid.len * (SNMPCHARSIZE + 1)) + 1;

  if (buffer) delete [] buffer;  // delete the previous output string

  buffer = new char[nz];  // allocate some space for the output string
  if (buffer == 0)
    return 0;

  buffer[0] = 0;  // init the string

  // cannot ask for more than there is..
  if ((start == 0) || (my_end > smival.value.oid.len))
    return buffer;

  char *cur_ptr = buffer;
  bool first = true;

  // loop through and build up a string
  for (unsigned long index = my_start; index < my_end; ++index)
  {
    // if not at begin, pad with a dot
    if (first)
      first = false;
    else
      *cur_ptr++ = '.';

    // convert data element to a string
    cur_ptr += sprintf(cur_ptr, "%lu", smival.value.oid.ptr[index]);
  }

  if (buffer == iv_str)
  {
    Oid *nc_this = PP_CONST_CAST(Oid*, this);
    nc_this->m_changed = false;
  }

  return buffer;
}


//=============[Oid::StrToOid(char *string, SmiLPOID dst) ]==============
// convert a string to an oid
int Oid::StrToOid(const char *str, SmiLPOID dstOid) const
{
  unsigned int index = 0;

  // make a temp buffer to copy the data into first
  SmiLPUINT32 temp;
  unsigned int nz;

  if (str && *str)
  {
    nz = SAFE_UINT_CAST(strlen(str));
  }
  else
  {
    dstOid->len = 0;
    dstOid->ptr = 0;
    return -1;
  }
  temp = (SmiLPUINT32) new unsigned long[nz];

  if (temp == 0) return -1;   // return if can't get the mem

  while ((*str) && (index < nz))
  {
    // skip over the dot
    if (*str == '.') ++str;

    // convert digits
    if (my_isdigit(*str))
    {
      unsigned long number = 0;

      // grab a digit token and convert it to a long int
      while (my_isdigit(*str))
        number = (number * 10) + *(str++) - '0';

      // stuff the value into the array and bump the counter
      temp[index++] = number;

      // there must be a dot or end of string now
      if ((*str) && (*str != '.'))
      {
        delete [] temp;
        return -1;
      }
    }

    // check for other chars
    if ((*str) && (*str != '.'))
    {
      // found String -> converting it into an oid
      if (*str != '$')
      {
        delete [] temp;
        return -1;
      }

      // skip $
      ++str;

      // copy until second $
      while ((*str) && (*str != '$'))
      {
        temp[index] = (unsigned char)*str;
        ++str;
        ++index;
      }

      if (*str != '$')
      {
        delete [] temp;
        return -1;
      }

      // skip over the $
      ++str;

      // there must be a dot or end of string now
      if ((*str) && (*str != '.'))
      {
        delete [] temp;
        return -1;
      }
    }
  }

  // get some space for the real oid
  dstOid->ptr = (SmiLPUINT32) new unsigned long[index];
  // return if can't get the mem needed
  if(dstOid->ptr == 0)
  {
    delete [] temp;
    return -1;
  }

  // copy in the temp data
  memcpy((SmiLPBYTE) dstOid->ptr,
         (SmiLPBYTE) temp,
         (size_t) (index*sizeof(SmiUINT32)));

  // set the len of the oid
  dstOid->len = index;

  // free up temp data
  delete [] temp;

  return (int) index;
}

//================[Oid::OidToStr ]=========================================
// convert an oid to a string
int Oid::OidToStr(const SmiOID *srcOid,
                  SmiUINT32 size,
                  char *str) const
{
  unsigned totLen = 0;
  char szNumber[SNMPBUFFSIZE];

  str[0] = 0;   // init the string

  // verify there is something to copy
  if (srcOid->len == 0)
    return -1;

  // loop through and build up a string
  for (unsigned long index = 0; index < srcOid->len; ++index)
  {
    // convert data element to a string
    int cur_len = sprintf(szNumber, "%lu", srcOid->ptr[index]);

    // verify len is not over
    if (totLen + cur_len + 1 >= size)
      return -2;

    // if not at begin, pad with a dot
    if (totLen)
      str[totLen++] = '.';

    // copy the string token into the main string
    strcpy(str + totLen, szNumber);

    // adjust the total len
    totLen += cur_len;
  }
  return totLen+1;
}


//================[ general Value = operator ]========================
SnmpSyntax& Oid::operator=(const SnmpSyntax &val)
{
  if (this == &val) return *this; // protect against assignment from self

  delete_oid_ptr();

  // assign new value
  if (val.valid())
  {
    switch (val.get_syntax())
    {
      case sNMP_SYNTAX_OID:
        set_data(((Oid &)val).smival.value.oid.ptr,
                  (unsigned int)((Oid &)val).smival.value.oid.len);
        break;
    }
  }
  return *this;
}

int Oid::get_asn1_length() const
{
  int length = 1; // for first 2 subids

  for (unsigned int i = 2; i < smival.value.oid.len; ++i)
  {
    unsigned long v = smival.value.oid.ptr[i];

    if      (v <       0x80) //  7 bits long subid 
      length += 1;
    else if (v <     0x4000) // 14 bits long subid
      length += 2;
    else if (v <   0x200000) // 21 bits long subid
      length += 3;
    else if (v < 0x10000000) // 28 bits long subid
      length += 4;
    else                     // 32 bits long subid
      length += 5;
  }

  if (length < 128)
    return length + 2;
  else if (length < 256)
    return length + 3;
  return length + 4;
}

#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif 
