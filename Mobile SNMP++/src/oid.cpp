/*_############################################################################
  _## 
  _##  oid.cpp  
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

  O I D. C P P

  OID CLASS IMPLEMENTATION

  DESIGN + AUTHOR:         Peter E. Mellquist

  DESCRIPTION:
  This module contains the implementation of the oid class. This
  includes all protected and public member functions. The oid class
  may be compiled stand alone without the use of any other library.
=====================================================================*/
char oid_cpp_version[]="#(@) SNMP++ $Id: oid.cpp 1742 2010-04-29 19:08:54Z katz $";

//---------[ external C libaries used ]--------------------------------
#include <stdio.h>                // standard io
#if !(defined (CPU) && CPU == PPC603)
#include <memory.h>               // memcpy's
#endif
#include <string.h>               // strlen, etc..
#include <stdlib.h>               // standard library
#include <ctype.h>                // isdigit
#include <stdlib.h>               // malloc, free

#include "snmp_pp/oid.h"                  // include def for oid class

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

#define  SNMPBUFFSIZE 11          // size of scratch buffer
#define  SNMPCHARSIZE 11          // an individual oid instance as a string

/* Borlands isdigit has a bug */
#ifdef __BCPLUSPLUS__
#define my_isdigit(c) ((c) >= '0' && (c) <= '9')
#else
#define my_isdigit isdigit
#endif

//=============[Oid::Oid(void)]============================================
// constructor using no arguments
// initialize octet ptr and string
// ptr to null
Oid::Oid() : iv_str(0), iv_part_str(0), m_changed(true)
{
  smival.syntax = sNMP_SYNTAX_OID;
  smival.value.oid.len = 0;
  smival.value.oid.ptr = 0;
}


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


//=============[Oid::Oid(const Oid &oid) ]================================
// constructor using another oid object
//
// do an oid copy using the oid object passed in
Oid::Oid(const Oid &oid)
  : iv_str(0), iv_part_str(0), m_changed(true)
{
  smival.syntax = sNMP_SYNTAX_OID;
  smival.value.oid.len = 0;
  smival.value.oid.ptr = 0;

  // allocate some memory for the oid
  // in this case the size to allocate is the same size as the source oid
  if (oid.smival.value.oid.len)
  {
    smival.value.oid.ptr = (SmiLPUINT32) new unsigned long[oid.smival.value.oid.len];
    if (smival.value.oid.ptr)
      OidCopy((SmiLPOID)&(oid.smival.value.oid), (SmiLPOID)&smival.value.oid);
  }
}


//=============[Oid::Oid(const unsigned long *raw_oid, int oid_len) ]====
// constructor using raw numeric form
//
// copy the integer values into the private member
Oid::Oid(const unsigned long *raw_oid, int oid_len)
  : iv_str(0), iv_part_str(0), m_changed(true)
{
  smival.syntax = sNMP_SYNTAX_OID;
  smival.value.oid.len = 0;
  smival.value.oid.ptr = 0;

  if (raw_oid && (oid_len > 0))
  {
    smival.value.oid.ptr = (SmiLPUINT32) new unsigned long[oid_len];
    if (smival.value.oid.ptr)
    {
      smival.value.oid.len = oid_len;
      for (int i=0; i < oid_len; i++)
        smival.value.oid.ptr[i] = raw_oid[i];
    }
  }
}

//=============[Oid::~Oid]==============================================
Oid::~Oid()
{
  delete_oid_ptr();
  if (iv_str)      delete [] iv_str;        // free up the output string
  if (iv_part_str) delete [] iv_part_str;   // free up the output string
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


//=============[Oid:: operator = const Oid &oid ]==========================
// assignment to another oid object overloaded
//
// free the existing oid
// create a new one from the object passed in
Oid& Oid::operator=(const Oid &oid)
{
  if (this == &oid) return *this;  // protect against assignment from self

  delete_oid_ptr();

  // check for zero len on source
  if (oid.smival.value.oid.len == 0)
    return *this;

  // allocate some memory for the oid
  smival.value.oid.ptr = (SmiLPUINT32) new unsigned long[oid.smival.value.oid.len];
  if (smival.value.oid.ptr)
    OidCopy((SmiLPOID)&(oid.smival.value.oid), (SmiLPOID)&smival.value.oid);
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
    /// @todo optimze this function (avoid conversion to string)
    OidToStr(&smival.value.oid, n, ptr);
    if (ptr[0])
      STRCAT(ptr,".");
    STRCAT(ptr,a);

    delete_oid_ptr();

    StrToOid(ptr, &smival.value.oid);
    delete [] ptr;
  }
  return *this;
}

//=============[ int operator == oid,oid ]=================================
// equivlence operator overloaded
int operator==(const Oid &lhs, const Oid &rhs)
{
  // ensure same len, then use nCompare
  if (rhs.len() != lhs.len()) return 0;
  return (lhs.nCompare(rhs.len(), rhs) == 0);
}

//==============[ operator<(Oid &x,Oid &y) ]=============================
// less than < overloaded
int operator<(const Oid &lhs, const Oid &rhs)
{
  int result;
  // call nCompare with the current
  // Oidx, Oidy and len of Oidx
  if((result = lhs.nCompare(rhs.len(), rhs))<0)  return 1;
  if (result > 0)    return 0;

  // if here, equivalent substrings, call the shorter one <
  return (lhs.len() < rhs.len());
}

//==============[ operator==(Oid &x,char *) ]=============================
// equivlence operator overloaded
int operator==(const Oid &x, const char *dotted_oid_string)
{
  Oid to(dotted_oid_string);   // create a temp oid object
  return (x == to);   // compare using existing operator
}

//==============[ operator!=(Oid &x,char*) ]=============================
// not equivlence operator overloaded
int operator!=(const Oid &x, const char *dotted_oid_string)
{
  Oid to(dotted_oid_string);  // create a temp oid object
  return (x != to);  // compare using existing operator
}

//==============[ operator<(Oid &x,char*) ]=============================
// less than < operator overloaded
int operator<(const Oid &x, const char *dotted_oid_string)
{
  Oid to(dotted_oid_string);  // create a temp oid object
  return (x < to);  // compare using existing operator
}

//==============[ operator<=(Oid &x,char *) ]=============================
// less than <= operator overloaded
int operator<=(const Oid &x,char *dotted_oid_string)
{
  Oid to(dotted_oid_string);  // create a temp oid object
  return (x <= to);  // compare using existing operator
}

//==============[ operator>(Oid &x,char* ]=============================
// greater than > operator overloaded
int operator>(const Oid &x,const char *dotted_oid_string)
{
  Oid to(dotted_oid_string);  // create a temp oid object
  return (x > to);   // compare using existing operator
}

//==============[ operator>=(Oid &x,char*) ]=============================
// greater than >= operator overloaded
int operator>=(const Oid &x,const char *dotted_oid_string)
{
  Oid to(dotted_oid_string);  // create a temp oid object
  return (x >= to);   // compare using existing operator
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
  MEMCPY((SmiLPBYTE) smival.value.oid.ptr,
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

//===============[Oid::trim(unsigned int) ]============================
// trim off the n leftmost values of an oid
// Note!, does not adjust actual space for
// speed
void Oid::trim(const unsigned long n)
{
  // verify that n is legal
  if ((n <= smival.value.oid.len) && (n > 0))
  {
    smival.value.oid.len -= n;
    if (smival.value.oid.len == 0)
      delete_oid_ptr();
    m_changed = true;
  }
}

//===============[Oid::operator += const unsigned int) ]====================
// append operator, appends an int
//
Oid& Oid::operator+=(const unsigned long i)
{
  Oid other(&i, 1);
  (*this) += other;
  return *this;
}

//===============[Oid::operator += const Oid) ]========================
// append operator, appends an Oid
//
// allocate some space for a max oid string
// extract current string into space
// concat new string
// free up existing oid
// make a new oid from string
// delete allocated space
Oid& Oid::operator+=(const Oid &o)
{
  SmiLPUINT32 new_oid;

  if (o.smival.value.oid.len == 0)
    return *this;

  new_oid = (SmiLPUINT32) new unsigned long[smival.value.oid.len + o.smival.value.oid.len];
  if (new_oid == 0)
  {
    delete_oid_ptr();
    return *this;
  }

  if (smival.value.oid.ptr)
  {
    MEMCPY((SmiLPBYTE) new_oid,
           (SmiLPBYTE) smival.value.oid.ptr,
           (size_t) (smival.value.oid.len*sizeof(SmiUINT32)));

    delete [] smival.value.oid.ptr;
  }

  // out with the old, in with the new...
  smival.value.oid.ptr = new_oid;

  MEMCPY((SmiLPBYTE) &new_oid[smival.value.oid.len],
         (SmiLPBYTE) o.smival.value.oid.ptr,
         (size_t) (o.smival.value.oid.len*sizeof(SmiUINT32)));

  smival.value.oid.len += o.smival.value.oid.len;

  m_changed = true;
  return *this;
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
  MEMCPY((SmiLPBYTE) dstOid->ptr,
         (SmiLPBYTE) temp,
         (size_t) (index*sizeof(SmiUINT32)));

  // set the len of the oid
  dstOid->len = index;

  // free up temp data
  delete [] temp;

  return (int) index;
}


//===============[Oid::OidCopy(source, destination) ]====================
// Copy an oid
int Oid::OidCopy(SmiLPOID srcOid, SmiLPOID dstOid) const
{
  // check source len ! zero
  if (srcOid->len == 0) return -1;

  // copy source to destination
  MEMCPY((SmiLPBYTE) dstOid->ptr,
         (SmiLPBYTE) srcOid->ptr,
         (size_t) (srcOid->len*sizeof(SmiUINT32)));

  //set the new len
  dstOid->len = srcOid->len;
  return (int) srcOid->len;
}


//===============[Oid::nCompare(n, Oid) ]=================================
// compare the n leftmost values of two oids (left-to_right )
//
// self == Oid then return 0, they are equal
// self < Oid then return -1, <
// self > Oid then return 1,  >
int Oid::nCompare(const unsigned long n,
                  const Oid &o) const
{
  unsigned long length = n;
  bool reduced_len = false;

  // If both oids are too short, decrease len
  while ((smival.value.oid.len < length) && (o.smival.value.oid.len < length))
    length--;

  if (length == 0) return 0; // equal
    
  // only compare for the minimal length
  if (length > smival.value.oid.len)
  {
    length = smival.value.oid.len;
    reduced_len = true;
  }
  if (length > o.smival.value.oid.len)
  {
    length = o.smival.value.oid.len;
    reduced_len = true;
  }

  unsigned long z = 0;
  while (z < length)
  {
    if (smival.value.oid.ptr[z] < o.smival.value.oid.ptr[z])
      return -1;                              // less than
    if (smival.value.oid.ptr[z] > o.smival.value.oid.ptr[z])
      return 1;                               // greater than
    ++z;
  }

  // if we truncated the len then these may not be equal
  if (reduced_len)
  {
    if (smival.value.oid.len < o.smival.value.oid.len) return -1;
    if (smival.value.oid.len > o.smival.value.oid.len) return 1;
  }
  return 0;                                 // equal
}

//================[Oid::OidToStr ]=========================================
// convert an oid to a string
int Oid::OidToStr(const SmiOID *srcOid,
                  SmiUINT32 size,
                  char *str) const
{
  unsigned totLen = 0;
  char szNumber[SNMPBUFFSIZE];
  int cur_len;

  str[0] = 0;   // init the string

  // verify there is something to copy
  if (srcOid->len == 0)
    return -1;

  // loop through and build up a string
  for (unsigned long index = 0; index < srcOid->len; ++index)
  {
    // convert data element to a string
    cur_len = sprintf(szNumber, "%lu", srcOid->ptr[index]);

    // verify len is not over
    if (totLen + cur_len + 1 >= size)
      return -2;

    // if not at begin, pad with a dot
    if (totLen)
      str[totLen++] = '.';

    // copy the string token into the main string
    STRCPY(str + totLen, szNumber);

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
}; // end of namespace Snmp_pp
#endif 
