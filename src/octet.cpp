/*_############################################################################
  _## 
  _##  octet.cpp  
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

  O C T E T . C P P

  OCTETSTR CLASS IMPLEMENTATION

  DESIGN + AUTHOR:  Peter E Mellquist

  DESCRIPTION:
  This class is fully contained and does not rely on or any other
  SNMP libraries. This class is portable across any platform
  which supports C++.
=====================================================================*/
char octet_cpp_version[]="@(#) SNMP++ $Id$";

#include <libsnmp.h>

#include "snmp_pp/octet.h"    // include definition for octet class

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

enum OctetStr::OutputType OctetStr::hex_output_type
                                               = OctetStr::OutputHexAndClear;
char OctetStr::nonprintable_char = '.';

#ifdef __unix
    char OctetStr::linefeed_chars[3] = "\n";
#else
    char OctetStr::linefeed_chars[3] = "\r\n";
#endif // __unix


//============[ constructor using no arguments ]======================
OctetStr::OctetStr()
  : output_buffer(0), output_buffer_len(0), m_changed(true), validity(true)
{
  smival.syntax = sNMP_SYNTAX_OCTETS;
  smival.value.string.ptr = 0;
  smival.value.string.len = 0;
}

//============[ constructor using a  string ]=========================
OctetStr::OctetStr(const char *str)
  : output_buffer(0), output_buffer_len(0), m_changed(true), validity(true)
{
  smival.syntax = sNMP_SYNTAX_OCTETS;
  smival.value.string.ptr = 0;
  smival.value.string.len = 0;

  size_t z;

  // check for null string
  if (!str || !((z = strlen(str))))
    return;

  // get mem needed
  smival.value.string.ptr = (SmiLPBYTE) new unsigned char[z];

  if (smival.value.string.ptr)
  {
    memcpy(smival.value.string.ptr, str, z);
    smival.value.string.len = SAFE_INT_CAST(z);
  }
  else
    validity = false;
}


//============[ constructor using an unsigned char * ]================
OctetStr::OctetStr(const unsigned char *str, unsigned long len)
  : output_buffer(0), output_buffer_len(0), m_changed(true), validity(true)
{
  smival.syntax = sNMP_SYNTAX_OCTETS;
  smival.value.string.ptr = 0;
  smival.value.string.len = 0;

  if (!str || !len)  return;   // check for zero len

  // get the mem needed
  smival.value.string.ptr = (SmiLPBYTE) new unsigned char[len];

  if (smival.value.string.ptr)
  {
    memcpy(smival.value.string.ptr, str, (size_t) len);
    smival.value.string.len = len;
  }
  else
    validity = false;
}

//============[ constructor using another octet object ]==============
OctetStr::OctetStr(const OctetStr &octet)
  : output_buffer(0), output_buffer_len(0), m_changed(true), validity(true)
{
  smival.syntax = sNMP_SYNTAX_OCTETS;
  smival.value.string.ptr = 0;
  smival.value.string.len = 0;

  if (octet.smival.value.string.len == 0) return;  // check for zero len case

  // must be a valid object
  if (!octet.validity)
  {
    validity = false;
    return;
  }

  // get the mem needed
  smival.value.string.ptr = (SmiLPBYTE) new unsigned char[octet.smival.value.string.len];

  if (smival.value.string.ptr)
  {
    memcpy(smival.value.string.ptr,
	   octet.smival.value.string.ptr,
	   (size_t) octet.smival.value.string.len);
    smival.value.string.len = octet.smival.value.string.len;
  }
  else
    validity = false;
}

//=============[ destructor ]=========================================
OctetStr::~OctetStr()
{
  // if not empty, free it up
  if (smival.value.string.ptr) delete [] smival.value.string.ptr;
  smival.value.string.len = 0;
  smival.value.string.ptr = 0;
  if (output_buffer)           delete [] output_buffer;
  output_buffer = 0;
  output_buffer_len = 0;
}


//============[ set the data on an already constructed Octet ]============
void OctetStr::set_data(const unsigned char *str, unsigned long len)
{
  // free up already used space
  if (smival.value.string.ptr)
  {
    delete [] smival.value.string.ptr;
    smival.value.string.ptr = 0;
  }
  smival.value.string.len = 0;
  m_changed = true;

  // check for zero len
  if (!str || !len)
  {
    validity = true;
    return;
  }

  // get the mem needed
  smival.value.string.ptr = (SmiLPBYTE) new unsigned char[len];

  if (smival.value.string.ptr)
  {
    memcpy(smival.value.string.ptr, str, len);
    smival.value.string.len = len;
    validity = true;
  }
  else
    validity = false;
}

//=============[ assignment to a string operator overloaded ]=========
OctetStr& OctetStr::operator=(const char *str)
{
  set_data((const unsigned char*)str, (str ? strlen(str) : 0));
  return *this;	     // return self reference
}

//=============[ assignment to another oid object overloaded ]========
OctetStr& OctetStr::operator=(const OctetStr &octet)
{
  if (this == &octet)  return *this; // protect against assignment from self

  if (!octet.validity) return *this; // don't assign from invalid objs

  set_data(octet.smival.value.string.ptr, octet.smival.value.string.len);

  return *this;		       // return self reference
}

//==============[ equivlence operator overloaded ]====================
int operator==(const OctetStr &lhs, const OctetStr &rhs)
{
  if (lhs.smival.value.string.len != rhs.smival.value.string.len)
    return false;
  return (lhs.nCompare(rhs.smival.value.string.len, rhs) == 0);
}

//==============[ not equivlence operator overloaded ]================
int operator!=(const OctetStr &lhs, const OctetStr &rhs)
{
  if (lhs.smival.value.string.len != rhs.smival.value.string.len)
    return true;
  return (lhs.nCompare(rhs.smival.value.string.len, rhs) != 0);
}

//==============[ less than < overloaded ]============================
int operator<(const OctetStr &lhs, const OctetStr &rhs)
{
  int maxlen = lhs.smival.value.string.len > rhs.smival.value.string.len
             ? lhs.smival.value.string.len : rhs.smival.value.string.len;
  return (lhs.nCompare(maxlen, rhs) < 0);
}

//==============[ less than <= overloaded ]===========================
int operator<=(const OctetStr &lhs, const OctetStr &rhs)
{
  int maxlen = lhs.smival.value.string.len > rhs.smival.value.string.len
             ? lhs.smival.value.string.len : rhs.smival.value.string.len;
  return (lhs.nCompare(maxlen, rhs) <= 0);
}

//===============[ greater than > overloaded ]========================
int operator>(const OctetStr &lhs, const OctetStr &rhs)
{
  int maxlen = lhs.smival.value.string.len > rhs.smival.value.string.len
             ? lhs.smival.value.string.len : rhs.smival.value.string.len;
  return (lhs.nCompare(maxlen, rhs) > 0);
}

//===============[ greater than >= overloaded ]=======================
int operator>=(const OctetStr &lhs, const OctetStr &rhs)
{
  int maxlen = lhs.smival.value.string.len > rhs.smival.value.string.len
             ? lhs.smival.value.string.len : rhs.smival.value.string.len;
  return (lhs.nCompare(maxlen, rhs) >=0);
}

//===============[ equivlence operator overloaded ]===================
int operator==(const OctetStr &lhs, const char *rhs)
{
  OctetStr to(rhs);
  if (lhs.smival.value.string.len != to.smival.value.string.len)
    return false;
  return (lhs.nCompare(to.smival.value.string.len, to) == 0);
}

//===============[ not equivlence operator overloaded ]===============
int operator!=(const OctetStr &lhs, const char *rhs)
{
  OctetStr to(rhs);
  if (lhs.smival.value.string.len != to.smival.value.string.len)
    return true;
  return (lhs.nCompare(to.smival.value.string.len, to) != 0);
}

//===============[ less than < operator overloaded ]==================
int operator<(const OctetStr &lhs, const char *rhs)
{
  OctetStr to(rhs);
  int maxlen = lhs.smival.value.string.len > to.smival.value.string.len
             ? lhs.smival.value.string.len : to.smival.value.string.len;
  return (lhs.nCompare(maxlen,to) < 0);
}

//===============[ less than <= operator overloaded ]=================
int operator<=(const OctetStr &lhs, const char *rhs)
{
  OctetStr to(rhs);
  int maxlen = lhs.smival.value.string.len > to.smival.value.string.len
             ? lhs.smival.value.string.len : to.smival.value.string.len;
  return (lhs.nCompare(maxlen, to) <= 0);
}

//===============[ greater than > operator overloaded ]===============
int operator>(const OctetStr &lhs, const char *rhs)
{
  OctetStr to(rhs);
  int maxlen = lhs.smival.value.string.len > to.smival.value.string.len
             ? lhs.smival.value.string.len : to.smival.value.string.len;
  return (lhs.nCompare(maxlen, to) > 0);
}

//===============[ greater than >= operator overloaded ]==============
int operator>=(const OctetStr &lhs, const char *rhs)
{
  OctetStr to(rhs);
  int maxlen = lhs.smival.value.string.len > to.smival.value.string.len
             ? lhs.smival.value.string.len : to.smival.value.string.len;
  return (lhs.nCompare(maxlen, to) >= 0);
}

//===============[ append operator, appends a string ]================
OctetStr& OctetStr::operator+=(const char *a)
{
  unsigned char *tmp;
  size_t slen, nlen;

  // get len of string
  if (!a || ((slen = strlen(a)) == 0))
    return *this;

  nlen = slen + (size_t) smival.value.string.len;  // total len of new octet
  tmp = (SmiLPBYTE) new unsigned char[nlen];  // get mem needed

  if (tmp)
  {
    // copy in the original 1st
    memcpy(tmp, smival.value.string.ptr, smival.value.string.len);
    // copy in the string
    memcpy(tmp + smival.value.string.len, a, slen);
    // delete the original
    if (smival.value.string.ptr)
      delete [] smival.value.string.ptr;
    // point to the new one
    smival.value.string.ptr = tmp;
    smival.value.string.len = SAFE_INT_CAST(nlen);

    m_changed = true;
    validity = true;
  }
  return *this;
}

//================[ append one OctetStr to another ]==================
OctetStr& OctetStr::operator+=(const OctetStr& octet)
{
  unsigned char *tmp;
  size_t slen, nlen;

  if (!octet.validity || !((slen = (size_t)octet.len())))
    return *this;

  nlen = slen + (size_t) smival.value.string.len;  // total len of new octet
  tmp = (SmiLPBYTE) new unsigned char[nlen];  // get mem needed

  if (tmp)
  {
    // copy in the original 1st
    memcpy(tmp, smival.value.string.ptr, smival.value.string.len);
    // copy in the string
    memcpy(tmp + smival.value.string.len, octet.data(), slen);
    // delete the original
    if (smival.value.string.ptr )
      delete [] smival.value.string.ptr;
    // point to the new one
    smival.value.string.ptr = tmp;
    smival.value.string.len = SAFE_INT_CAST(nlen);

    m_changed = true;
    validity = true;
  }
  return *this;
}

//================[ appends a char ]==================================
OctetStr& OctetStr::operator+=(const unsigned char c)
{
  unsigned char *tmp;

  // get the memory needed plus one extra byte
  tmp = (SmiLPBYTE) new unsigned char[smival.value.string.len + 1];

  if (tmp)
  {
    memcpy(tmp, smival.value.string.ptr, smival.value.string.len);
    tmp[smival.value.string.len] = c; 	// assign in new byte

    if (smival.value.string.ptr)	// delete the original
      delete [] smival.value.string.ptr;

    smival.value.string.ptr = tmp;	// point to new one
    smival.value.string.len++;	   	// up the len

    m_changed = true;
    validity = true;
  }
  return *this;		   		  // return self reference
}

//================[ compare n elements of an Octet ]==================
int OctetStr::nCompare(const unsigned long n, const OctetStr &o) const
{
  unsigned long n_max;
  unsigned long w,str_len;

  if (n == 0) return 0; // Nothing to compare, strings are equal

  // both are empty, they are equal
  if ((smival.value.string.len == 0) && (o.smival.value.string.len == 0))
    return 0;  // equal

  // self is empty and param has something
  if ((smival.value.string.len == 0) && (o.smival.value.string.len > 0))
    return -1;

  // self has something and param has nothing
  if ((smival.value.string.len > 0) && (o.smival.value.string.len == 0))
    return 1;

  // now: n > 0; this.len > 0; o.len > 0 !!!

  // pick the Min of n, this and the param len
  // this is the maximum # to iterate a search
  str_len = smival.value.string.len < o.smival.value.string.len
	    ? smival.value.string.len : o.smival.value.string.len;
  w = (n <= str_len) ? n : str_len;

  unsigned long z = 0;
  while (z < w)
  {
    if (smival.value.string.ptr[z] < o.smival.value.string.ptr[z])
      return -1;				// less than
    if (smival.value.string.ptr[z] > o.smival.value.string.ptr[z])
      return 1;				// greater than
    z++;
  }

  // now: z == w > 0
  // set n_max to min(n, max(len of strings))
  n_max = smival.value.string.len > o.smival.value.string.len
          ? smival.value.string.len : o.smival.value.string.len;
  if (n< n_max) n_max = n;

  if (w < n_max) // ==> we have compared too few bytes
  {
    if (smival.value.string.len < o.smival.value.string.len)
      return -1;
    else
      return 1;
  }
  return 0;
}

//================[ ASCII format return ]=============================
const char *OctetStr::get_printable() const
{
  if ((m_changed == false) &&
      (output_last_function == OutputFunctionDefault))
    return output_buffer;

  for (unsigned long i=0; i < smival.value.string.len; i++)
  {
    if ((smival.value.string.ptr[i] != '\r')&&
	(smival.value.string.ptr[i] != '\n')&&
	(isprint((int) (smival.value.string.ptr[i]))==0))
      switch (hex_output_type)
      {
        case OutputClear:        return get_printable_clear();
        case OutputHexAndClear:
        case OutputHex:
        default:                 return get_printable_hex();
      }
  }

  OctetStr *ncthis = PP_CONST_CAST(OctetStr*, this);
  if (output_buffer_len < smival.value.string.len + 1)
  {
    if (output_buffer) delete [] ncthis->output_buffer;

    ncthis->output_buffer = new char[smival.value.string.len + 1];
    if (!ncthis->output_buffer)
    {
      ncthis->output_buffer_len = 0;
      return output_buffer;
    }
    ncthis->output_buffer_len = smival.value.string.len + 1;
  }
  if (smival.value.string.len)
    memcpy(ncthis->output_buffer,
	   smival.value.string.ptr, (unsigned int) smival.value.string.len);
  ncthis->output_buffer[smival.value.string.len] = '\0';

  ncthis->m_changed = false;
  ncthis->output_last_function = OutputFunctionDefault;

  return output_buffer;
}

//================[ ASCII format return ]=============================
const char *OctetStr::get_printable_clear() const
{
  if ((m_changed == false) &&
      (output_last_np_char == nonprintable_char) &&
      (output_last_function == OutputFunctionClear))
    return output_buffer;

  OctetStr *ncthis = PP_CONST_CAST(OctetStr*, this);
  if (output_buffer_len < smival.value.string.len + 1)
  {
    if (output_buffer) delete [] ncthis->output_buffer;

    ncthis->output_buffer = new char[smival.value.string.len + 1];
    if (!ncthis->output_buffer)
    {
      ncthis->output_buffer_len = 0;
      return output_buffer;
    }
    ncthis->output_buffer_len = smival.value.string.len + 1;
  }

  if (smival.value.string.len)
  {
    for (unsigned long i=0; i < smival.value.string.len; i++)
    {
      if (isprint((int) (smival.value.string.ptr[i]))==0)
        ncthis->output_buffer[i] = nonprintable_char;
      else
        ncthis->output_buffer[i] = smival.value.string.ptr[i];
    }
  }

  ncthis->output_buffer[smival.value.string.len] = '\0';

  ncthis->output_last_np_char = nonprintable_char;
  ncthis->m_changed = false;
  ncthis->output_last_function = OutputFunctionClear;

  return output_buffer;
}


//================[ general Value = operator ]========================
SnmpSyntax& OctetStr::operator=(const SnmpSyntax &val)
{
  if (this == &val) return *this;  // protect against assignment from self

  // blow away the old value
  if (smival.value.string.ptr)
  {
    delete [] smival.value.string.ptr;
    smival.value.string.ptr = 0;
  }
  smival.value.string.len = 0;
  validity = false;

  if (val.valid()){
    switch (val.get_syntax()){
      case sNMP_SYNTAX_OPAQUE:
      case sNMP_SYNTAX_BITS:
      case sNMP_SYNTAX_OCTETS:
      case sNMP_SYNTAX_IPADDR:
	set_data(((OctetStr &)val).smival.value.string.ptr,
		 ((OctetStr &)val).smival.value.string.len);
	break;
    }
  }
  m_changed = true;
  return *this;
}

#define ATOI(x)  if      ((x >= 48) && (x <= 57)) x = x-48; /* 0-9 */ \
                 else if ((x >= 65) && (x <= 70)) x = x-55; /* A-F */ \
		 else if ((x >= 97) && (x <=102)) x = x-87; /* a-f */ \
	         else x = 0

//=======[ create an octet string from a hex string ]===================
OctetStr OctetStr::from_hex_string(const OctetStr &hex_string)
{
  OctetStr val;
  unsigned int p;
  unsigned int hex_len = 0;

  // make sure the string has at least one byte
  if (hex_string.len() == 0) return val;

  // allocate max needed space for copy without spaces
  unsigned char *hex, *hex_ptr;
  hex = hex_ptr = new unsigned char[hex_string.len()];
  if (!hex) return val;

  // delete spaces
  const unsigned char *ptr = hex_string.smival.value.string.ptr;
  for (p = hex_string.len(); p > 0; p--)
  {
    unsigned char c = *ptr++;
    if (c != ' ')
    {
      *hex_ptr++ = c;
      ++hex_len;
    }
  }

  // leading 0 may be omitted
  if (hex_len % 2)
  {
    unsigned char c = hex[0];
    ATOI(c);
    val += c;
    p = 1;
  }
  else
  {
    p = 0;
  }

  while (p < hex_len)
  {
    unsigned char c = hex[p++];
    unsigned char d = hex[p++];

    ATOI(c);
    ATOI(d);
    val += (c*16 + d);
  }
  delete[] hex;
  return val;
}

#undef ATOI

//================[ format the output into hex ]========================
const char *OctetStr::get_printable_hex() const
{
  if ((m_changed == false) && (output_last_type == hex_output_type) &&
      (output_last_np_char == nonprintable_char) &&
      (output_last_function == OutputFunctionHex))
    return output_buffer;

  int cnt;
  char char_buf[80];              // holds ASCII representation of data
  char *buf_ptr;                  // pointer into ASCII listing
  char *line_ptr;                 // pointer into Hex listing
  unsigned int  storageNeeded;    // how much space do we need ?
  int  local_len = (int) smival.value.string.len;
  unsigned char *bytes = smival.value.string.ptr;

  storageNeeded = (unsigned int) ((smival.value.string.len/16)+1) * 72 + 1;
  OctetStr *ncthis = PP_CONST_CAST(OctetStr*, this);

  if (output_buffer_len < storageNeeded)
  {
    if (output_buffer)  delete [] ncthis->output_buffer;

    ncthis->output_buffer = new char[storageNeeded];
    if (!ncthis->output_buffer)
    {
      ncthis->output_buffer_len = 0;
      return output_buffer;
    }
    ncthis->output_buffer_len = storageNeeded;
    output_buffer[0] = 0;
  }

  line_ptr = ncthis->output_buffer;

  /*----------------------------------------*/
  /* processing loop for entire data buffer */
  /*----------------------------------------*/
  while (local_len > 0)
  {
    cnt	     = 16;	  /* print 16 bytes per line */
    buf_ptr  = char_buf;
    sprintf(line_ptr, "  ");
    line_ptr += 2;  /* indent */

    /*-----------------------*/
    /* process a single line */
    /*-----------------------*/
    while (cnt-- > 0 && local_len-- > 0)
    {
      sprintf(line_ptr, "%2.2X ", *bytes);

      line_ptr +=3;   /* the display of a byte always 3 chars long */
      if (isprint(*bytes))
	*buf_ptr++ = *bytes;
      else
	*buf_ptr++ = nonprintable_char;
      ++bytes;
    }
    ++cnt;
    *buf_ptr = 0; // null terminate string

    /*----------------------------------------------------------*/
    /* this is to make sure that the ASCII displays line up for */
    /* incomplete lines of hex                                  */
    /*----------------------------------------------------------*/
    while (cnt-- > 0)
    {
      *line_ptr++ = ' ';
      *line_ptr++ = ' ';
      *line_ptr++ = ' ';
    }

    /*------------------------------------------*/
    /* append the ASCII display to the Hex line */
    /*------------------------------------------*/
    if (hex_output_type == OutputHex)
      char_buf[0] = 0;

    sprintf(line_ptr,"   %s%s", char_buf, linefeed_chars);
    line_ptr += 3 + strlen(char_buf) + strlen(linefeed_chars);
  }

  ncthis->output_last_type = hex_output_type;
  ncthis->output_last_np_char = nonprintable_char;
  ncthis->m_changed = false;
  ncthis->output_last_function = OutputFunctionHex;

  return output_buffer;
}


//==============[ Null out the contents of the string ]===================
void OctetStr::clear()
{
  if (smival.value.string.len > 0)
  {
    memset(smival.value.string.ptr, 0, smival.value.string.len);
    smival.value.string.len = 0;
  }

  if (output_buffer)
    memset(output_buffer, 0, output_buffer_len);
  m_changed = true;
}

//============[Return the space needed for serialization]=================
int OctetStr::get_asn1_length() const
{
  if (smival.value.string.len < 0x80)
    return smival.value.string.len + 2;
  else if (smival.value.string.len < 0x100)
    return smival.value.string.len + 3;
  else if (smival.value.string.len < 0x10000)
    return smival.value.string.len + 4;
  else if (smival.value.string.len < 0x1000000)
    return smival.value.string.len + 5;
  return smival.value.string.len + 6; // should be safe for some time...
}

//========[Set the character for linefeeds in get_printable() functions]====
bool OctetStr::set_linefeed_chars(const char* lf_chars)
{
    if (!lf_chars) return false;
    if (strlen(lf_chars) > 2) return false;

    strcpy(linefeed_chars, lf_chars);

    return true;
}

//===============[ append or shorten the data buffer ]================
bool OctetStr::set_len(const unsigned long new_len)
{
  if (new_len <= smival.value.string.len)
  {
    smival.value.string.len = new_len;
    m_changed = true;

    if (new_len == 0)
    {
      if (smival.value.string.ptr) delete [] smival.value.string.ptr;
      smival.value.string.ptr = 0;
    }

    validity = true;
    return true;
  }

  unsigned char *tmp = new unsigned char[new_len]; // get mem needed
  if (!tmp) return false;

  if (smival.value.string.ptr)
    memcpy(tmp, smival.value.string.ptr, smival.value.string.len);
  memset(tmp + smival.value.string.len, 0, new_len - smival.value.string.len);
  if (smival.value.string.ptr)
    delete [] smival.value.string.ptr;
  smival.value.string.ptr = tmp;
  smival.value.string.len = new_len;

  m_changed = true;
  validity = true;

  return true;
}

#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif
