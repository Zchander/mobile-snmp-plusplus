/*_############################################################################
  _## 
  _##  idea.cpp  
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
char idea_cpp_version[]="#(@) SNMP++ $Id: idea.cpp 43 2004-03-03 23:11:21Z katz $";
/*

idea.c

Author: Tatu Ylonen <ylo@cs.hut.fi>

Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
                   All rights reserved

Created: Sun Jun 25 02:59:39 1995 ylo

This code is based on Xuejia Lai: On the Design and Security of Block
Ciphers, ETH Series in Information Processing, vol. 1, Hartung-Gorre
Verlag, Konstanz, Switzerland, 1992.  Another source was Bruce
Schneier: Applied Cryptography, John Wiley & Sons, 1994.

The IDEA mathematical formula may be covered by one or more of the
following patents: PCT/CH91/00117, EP 0 482 154 B1, US Pat. 5,214,703.

*/

//#include "snmp_pp/includes.h"
//#include "snmp_pp/getput.h"
#include "snmp_pp/idea.h"
#include <string.h>

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

#ifdef _USE_IDEA

/* Sets idea key for encryption. */

void idea_set_key(IDEAContext *c, const unsigned char key[16])
{
  int i;
  word16 *keys;

  /* Get pointer to the keys. */
  keys = c->key_schedule;

  /* Keys for the first round are directly taken from the user-supplied key. */
  for (i = 0; i < 8; i++)
    keys[i] = (word16)GET_16BIT(key + 2 * i);

  /* Each round uses the key of the previous key, rotated to the left by 25
     bits.  The last four keys (output transform) are the first four keys
     from what would be the ninth round. */
  for (i = 8; i < 52; i++)
    {
      if ((i & 7) == 0)
	keys += 8;
      keys[i & 7] = ((keys[((i + 1) & 7) - 8] << 9) |
		     (keys[((i + 2) & 7) - 8] >> 7)) & 0xffff;
    }
}

/* Destroys any sensitive data in the context. */

void idea_destroy_context(IDEAContext *c)
{
  memset(&c, 0, sizeof(c));
}

/* Performs the "multiplication" operation of IDEA: returns a*b mod 65537,
   where a and b are first converted to 65536 if they are zero, and result
   65536 is converted to zero.  Both inputs should be less than 65536.
   Only the lower 16 bits of result are significant; other bits are garbage.
   */

static inline word32 mulop(word32 a, word32 b)
{
  word32 ab = a * b;
  if (ab != 0)
    {
      word32 lo = ab & 0xffff;
      word32 hi = (ab >> 16) & 0xffff;
      return (lo - hi) + (lo < hi);
    }
  if (a == 0)
    return 1 - b;
  return  1 - a;
}

/* Performs the IDEA cipher transform on a block of data. */

void idea_transform(IDEAContext *c, word32 l, word32 r, word32 *output)
{
  unsigned int round;
  word16 *keys;
  word32 t1, t2, x1, x2, x3, x4;

  keys = c->key_schedule;
  x1 = l >> 16;
  x2 = l;
  x3 = r >> 16;
  x4 = r;
  for (round = 0; round < 8; round++)
    {
      x1 = mulop(x1 & 0xffff, keys[0]);
      x3 = x3 + keys[2];
      x4 = mulop(x4 & 0xffff, keys[3]);
      x2 = x2 + keys[1];
      t1 = x1 ^ x3;
      t2 = x2 ^ x4;
      t1 = mulop(t1 & 0xffff, keys[4]);
      t2 = t1 + t2;
      t2 = mulop(t2 & 0xffff, keys[5]);
      t1 = t1 + t2;
      x1 = x1 ^ t2;
      x4 = x4 ^ t1;
      t1 = t1 ^ x2;
      x2 = t2 ^ x3;
      x3 = t1;
      keys += 6;
    }

  x1 = mulop(x1 & 0xffff, keys[0]);
  x3 = (x2 + keys[2]) & 0xffff;
  x2 = t1 + keys[1]; /* t1 == old x3 */
  x4 = mulop(x4 & 0xffff, keys[3]);
  output[0] = (x1 << 16) | (x2 & 0xffff);
  output[1] = (x3 << 16) | (x4 & 0xffff);
}

/* Encrypts len bytes from src to dest in CFB mode.  Len need not be a multiple
   of 8; if it is not, iv at return will contain garbage.
   Otherwise, iv will be modified at end to a value suitable for continuing
   encryption. */

void idea_cfb_encrypt(IDEAContext *c, unsigned char *iv, unsigned char *dest,
		      const unsigned char *src, unsigned int len)
{
  word32 iv0, iv1, out[2];
  unsigned int i;

  iv0 = GET_32BIT(iv);
  iv1 = GET_32BIT(iv + 4);

  for (i = 0; i < len; i += 8)
    {
      idea_transform(c, iv0, iv1, out);
      iv0 = out[0] ^ GET_32BIT(src + i);
      iv1 = out[1] ^ GET_32BIT(src + i + 4);
      if (i + 8 <= len)
	{
	  PUT_32BIT(dest + i, iv0);
	  PUT_32BIT(dest + i + 4, iv1);
	}
      else
	{
	  switch (len - i)
	    {
	    case 7:
	      dest[i + 6] = iv1 >> 8;
	      /*FALLTHROUGH*/
	    case 6:
	      dest[i + 5] = iv1 >> 16;
	      /*FALLTHROUGH*/
	    case 5:
	      dest[i + 4] = iv1 >> 24;
	      /*FALLTHROUGH*/
	    case 4:
	      dest[i + 3] = iv0;
	      /*FALLTHROUGH*/
	    case 3:
	      dest[i + 2] = iv0 >> 8;
	      /*FALLTHROUGH*/
	    case 2:
	      dest[i + 1] = iv0 >> 16;
	      /*FALLTHROUGH*/
	    case 1:
	      dest[i] = iv0 >> 24;
	      /*FALLTHROUGH*/
	    }
	}
    }
  PUT_32BIT(iv, iv0);
  PUT_32BIT(iv + 4, iv1);
}

/* Decrypts len bytes from src to dest in CFB mode.  Len need not be a multiple
   of 8; if it is not, iv at return will contain garbage.
   Otherwise, iv will be modified at end to a value suitable for continuing
   decryption. */

void idea_cfb_decrypt(IDEAContext *c, unsigned char *iv, unsigned char *dest,
		      const unsigned char *src, unsigned int len)
{
  word32 iv0, iv1, out[2], plain0, plain1;
  unsigned int i;

  iv0 = GET_32BIT(iv);
  iv1 = GET_32BIT(iv + 4);

  for (i = 0; i < len; i += 8)
    {
      idea_transform(c, iv0, iv1, out);
      iv0 = GET_32BIT(src + i);
      iv1 = GET_32BIT(src + i + 4);
      plain0 = out[0] ^ iv0;
      plain1 = out[1] ^ iv1;
      if (i + 8 <= len)
	{
	  PUT_32BIT(dest + i, plain0);
	  PUT_32BIT(dest + i + 4, plain1);
	}
      else
	{
	  switch (len - i)
	    {
	    case 7:
	      dest[i + 6] = plain1 >> 8;
	      /*FALLTHROUGH*/
	    case 6:
	      dest[i + 5] = plain1 >> 16;
	      /*FALLTHROUGH*/
	    case 5:
	      dest[i + 4] = plain1 >> 24;
	      /*FALLTHROUGH*/
	    case 4:
	      dest[i + 3] = plain0;
	      /*FALLTHROUGH*/
	    case 3:
	      dest[i + 2] = plain0 >> 8;
	      /*FALLTHROUGH*/
	    case 2:
	      dest[i + 1] = plain0 >> 16;
	      /*FALLTHROUGH*/
	    case 1:
	      dest[i] = plain0 >> 24;
	      /*FALLTHROUGH*/
	    }
	}
    }
  PUT_32BIT(iv, iv0);
  PUT_32BIT(iv + 4, iv1);
}

#endif

#ifdef SNMP_PP_NAMESPACE
}; // end of namespace Snmp_pp
#endif 
