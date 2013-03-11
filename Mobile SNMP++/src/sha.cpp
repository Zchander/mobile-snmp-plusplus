/*_############################################################################
  _## 
  _##  sha.cpp  
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
char sha_cpp_version[]="#(@) SNMP++ $Id: sha.cpp 1549 2009-06-26 19:42:55Z katz $";

#include "snmp_pp/sha.h"

#if !defined(_USE_LIBTOMCRYPT) && !defined(_USE_OPENSSL)

/*****************************************************************
 * SHS.c  -  Secure Hash Standard (draft) FIPS 180-1             *
 *                                                               *
 * Copyright (C) 1994  Uri Blumenthal, uri@watson.ibm.com        *
 * Copyright (C) 1994  IBM T. J. Watson esearch Center           *
 *                                                               *
 * Feel free to use this code,  as long as you acknowledge the   *
 * ownership by U. Blumenthal and IBM Corp.  and agree to hold   *
 * both harmless in case of ANY problem you may have with this   *
 * code.                                                         *
 *****************************************************************/

#if !(defined (CPU) && CPU == PPC603)
#include <memory.h>
#else
#include <string.h>
#endif
#include <stdio.h>

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

#define K1 0x5A827999
#define K2 0x6ED9EBA1
#define K3 0x8F1BBCDC
#define K4 0xCA62C1D6

#define F1(B, C, D) ((B & C) | (~B & D))
#define F2(B, C, D) (B ^ C ^ D)
#define F3(B, C, D) ((B & C) | (B & D) | (C & D))
#define F4(B, C, D) (B ^ C ^ D)

#define ROL(A, K) ((A << K) | (A >> (32 - K)))

#if !defined(i386) && !defined(_IBMR2)
static int msb_flag = 0;    /* ENDIAN-ness of CPU    */
#endif

static void SHATransform(SHA_CTX *ctx, const unsigned char *X)
{
  unsigned /* long */ int a, b, c, d, e, temp = 0;
  unsigned /* long */ int W[80]; /* Work array for SHS    */
  int i;

#ifdef _IBMR2
    unsigned long int *p = (unsigned long int *)X;
    memcpy((char *)&W[0], p, 64);
#else
#ifndef i386
  unsigned long int *p = (unsigned long int *)X;
  if (msb_flag)
    memcpy((char *)&W[0], p, 64);
  else
#endif /* ~i386 */
    for (i = 0; i < 64; i += 4)
      W[(i/4)] = X[i+3] | (X[i+2] << 8) |
	(X[i+1] << 16) | (X[i] << 24);
#endif /* _IBMR2 */

  for (i = 16; i < 80; i++)
    W[i] = ROL((W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16]), 1);

  a = ctx->h[0];
  b = ctx->h[1];
  c = ctx->h[2];
  d = ctx->h[3];
  e = ctx->h[4];

  for (i =  0; i <= 19; i++) {
    temp = ROL(a, 5) + F1(b, c, d) + e + K1 + W[i];
    e = d; d = c; c = ROL(b, 30); b = a; a = temp;
  }

  for (i = 20; i <= 39; i++) {
    temp = ROL(a, 5) + F2(b, c, d) + e + K2 + W[i];
    e = d; d = c; c = ROL(b, 30); b = a; a = temp;
  }

  for (i = 40; i <= 59; i++) {
    temp = ROL(a, 5) + F3(b, c, d) + e + K3 + W[i];
    e = d; d = c; c = ROL(b, 30); b = a; a = temp;
  }

  for (i = 60; i <= 79; i++) {
    temp = ROL(a, 5) + F4(b, c, d) + e + K4 + W[i];
    e = d; d = c; c = ROL(b, 30); b = a; a = temp;
  }

  ctx->h[0] += a;
  ctx->h[1] += b;
  ctx->h[2] += c;
  ctx->h[3] += d;
  ctx->h[4] += e;
}


void SHAInit(SHA_CTX *ctx)
{
#if !defined(i386) && !defined(_IBMR2)
  union z_test {
    unsigned char ch[4];
    unsigned long ll;
  } z_t;
#endif
  /* Zero the SHS Context */
  memset((char *)ctx, 0, sizeof(*ctx));

  /* Prime the SHS with "magic" init constants */
  ctx->h[0] = 0x67452301;
  ctx->h[1] = 0xEFCDAB89;
  ctx->h[2] = 0x98BADCFE;
  ctx->h[3] = 0x10325476;
  ctx->h[4] = 0xC3D2E1F0;

#if !defined(i386) && !defined(_IBMR2)
  /* Determine the ENDIAN-ness of the CPU */
  z_t.ll = 0;

  z_t.ch[0] = 0x01;

  if (z_t.ll == 0x01000000)
    msb_flag = 1;
  else {
    if (z_t.ll == 0x00000001)
      msb_flag = 0;
    else
      printf("ENDIAN-ness is SCREWED! (%0#lx)\n", z_t.ll);
  }
#endif /* ~_IBMR2 & ~i386 */
}


void SHAUpdate(SHA_CTX *ctx, const unsigned char *buf, unsigned int lenBuf)
{
  /* Do we have any bytes? */
  if (lenBuf == 0) return;

  /* Calculate buf len in bits and update the len count */
  ctx->count[0] += (lenBuf << 3);
  if (ctx->count[0] < (lenBuf << 3))
    ctx->count[1] += 1;
  ctx->count[1] += (lenBuf >> 29);

  /* Fill the hash working buffer for the first run, if  */
  /* we have enough data...                              */
  int i = 64 - ctx->index;  /* either fill it up to 64 bytes */
  if ((int)lenBuf < i) i = lenBuf; /* or put the whole data...*/

  lenBuf -= i;  /* Reflect the data we'll put in the buf */

  /* Physically put the data in the hash workbuf */
  memcpy((char *)&(ctx->X[ctx->index]), buf, i);
  buf += i; ctx->index += i;

  /* Adjust the buf index */
  if (ctx->index == 64)
    ctx->index = 0;

  /* Let's see whether we're equal to 64 bytes in buf  */
  if (ctx->index == 0)
    SHATransform(ctx, ctx->X);

  /* Process full 64-byte blocks */
  while(lenBuf >= 64) {
    lenBuf -= 64;
    SHATransform(ctx, buf);
    buf += 64;
  }

  /* Put the rest of data in the hash buf for next run */
  if (lenBuf > 0) {
    memcpy(ctx->X, buf, lenBuf);
    ctx->index = lenBuf;
  }
}


void SHAFinal(unsigned char *digest, SHA_CTX *ctx)
{
  int i;
  unsigned long int c0, c1;
  unsigned char truelen[8];
  static unsigned char padding[64] = {
    0x80, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  /*  8 */
    0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  /* 16 */
    0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  /* 24 */
    0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  /* 32 */
    0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  /* 40 */
    0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  /* 48 */
    0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,  /* 56 */
    0x00, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}; /* 64 */
					
  /* Store the message length to append after */
  /* padding is done... */

#ifdef _IBMR2
    memcpy(truelen, (char *) &(ctx->count[1]), 4);
    memcpy(&truelen[4], (char *) &(ctx->count[0]), 4);
#else
#ifndef i386
  if (msb_flag) {
    memcpy(truelen, (char *) &(ctx->count[1]), 4);
    memcpy(&truelen[4], (char *) &(ctx->count[0]), 4);
  } else
#endif /* ~i386 */
  {
    c0 = ctx->count[0]; c1 = ctx->count[1];
    for (i = 7; i >=0; i--) {
      truelen[i] = (unsigned char) (c0 & 0xff);
      c0 = (c0 >> 8) | (((c1 >> 8) & 0xff) << 24);
      c1 = (c1 >> 8);
    }
  }
#endif /* _IBMR2 */

  /* How many padding bytes do we need? */
  i = (ctx->count[0] >> 3) & 0x3f;  /* # of bytes mod 64 */
  if (i >= 56) i = 120 - i; /* # of padding bytes needed */
  else i = 56 - i;


  SHAUpdate(ctx, padding, i);   /* Append the padding */
  SHAUpdate(ctx, truelen, 8);   /* Append the length  */

#ifdef _IBMR2
    memcpy(digest, (char *)&ctx->h[0], 20);
#else
#ifndef i386
  if (msb_flag)
    memcpy(digest, (char *)&ctx->h[0], 20);
  else
#endif /* ~i386 */
    for (i = 0; i < 4; i++) {
      digest[3-i]  = (unsigned char) (ctx->h[0] & 0xff);
      ctx->h[0] >>= 8;
      digest[7-i]  = (unsigned char) (ctx->h[1] & 0xff);
      ctx->h[1] >>= 8;
      digest[11-i] = (unsigned char) (ctx->h[2] & 0xff);
      ctx->h[2] >>= 8;
      digest[15-i] = (unsigned char) (ctx->h[3] & 0xff);
      ctx->h[3] >>= 8;
      digest[19-i] = (unsigned char) (ctx->h[4] & 0xff);
      ctx->h[4] >>= 8;
    }
#endif /* _IBMR2 */
}

#ifdef SNMP_PP_NAMESPACE
}; // end of namespace Snmp_pp
#endif 

#endif // !defined(_USE_LIBTOMCRYPT) && !defined(_USE_OPENSSL)
