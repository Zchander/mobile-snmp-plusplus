/*_############################################################################
  _## 
  _##  auth_priv.cpp  
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

#include <libsnmp.h>

#include "snmp_pp/config_snmp_pp.h"

#ifdef _SNMPv3

// Only use DES, AES, SHA1 and MD5 from libtomcrypt if openssl is not used
#if defined(_USE_LIBTOMCRYPT) && !defined(_USE_OPENSSL)
#include <tomcrypt.h>
#endif

// Use DES, AES, SHA and MD5 from openssl
#ifdef _USE_OPENSSL
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#endif

// Use internal functions for SHA and MD5 and libdes only
// if not using libtomcrypt and openssl
#if !defined(_USE_LIBTOMCRYPT) && !defined(_USE_OPENSSL)
#include "snmp_pp/sha.h"
#ifdef RSAEURO
#include <rsaeuro.h>
#else
#include <des.h>
#include "snmp_pp/md5.h"
#endif
#endif // !defined(_USE_LIBTOMCRYPT) && !defined(_USE_OPENSSL)

// IDEA can only be used with a valid license
#ifdef _USE_IDEA
#include "snmp_pp/idea.h"
#endif

#include "snmp_pp/auth_priv.h"
#include "snmp_pp/v3.h"
#include "snmp_pp/snmperrs.h"
#include "snmp_pp/address.h"
#include "snmp_pp/log.h"

#include <memory>

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

static const char *loggerModuleName = "snmp++.auth";

/*-----------------[ defines for crypto libraries ]------------------*/

#ifdef _USE_OPENSSL

/* -- START: Defines for OpenSSL -- */

#if OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)
// OpenSSL versions up to 1.0.x and LibreSSL
typedef EVP_MD_CTX            EVPHashStateType;

int evpAllocAndInit(EVP_MD_CTX *ctx, const EVP_MD *md)
{
  // no Alloc needed
  return EVP_DigestInit(ctx, md);
}

#define evpDigestUpdate(s, p, l) EVP_DigestUpdate(s, p, l)

int evpDigestFinalAndFree(EVP_MD_CTX *ctx, unsigned char *digest)
{
  // no free needed
  return EVP_DigestFinal(ctx, digest, NULL);
}

typedef EVP_MD_CTX            SHAHashStateType;
#define SHA1_INIT(s)          EVP_DigestInit(s, EVP_sha1())
#define SHA1_PROCESS(s, p, l) EVP_DigestUpdate(s, p, l)
#define SHA1_DONE(s, k)       EVP_DigestFinal(s, k, NULL)

typedef EVP_MD_CTX            MD5HashStateType;
#define MD5_INIT(s)           EVP_DigestInit(s, EVP_md5())
#define MD5_PROCESS(s, p, l)  EVP_DigestUpdate(s, p, l)
#define MD5_DONE(s, k)        EVP_DigestFinal(s, k, NULL)

#else
// OpenSSL since 1.1.0

typedef EVP_MD_CTX*           EVPHashStateType;

int evpAllocAndInit(EVP_MD_CTX **ctx, const EVP_MD *md)
{
  *ctx = EVP_MD_CTX_new();
  return EVP_DigestInit(*ctx, md);
}

#define evpDigestUpdate(s, p, l) EVP_DigestUpdate(*(s), p, l)

int evpDigestFinalAndFree(EVP_MD_CTX **ctx, unsigned char *digest)
{
  int result = EVP_DigestFinal(*ctx, digest, NULL);
  EVP_MD_CTX_free(*ctx);
  return result;
}


typedef EVP_MD_CTX*           SHAHashStateType;
#define SHA1_INIT(s)          evpAllocAndInit(s, EVP_sha1())
#define SHA1_PROCESS(s, p, l) EVP_DigestUpdate(*(s), p, l)
#define SHA1_DONE(s, k)       evpDigestFinalAndFree(s, k)

typedef EVP_MD_CTX*           MD5HashStateType;
#define MD5_INIT(s)           evpAllocAndInit(s, EVP_md5())
#define MD5_PROCESS(s, p, l)  EVP_DigestUpdate(*(s), p, l)
#define MD5_DONE(s, k)        evpDigestFinalAndFree(s, k)

#endif // OPENSSL_VERSION_NUMBER < 0x10100000L || defined(LIBRESSL_VERSION_NUMBER)

typedef DES_key_schedule      DESCBCType;
#define DES_CBC_START_ENCRYPT(c, iv, k, kl, r, s) \
          if (DES_key_sched((const_DES_cblock*)(k), &(s)) < 0)  \
          { \
            debugprintf(0, "Starting DES encryption failed."); \
            return SNMPv3_USM_ERROR; \
          }
#define DES_CBC_START_DECRYPT(c, iv, k, kl, r, s) \
          if (DES_key_sched((const_DES_cblock*)(k), &(s)) < 0) \
          { \
             debugprintf(0, "Starting DES decryption failed."); \
             return SNMPv3_USM_ERROR; \
          }

#define DES_CBC_ENCRYPT(pt, ct, s, iv, l) \
          DES_ncbc_encrypt(pt, ct, l, \
			   &(s), (const_DES_cblock*)(iv), DES_ENCRYPT)
#define DES_CBC_DECRYPT(ct, pt, s, iv, l) \
          DES_ncbc_encrypt(ct, pt, l, \
			   &(s), (const_DES_cblock*)(iv), DES_DECRYPT)

#define DES_EDE3_CBC_ENCRYPT(pt, ct, l, k1, k2, k3, iv) \
          DES_ede3_cbc_encrypt(pt, ct, l, \
			       &(k1), &(k2), &(k3), (const_DES_cblock*)(iv), DES_ENCRYPT)

#define DES_EDE3_CBC_DECRYPT(ct, pt, l, k1, k2, k3, iv) \
          DES_ede3_cbc_encrypt(ct, pt, l, \
			       &(k1), &(k2), &(k3), (const_DES_cblock*)(iv), DES_DECRYPT)

#define DES_MEMSET(s, c, l)   memset(&(s), c, l)

/* -- END: Defines for OpenSSL -- */

#else

#ifdef _USE_LIBTOMCRYPT

/* -- START: Defines for LibTomCrypt -- */
typedef hash_state            SHAHashStateType;
#define SHA1_INIT(s)          sha1_init(s)
#define SHA1_PROCESS(s, p, l) sha1_process(s, p, l)
#define SHA1_DONE(s, k)       sha1_done(s, k)

typedef hash_state            MD5HashStateType;
#define MD5_INIT(s)           md5_init(s)
#define MD5_PROCESS(s, p, l)  md5_process(s, p, l)
#define MD5_DONE(s, k)        md5_done(s, k)

typedef symmetric_CBC         DESCBCType;
#define DES_CBC_START_ENCRYPT(c, iv, k, kl, r, s) \
                 if (cbc_start(c, iv, k, kl, r, &(s)) != CRYPT_OK) \
                 { \
                   debugprintf(0, "Starting DES encryption failed."); \
                   return SNMPv3_USM_ERROR; \
                 }

#define DES_CBC_START_DECRYPT(c, iv, k, kl, r, s) \
                 if (cbc_start(c, iv, k, kl, r, &(s)) != CRYPT_OK) \
                 { \
                   debugprintf(0, "Starting DES decryption failed."); \
                   return SNMPv3_USM_ERROR; \
                 }

#define DES_CBC_ENCRYPT(pt, ct, s, iv, l) \
                 if (cbc_encrypt(pt, ct, l, &(s)) != CRYPT_OK) \
                 { \
                   debugprintf(0, "Error during DES encryption."); \
                   return SNMPv3_USM_ERROR; \
                 }
#define DES_CBC_DECRYPT(ct, pt, s, iv, l) \
                 if (cbc_decrypt(ct, pt, l, &(s)) != CRYPT_OK) \
                 { \
                   debugprintf(0, "Error during DES decryption."); \
                   return SNMPv3_USM_ERROR; \
                 }
#define DES_MEMSET(s, c, l)   memset(&(s), c, l)
/* -- END: Defines for LibTomCrypt -- */

#else // _USE_LIBTOMCRYPT  --> libdes

/* -- START: Defines for libdes -- */

typedef SHA_CTX               SHAHashStateType;
#define SHA1_INIT(s)          SHAInit(s)
#define SHA1_PROCESS(s, p, l) SHAUpdate(s, p, l)
#define SHA1_DONE(s, k)       SHAFinal(k, s)

typedef MD5_CTX               MD5HashStateType;
#define MD5_INIT(s)           MD5Init(s)
#define MD5_PROCESS(s, p, l)  MD5Update(s, p, l)
#define MD5_DONE(s, k)        MD5Final(k, s)

#define DES_EDE3_CBC_ENCRYPT(pt, ct, l, k1, k2, k3, iv) \
               des_ede3_cbc_encrypt((C_Block*)(pt), (C_Block*)(ct), l, \
                                    k1, k2, k3, (C_Block*)(iv), DES_ENCRYPT)

#define DES_EDE3_CBC_DECRYPT(ct, pt, l, k1, k2, k3, iv) \
               des_ede3_cbc_encrypt((C_Block*)(ct), (C_Block*)(pt), l, \
                                    k1, k2, k3, (C_Block*)(iv), DES_DECRYPT)

#ifdef RSAEURO

#undef  MD5_PROCESS
#define MD5_PROCESS(s, p, l)  MD5Update(s, (unsigned char*)(p), l)

typedef DES_CBC_CTX           DESCBCType;
#define DES_CBC_START_ENCRYPT(c, iv, k, kl, r, s) \
                              DES_CBCInit(&(s), (unsigned char*)(k), iv, 1)
#define DES_CBC_START_DECRYPT(c, iv, k, kl, r, s) \
                              DES_CBCInit(&(s),(unsigned char*)(k), iv, 0)
#define DES_CBC_ENCRYPT(pt, ct, s, iv, l) DES_CBCUpdate(&(s), pt, ct, l)
#define DES_CBC_DECRYPT(ct, pt, s, iv, l) DES_CBCUpdate(&(s), (unsigned char*)(ct), pt, l)
#define DES_MEMSET(s, c, l)   R_memset((POINTER)&(s), c, l)

#else // RSAEURO

typedef des_key_schedule      DESCBCType;
#define DES_CBC_START_ENCRYPT(c, iv, k, kl, r, s) \
                 if (des_key_sched((C_Block*)(k), s) < 0) \
                 { \
                   debugprintf(0, "Starting DES encryption failed."); \
                   return SNMPv3_USM_ERROR; \
                 }
#define DES_CBC_START_DECRYPT(c, iv, k, kl, r, s) \
                 if (des_key_sched((C_Block*)(k), s) < 0) \
                 { \
                   debugprintf(0, "Starting DES decryption failed."); \
                   return SNMPv3_USM_ERROR; \
                 }

#define DES_CBC_ENCRYPT(pt, ct, s, iv, l) \
                        des_ncbc_encrypt((C_Block*)(pt), (C_Block*)(ct), l, \
                                         s, (C_Block*)(iv), DES_ENCRYPT)
#define DES_CBC_DECRYPT(ct, pt, s, iv, l) \
                        des_ncbc_encrypt((C_Block*)(ct), (C_Block*)(pt), l, \
                                         s, (C_Block*)(iv), DES_DECRYPT)
#define DES_MEMSET(s, c, l)   memset(&(s), c, l)

/* -- END: Defines for libdes -- */

#endif // RSAEURO

#endif // _USE_LIBTOMCRYPT

#endif // _USE_OPENSSL


// 3DES key extension used by two classes
int des3_extend_short_key(const unsigned char * /* password */,
                          const unsigned int    /* password_len */,
                          const unsigned char *engine_id,
                          const unsigned int   engine_id_len,
                          unsigned char       *key,
                          unsigned int        *key_len,
                          const unsigned int   max_key_len,
                          Auth                *auth,
                          const unsigned int min_key_len)
{
  if (max_key_len < min_key_len)
    return SNMPv3_USM_ERROR;

  unsigned int p2k_output_len = *key_len;
  unsigned char *p2k_buf = new unsigned char[p2k_output_len];
  int res = 0;

  if (!p2k_buf) return SNMPv3_USM_ERROR;

  // p2k function takes the old key as input
  unsigned char *p2k_input_buf = key;
  unsigned int   p2k_input_len = *key_len;

  while (*key_len < min_key_len)
  {
    unsigned int p2k_buf_len = p2k_output_len;

    res = auth->password_to_key(p2k_input_buf, p2k_input_len,
                                engine_id, engine_id_len,
                                p2k_buf, &p2k_buf_len);

    if (res != SNMPv3_USM_OK)
      break;

    unsigned int copy_bytes = min_key_len - *key_len;

    if (copy_bytes > p2k_buf_len)
        copy_bytes = p2k_buf_len;

    if (*key_len + copy_bytes > max_key_len)
        copy_bytes = max_key_len - *key_len;

    memcpy(key + *key_len, p2k_buf, copy_bytes);

    // save just generated key for next iteration
    p2k_input_buf = key + *key_len;
    p2k_input_len = p2k_buf_len;

    *key_len += copy_bytes;
  }

  if (p2k_buf) delete [] p2k_buf;

  return res;
}


AuthPriv::AuthPriv(int &construct_state)
{
  auth = new AuthPtr[10];
  priv = new PrivPtr[10];

  if (auth)
    auth_size = 10;
  else
  {
    auth_size = 0;

    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Error allocating array for authentication.");
    LOG_END;
  }

  if (priv)
    priv_size = 10;
  else
  {
    priv_size = 0;

    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Error allocating array for privacy.");
    LOG_END;
  }

  for (int i = 0; i < auth_size; i++)
    auth[i] = 0;

  for (int j = 0; j < priv_size; j++)
    priv[j] = 0;

  /* Check size of salt, has to be 64 bits */
  if (sizeof(salt) != 8)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: *BUG* sizeof(pp_uint64) is not 8 bytes. snmp++ has to be patched for this system.");
    LOG_END;

    construct_state = SNMPv3_USM_ERROR;
    return;
  }

  /* Initialize salt. srand() has been already done in Snmp::init() */
  unsigned int *rnd = (unsigned int*)(void *)&salt;
  for (size_t i = 0; i < sizeof(salt); i += sizeof(unsigned int), rnd++)
  {
    *rnd = rand() << 1;
    if (rand() < (RAND_MAX / 2))
      *rnd += 1;
  }

  construct_state = SNMPv3_USM_OK;

#if defined(_USE_LIBTOMCRYPT) && !defined(_USE_OPENSSL)
  /* register needed hashes and ciphers in libtomcrypt */
  if (register_cipher(&rijndael_desc) < 0)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Error registering Rijndael.");
    LOG_END;

    construct_state = SNMPv3_USM_ERROR;
  }

  if (register_cipher(&des_desc) < 0)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Error registering DES.");
    LOG_END;

    construct_state = SNMPv3_USM_ERROR;
  }

  if (register_cipher(&des3_desc) < 0)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Error registering 3DES.");
    LOG_END;

    construct_state = SNMPv3_USM_ERROR;
  }

  if (register_hash(&sha1_desc) < 0)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Error registering SHA1.");
    LOG_END;

    construct_state = SNMPv3_USM_ERROR;
  }

  if (register_hash(&md5_desc) < 0)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Error registering MD5.");
    LOG_END;

    construct_state = SNMPv3_USM_ERROR;
  }
#endif // defined(_USE_LIBTOMCRYPT) && !defined(_USE_OPENSSL)
}

AuthPriv::~AuthPriv()
{
  for (int i = 0; i < auth_size; i++)
    if (auth[i])
    {
      delete auth[i];
      auth[i] = 0;
    }

  for (int j = 0; j < priv_size; j++)
    if (priv[j])
    {
      delete priv[j];
      priv[j] = 0;
    }

  delete [] auth;
  delete [] priv;
}

int AuthPriv::add_auth(Auth *new_auth)
{
  if (!new_auth)
  {
    return SNMP_CLASS_ERROR;
  }

  int id = new_auth->get_id();

  if (id < 0)
  {
    return SNMP_CLASS_ERROR;
  }

  if (id >= auth_size)
  {
    AuthPtr *new_array = new AuthPtr[id + 5];
    if (!new_array)
    {
      LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
      LOG("AuthPriv: Could not allocate new auth array.");
      LOG_END;

      return SNMP_CLASS_ERROR;
    }
    for (int i=0 ; i<auth_size; i++)
      new_array[i] = auth[i];

    for (int j=auth_size ; j<id + 5; j++)
      new_array[j] = 0;

    AuthPtr *victim = auth;
    auth = new_array;
    delete [] victim;
    auth_size = id + 5;
  }

  new_auth->set_salt(&salt);

  if (auth[id])
  {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 4);
    LOG("AuthPriv: deleting old auth object before adding new one (id)");
    LOG(id);
    LOG_END;

    delete auth[id];
  }

  auth[id] = new_auth;

  LOG_BEGIN(loggerModuleName, INFO_LOG | 6);
  LOG("AuthPriv: Added auth protocol (id)");
  LOG(id);
  LOG_END;

  return SNMP_CLASS_SUCCESS;
}

int AuthPriv::del_auth(const int auth_id)
{
  if ((auth_id < 0) || (auth_id >= auth_size) || (auth[auth_id] == 0))
  {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 4);
    LOG("AuthPriv: Request to delete non existing auth protocol (id)");
    LOG(auth_id);
    LOG_END;

    return SNMP_CLASS_ERROR;
  }

  delete auth[auth_id];
  auth[auth_id] = 0;

  LOG_BEGIN(loggerModuleName, INFO_LOG | 6);
  LOG("AuthPriv: Removed auth protocol (id)");
  LOG(auth_id);
  LOG_END;

  return SNMP_CLASS_SUCCESS;
}


int AuthPriv::add_priv(Priv *new_priv)
{
  if (!new_priv)
  {
    return SNMP_CLASS_ERROR;
  }

  int id = new_priv->get_id();

  if (id < 0)
  {
    return SNMP_CLASS_ERROR;
  }

  if (id >= priv_size)
  {
    PrivPtr *new_array = new PrivPtr[id + 5];
    if (!new_array)
    {
      LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
      LOG("AuthPriv: Could not allocate new priv array.");
      LOG_END;

      return SNMP_CLASS_ERROR;
    }
    for (int i=0 ; i<priv_size; i++)
      new_array[i] = priv[i];

    for (int j=priv_size ; j<id + 5; j++)
      new_array[j] = 0;

    PrivPtr *victim = priv;
    priv = new_array;
    delete [] victim;
    priv_size = id + 5;
  }

  new_priv->set_salt(&salt);

  if (priv[id])
  {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 4);
    LOG("AuthPriv: deleting old priv object before adding new one (id)");
    LOG(id);
    LOG_END;

    delete priv[id];
  }

  priv[id] = new_priv;

  LOG_BEGIN(loggerModuleName, INFO_LOG | 6);
  LOG("AuthPriv: Added priv protocol (id)");
  LOG(id);
  LOG_END;

  return SNMP_CLASS_SUCCESS;
}

int AuthPriv::del_priv(const int priv_id)
{
  if ((priv_id < 0) || (priv_id >= priv_size) || (priv[priv_id] == 0))
  {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 4);
    LOG("AuthPriv: Request to delete non existing priv protocol (id)");
    LOG(priv_id);
    LOG_END;

    return SNMP_CLASS_ERROR;
  }

  delete priv[priv_id];
  priv[priv_id] = 0;

  LOG_BEGIN(loggerModuleName, INFO_LOG | 6);
  LOG("AuthPriv: Removed priv protocol (id)");
  LOG(priv_id);
  LOG_END;

  return SNMP_CLASS_SUCCESS;
}

Auth *AuthPriv::get_auth(const int auth_prot)
{
  if ((auth_prot >= 0) && (auth_prot < auth_size))
    return auth[auth_prot];
  return 0;
}

Priv *AuthPriv::get_priv(const int priv_prot)
{
  if ((priv_prot >= 0) && (priv_prot < priv_size))
    return priv[priv_prot];
  return 0;
}

// Get the unique id for the given auth protocol.
int AuthPriv::get_auth_id(const char *string_id) const
{
  for (int i = 0; i < auth_size; ++i)
    if ((auth[i]) && (strcmp(string_id, auth[i]->get_id_string()) == 0))
      return i;
  return -1;
}

// Get the unique id for the given priv protocol.
int AuthPriv::get_priv_id(const char *string_id) const
{
  for (int i = 0; i < priv_size; ++i)
    if ((priv[i]) && (strcmp(string_id, priv[i]->get_id_string()) == 0))
      return i;
  return -1;
}

int AuthPriv::get_keychange_value(const int       auth_prot,
                                  const OctetStr& old_key,
                                  const OctetStr& new_key,
                                  OctetStr&       keychange_value)
{

  // uses fixed key length determined from oldkey!
  // works with SHA and MD5
  // modifications needed to support variable length keys
  // algorithm according to USM-document textual convention KeyChange

  keychange_value.clear();
  int key_len = old_key.len();

  Auth *a = get_auth(auth_prot);

  if (!a)
    return SNMPv3_USM_UNSUPPORTED_AUTHPROTOCOL;

  // compute random value
  OctetStr random = "";

  for (int i=0; i<key_len; i++) {
#ifdef _TEST
    // do not use random values for testing
    random += OctetStr((unsigned char*)"\0",1);
#else
    char tmprand = rand();
    random += tmprand;
#endif
  }

#ifdef __DEBUG
  debugprintf(21, "Values for keyChange:");
  debughexcprintf(21, "old_key", old_key.data(), old_key.len());
  debughexcprintf(21, "new_key", new_key.data(), new_key.len());
  debughexcprintf(21, "random value", random.data(), random.len());
#endif

  int iterations = (key_len - 1) / a->get_hash_len();
  OctetStr tmp = old_key;
  OctetStr delta;

  for (int k = 0; k < iterations; k++)
  {
      unsigned char digest[SNMPv3_USM_MAX_KEY_LEN];
      memset((char*)digest, 0, SNMPv3_USM_MAX_KEY_LEN);
      tmp += random;
      //debughexcprintf(21, "loop tmp1", tmp.data(), tmp.len());
      a->hash(tmp.data(), tmp.len(), digest);
      tmp.set_data(digest, a->get_hash_len());
      //debughexcprintf(21, "loop tmp2", tmp.data(), tmp.len());
      delta.set_len(delta.len() + a->get_hash_len());
      for (int kk=0; kk < a->get_hash_len(); kk++)
          delta[k * a->get_hash_len() + kk]
              = tmp[kk] ^ new_key[k * a->get_hash_len() + kk];
      //debughexcprintf(21, "loop delta", delta.data(), delta.len());
  }

  unsigned char digest[SNMPv3_USM_MAX_KEY_LEN];
  memset((char*)digest, 0, SNMPv3_USM_MAX_KEY_LEN);
  tmp += random;
  //debughexcprintf(21, " tmp1", tmp.data(), tmp.len());
  a->hash(tmp.data(), tmp.len(), digest);
  tmp.set_data(digest, key_len - delta.len());
  //debughexcprintf(21, " tmp2", tmp.data(), tmp.len());
  for (unsigned int j = 0; j < tmp.len(); j++)
      tmp[j] = tmp[j] ^ new_key[iterations * a->get_hash_len() + j];
  //debughexcprintf(21, " tmp3", tmp.data(), tmp.len());

  keychange_value = random;
  keychange_value += delta;
  keychange_value += tmp;

#ifdef __DEBUG
  debughexcprintf(21, "keychange_value",
                  keychange_value.data(), keychange_value.len());
#endif

  return SNMPv3_USM_OK;
}

int AuthPriv::password_to_key_auth(const int            auth_prot,
                                   const unsigned char *password,
                                   const unsigned int   password_len,
                                   const unsigned char *engine_id,
                                   const unsigned int   engine_id_len,
                                   unsigned char *key,
                                   unsigned int  *key_len)
{
  if (auth_prot == SNMP_AUTHPROTOCOL_NONE)
  {
    *key_len = 0;
    return SNMPv3_USM_OK;
  }

  if (!password || (password_len == 0))
  {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 2);
    LOG("AuthPriv: Password to key auth needs a non empty password");
    LOG_END;

    return SNMPv3_USM_ERROR;
  }

  Auth *a = get_auth(auth_prot);

  if (!a)
    return SNMPv3_USM_UNSUPPORTED_AUTHPROTOCOL;

  int res = a->password_to_key(password, password_len,
                               engine_id, engine_id_len,
                               key, key_len);

  return res;
}


int AuthPriv::password_to_key_priv(const int            auth_prot,
                                   const int            priv_prot,
                                   const unsigned char *password,
                                   const unsigned int   password_len,
                                   const unsigned char *engine_id,
                                   const unsigned int   engine_id_len,
                                   unsigned char *key,
                                   unsigned int  *key_len)
{
  /* check for priv protocol */
  if (priv_prot == SNMP_PRIVPROTOCOL_NONE)
  {
    *key_len = 0;
    return SNMPv3_USM_OK;
  }

  if (!password || (password_len == 0))
  {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 2);
    LOG("AuthPriv: Password to key priv needs a non empty password");
    LOG_END;

    return SNMPv3_USM_ERROR;
  }

  Priv *p = get_priv(priv_prot);
  Auth *a = get_auth(auth_prot);

  if (!p)  return SNMPv3_USM_UNSUPPORTED_PRIVPROTOCOL;
  if (!a)  return SNMPv3_USM_UNSUPPORTED_AUTHPROTOCOL;

  unsigned int max_key_len = *key_len; /* save length of buffer! */
  unsigned int min_key_len = p->get_min_key_len();

  /* check if buffer for key is long enough */
  if (min_key_len > max_key_len)
    return SNMPv3_USM_ERROR; // TODO: better error code!

  int res = password_to_key_auth(auth_prot,
                                 password, password_len,
                                 engine_id, engine_id_len,
                                 key, key_len);
  if (res != SNMPv3_USM_OK)
    return res;

  /* We have a too short key: Call priv protocoll to extend it */
  if (*key_len < min_key_len)
  {
    res = p->extend_short_key(password, password_len,
                              engine_id, engine_id_len,
                              key, key_len, max_key_len, a);
    if (res != SNMPv3_USM_OK)
      return res;
  }

  /* make sure key length is valid */
  p->fix_key_len(*key_len);

  return SNMPv3_USM_OK;
}




int AuthPriv::encrypt_msg(const int            priv_prot,
                          const unsigned char *key,
                          const unsigned int   key_len,
                          const unsigned char *buffer,
                          const unsigned int   buffer_len,
                          unsigned char       *out_buffer,
                          unsigned int        *out_buffer_len,
                          unsigned char       *privacy_params,
                          unsigned int        *privacy_params_len,
                          const unsigned long  engine_boots,
                          const unsigned long  engine_time)
{
  /* check for priv protocol */
  Priv *p = get_priv(priv_prot);

  if (!p)
    return SNMPv3_USM_UNSUPPORTED_PRIVPROTOCOL;

  return p->encrypt(key, key_len, buffer, buffer_len,
                    out_buffer, out_buffer_len,
                    privacy_params, privacy_params_len,
                    engine_boots, engine_time);
}

int AuthPriv::decrypt_msg(const int            priv_prot,
                          const unsigned char *key,
                          const unsigned int   key_len,
                          const unsigned char *buffer,
                          const unsigned int   buffer_len,
                          unsigned char       *out_buffer,
                          unsigned int        *out_buffer_len,
                          const unsigned char *privacy_params,
                          const unsigned int   privacy_params_len,
                          const unsigned long  engine_boots,
                          const unsigned long  engine_time)
{
  /* check for priv protocol */
  Priv *p = get_priv(priv_prot);

  if (!p)
    return SNMPv3_USM_UNSUPPORTED_PRIVPROTOCOL;

  return p->decrypt(key, key_len, buffer, buffer_len,
                    out_buffer, out_buffer_len,
                    privacy_params, privacy_params_len,
                    engine_boots, engine_time);
}


int AuthPriv::add_default_modules()
{
  int ret = SNMP_CLASS_SUCCESS;

  if (add_auth(new AuthSHA()) != SNMP_ERROR_SUCCESS)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Could not add default protocol AuthSHA.");
    LOG_END;

    ret = SNMP_CLASS_ERROR;
  }

#if defined(_USE_OPENSSL)

  if (add_auth(new AuthHMAC128SHA224()) != SNMP_ERROR_SUCCESS)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Could not add default protocol AuthHMAC128SHA224.");
    LOG_END;

    ret = SNMP_CLASS_ERROR;
  }

  if (add_auth(new AuthHMAC192SHA256()) != SNMP_ERROR_SUCCESS)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Could not add default protocol AuthHMAC192SHA256.");
    LOG_END;

    ret = SNMP_CLASS_ERROR;
  }

  if (add_auth(new AuthHMAC256SHA384()) != SNMP_ERROR_SUCCESS)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Could not add default protocol AuthHMAC256SHA384.");
    LOG_END;

    ret = SNMP_CLASS_ERROR;
  }

  if (add_auth(new AuthHMAC384SHA512()) != SNMP_ERROR_SUCCESS)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Could not add default protocol AuthHMAC384SHA512.");
    LOG_END;

    ret = SNMP_CLASS_ERROR;
  }

#endif

  if (add_auth(new AuthMD5()) != SNMP_ERROR_SUCCESS)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Could not add default protocol AuthMD5.");
    LOG_END;

    ret = SNMP_CLASS_ERROR;
  }

  if (add_priv(new PrivDES()) != SNMP_ERROR_SUCCESS)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Could not add default protocol PrivDES.");
    LOG_END;

    ret = SNMP_CLASS_ERROR;
  }

#ifdef _USE_IDEA
  if (add_priv(new PrivIDEA()) != SNMP_ERROR_SUCCESS)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Could not add default protocol PrivIDEA.");
    LOG_END;

    ret = SNMP_CLASS_ERROR;
  }
#endif

#if defined(_USE_LIBTOMCRYPT) || defined(_USE_OPENSSL)
  if (add_priv(new PrivAES(SNMP_PRIVPROTOCOL_AES128)) != SNMP_ERROR_SUCCESS)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Could not add default protocol PrivAES 128.");
    LOG_END;

    ret = SNMP_CLASS_ERROR;
  }

  if (add_priv(new PrivAES(SNMP_PRIVPROTOCOL_AES192)) != SNMP_ERROR_SUCCESS)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Could not add default protocol PrivAES 192.");
    LOG_END;

    ret = SNMP_CLASS_ERROR;
  }

  if (add_priv(new PrivAES(SNMP_PRIVPROTOCOL_AES256)) != SNMP_ERROR_SUCCESS)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Could not add default protocol PrivAES 256.");
    LOG_END;

    ret = SNMP_CLASS_ERROR;
  }
#endif

#ifdef _USE_3DES_EDE
  if (add_priv(new Priv3DES_EDE()) != SNMP_ERROR_SUCCESS)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("AuthPriv: Could not add default protocol Priv3DES_EDE.");
    LOG_END;

    ret = SNMP_CLASS_ERROR;
  }
#endif

  if (ret == SNMP_CLASS_SUCCESS)
  {
    LOG_BEGIN(loggerModuleName, INFO_LOG | 3);
    LOG("AuthPriv: Added default Auth and Priv protocols.");
    LOG_END;
  }

  return ret;
}

int AuthPriv::get_auth_params_len(const int auth_prot)
{
  Auth *a = get_auth(auth_prot);

  if (!a)
    return 0;

  return a->get_auth_params_len();
}

int AuthPriv::get_priv_params_len(const int priv_prot)
{
  Priv *p = get_priv(priv_prot);

  if (!p)
    return 0;

  return p->get_priv_params_len();
}

int AuthPriv::auth_out_msg(const int            auth_prot,
                           const unsigned char *key,
                           unsigned char       *msg,
                           const int            msg_len,
                           unsigned char       *auth_par_ptr)
{
  if (auth_prot == SNMP_AUTHPROTOCOL_NONE)
    return SNMPv3_USM_UNSUPPORTED_SECURITY_LEVEL;

  Auth *a = get_auth(auth_prot);

  if (!a)
    return SNMPv3_USM_UNSUPPORTED_AUTHPROTOCOL;

  return a->auth_out_msg(key, msg, msg_len, auth_par_ptr);
}

int AuthPriv::auth_inc_msg(const int            auth_prot,
                           const unsigned char *key,
                           unsigned char       *msg,
                           const int            msg_len,
                           unsigned char       *auth_par_ptr,
                           const int            auth_par_len)
{
  if (auth_prot == SNMP_AUTHPROTOCOL_NONE)
    return SNMPv3_USM_UNSUPPORTED_SECURITY_LEVEL;

  Auth *a = get_auth(auth_prot);

  if (!a)
    return SNMPv3_USM_UNSUPPORTED_AUTHPROTOCOL;

  /* @todo check if auth par is inside msg
  if ((auth_par_ptr < msg) ||
      (msg + msg_len < auth_par_ptr + auth_par_len))
  {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 1);
    LOG("AuthPriv: Authentication data is not within message (msg start) (len) (auth start) (len)");
    LOG(msg);
    LOG(msg_len);
    LOG(auth_par_ptr);
    LOG(auth_par_len);
    LOG_END;

    return SNMPv3_USM_ERROR;
  }
  */

  return a->auth_inc_msg(key, msg, msg_len, auth_par_ptr, auth_par_len);
}

/* ========================================================== */

/* ----------------------- AuthMD5 ---------------------------------------*/

int AuthMD5::password_to_key(const unsigned char *password,
                             const unsigned int   password_len,
                             const unsigned char *engine_id,
                             const unsigned int   engine_id_len,
                             unsigned char *key,
                             unsigned int *key_len)
{
  *key_len = 16; /* All MD5 keys have 16 bytes length */

#ifdef __DEBUG
  debugprintf(5,"password: %s.",
              OctetStr(password, password_len).get_printable());
  debugprintf(5,"engineID: %s.",
              OctetStr(engine_id, engine_id_len).get_printable());
#endif

  MD5HashStateType md5_hash_state;
  unsigned char password_buf[65];
  unsigned long password_index = 0;
  unsigned long count = 0;

  MD5_INIT(&md5_hash_state);   /* initialize MD5 */

  /**********************************************/
  /* Use while loop until we've done 1 Megabyte */
  /**********************************************/
  while (count < 1048576) {
    unsigned char *cp = password_buf;
    for (unsigned int i = 0; i < 64; i++) {
      /*************************************************/
      /* Take the next octet of the password, wrapping */
      /* to the beginning of the password as necessary.*/
      /*************************************************/
      *cp++ = password[password_index++ % password_len];
    }
    MD5_PROCESS(&md5_hash_state, password_buf, 64);
    count += 64;
  }
  MD5_DONE(&md5_hash_state, key);      /* tell MD5 we're done */

#ifdef __DEBUG
  debughexcprintf(21, "key", key, *key_len);
#endif

  /*****************************************************/
  /* Now localize the key with the engine_id and pass  */
  /* through MD5 to produce final key                  */
  /* May want to ensure that engine_id_len <= 32,      */
  /* otherwise need to use a buffer larger than 64     */
  /*****************************************************/
  memcpy(password_buf,                            key,       *key_len);
  memcpy(password_buf + *key_len,                 engine_id, engine_id_len);
  memcpy(password_buf + *key_len + engine_id_len, key,       *key_len);

  MD5_INIT(&md5_hash_state);
  MD5_PROCESS(&md5_hash_state, password_buf, (2 * *key_len) + engine_id_len);
  MD5_DONE(&md5_hash_state, key);

#ifdef __DEBUG
  debughexcprintf(21, "localized key", key, *key_len);
#endif

  return SNMPv3_USM_OK;
}

int AuthMD5::hash(const unsigned char *data,
                  const unsigned int   data_len,
                  unsigned char       *digest) const
{
  MD5HashStateType md5_hash_state;

  MD5_INIT(&md5_hash_state);
  MD5_PROCESS(&md5_hash_state, data, data_len);
  MD5_DONE(&md5_hash_state, digest);

  return SNMPv3_USM_OK;
}

int AuthMD5::auth_out_msg(const unsigned char *key,
                          unsigned char *msg,
                          const int      msg_len,
                          unsigned char *auth_par_ptr)
{
  MD5HashStateType md5_hash_state;
  int           key_len = 16; /* We use only 16 Byte Key! */
  unsigned char digest[16];
  unsigned char k_ipad[65];   /* inner padding - key XORd with ipad */
  unsigned char k_opad[65];   /* outer padding - key XORd with opad */

  memset((char*)(auth_par_ptr), 0, 12);

#ifdef __DEBUG
  debughexcprintf(21, "key", key, 16);
#endif

  /*
   * the HMAC_MD5 transform looks like:
   *
   * MD5(K XOR opad, MD5(K XOR ipad, msg))
   *
   * where K is an n byte key
   * ipad is the byte 0x36 repeated 64 times
   * opad is the byte 0x5c repeated 64 times
   * and text is the data being protected
   */

  /* start out by storing key in pads */
  memset( (char*)k_ipad, 0, sizeof k_ipad);
  memset( (char*)k_opad, 0, sizeof k_opad);
  memcpy( (char*)k_ipad, (char*)key, key_len);
  memcpy( (char*)k_opad, (char*)key, key_len);

  /* XOR key with ipad and opad values */
  for (int i=0; i<64; i++) {
    k_ipad[i] ^= 0x36;
    k_opad[i] ^= 0x5c;
  }

  /* perform inner MD5 */
  MD5_INIT(&md5_hash_state);            /* init md5_hash_state for 1st pass */
  MD5_PROCESS(&md5_hash_state, k_ipad, 64);    /* start with inner pad      */
  MD5_PROCESS(&md5_hash_state, msg, msg_len);  /* then text of datagram     */
  MD5_DONE(&md5_hash_state, digest);           /* finish up 1st pass        */
  /* perform outer MD5 */
  MD5_INIT(&md5_hash_state);            /* init md5_hash_state for 2nd pass */
  MD5_PROCESS(&md5_hash_state, k_opad, 64);    /* start with outer pad      */
  MD5_PROCESS(&md5_hash_state, digest, 16);    /* then results of 1st hash  */
  MD5_DONE(&md5_hash_state, digest);           /* finish up 2nd pass        */

#ifdef __DEBUG
  debughexcprintf(21, "digest", digest, 128 / 8);
#endif

  memcpy(auth_par_ptr, digest, 12);

  return SNMPv3_USM_OK;
}

int AuthMD5::auth_inc_msg(const unsigned char *key,
                          unsigned char *msg,
                          const int msg_len,
                          unsigned char *auth_par_ptr,
                          const int      auth_par_len)
{
  unsigned char receivedDigest[16];

  if (auth_par_len != 12)
  {
    debugprintf(4, "MD5 illegal digest length (%d), authentication FAILED.",
                auth_par_len);
    return SNMPv3_USM_AUTHENTICATION_FAILURE;
  }

#ifdef __DEBUG
  debughexcprintf(21, "digest in Message", auth_par_ptr, 12);
  debughexcprintf(21, "key", key, 16);
#endif

  memcpy(receivedDigest, auth_par_ptr, 12);

  if (SNMPv3_USM_OK != auth_out_msg(key, msg, msg_len, auth_par_ptr))
  {
    /* copy digest back into message and return error */
    memcpy(auth_par_ptr, receivedDigest, 12);
    debugprintf(4, "MD5 authentication FAILED (1).");
    return SNMPv3_USM_AUTHENTICATION_FAILURE;
  }

  /* compare digest to received digest */
  for (int i=0; i < 12 ; ++i)
  {
    if (auth_par_ptr[i] != receivedDigest[i])
    {
      /* copy digest back into message and return error */
      memcpy(auth_par_ptr, receivedDigest, 12);
      debugprintf(4, "MD5 authentication FAILED.");
      return SNMPv3_USM_AUTHENTICATION_FAILURE;
    }
  }
  debugprintf(4, "MD5 authentication OK.");
  return SNMPv3_USM_OK;
}

/* ========================= PRIV ================================*/

/* ----------------------- PrivDES ---------------------------------------*/

#if defined(_USE_LIBTOMCRYPT) && !defined(_USE_OPENSSL)
PrivDES::PrivDES()
{
  cipher = find_cipher("des");
}
#endif

int PrivDES::encrypt(const unsigned char *key,
                     const unsigned int   /*key_len*/,
                     const unsigned char *buffer,
                     const unsigned int   buffer_len,
                     unsigned char       *out_buffer,
                     unsigned int        *out_buffer_len,
                     unsigned char       *privacy_params,
                     unsigned int        *privacy_params_len,
                     const unsigned long  engine_boots,
                     const unsigned long  /*engine_time*/)
{
  unsigned char initVect[8];
  pp_uint64     my_salt = (*salt)++;

#ifdef INVALID_ENCRYPTION
  debugprintf(-10, "\nWARNING: Encrypting with zeroed salt!\n");
  my_salt = 0;
#endif

  /* check space in privacy_params buffer */
  if (*privacy_params_len < 8)
  {
    debugprintf(4, "Buffer too small: should be 8, is (%i).",
                *privacy_params_len);
    return SNMPv3_USM_ENCRYPTION_ERROR;
  }
  /* Length is always 8 */
  *privacy_params_len = 8;

  // last 8 bytes of key are used as base for initialization vector
  memcpy((char*)initVect, key+8, 8);

  // put salt in privacy_params
  for (int j=0; j<4; j++)
  {
    privacy_params[3-j] = (unsigned char) (0xFF & (engine_boots >> (8*j)));
    privacy_params[7-j] = (unsigned char) (0xFF & (my_salt >> (8*j)));
  }

  // xor initVect with salt
  for (int i=0; i<8; i++)
    initVect[i] ^= privacy_params[i];

#ifdef __DEBUG
  debughexcprintf(21, "apDESEncryptData: Data to encrypt",
                 buffer, buffer_len);
  debughexcprintf(21, "apDESEncryptData: used key (only 8 bytes used)",
                  key, 16);
  debughexcprintf(21, "apDESEncryptData: used iv",
                  initVect, 8);
#endif

  DESCBCType symcbc;
  DES_CBC_START_ENCRYPT(cipher, initVect, key, 8, 16, symcbc);

  for(unsigned int k = 0; k <= buffer_len - 8; k += 8) {
    DES_CBC_ENCRYPT(buffer + k, out_buffer + k, symcbc, initVect, 8);
  }

  /* last part of buffer */
  if (buffer_len % 8)
  {
    unsigned char tmp_buf[8];
    unsigned char *tmp_buf_ptr = tmp_buf;
    int start = buffer_len - (buffer_len % 8);
    memset(tmp_buf, 0, 8);
    for (unsigned int l = start; l < buffer_len; l++)
      *tmp_buf_ptr++ = buffer[l];
    DES_CBC_ENCRYPT(tmp_buf, out_buffer + start, symcbc, initVect, 8);
    *out_buffer_len = buffer_len + 8 - (buffer_len % 8);
  }
  else
    *out_buffer_len = buffer_len;

  /* Clear context buffer (paranoia!)*/
  DES_MEMSET(symcbc, 0, sizeof(symcbc));

#ifdef __DEBUG
  debughexcprintf(21, "apDESEncryptData: created privacy_params",
                  privacy_params, 8);
  debughexcprintf(21, "apDESEncryptData: encrypted Data",
                  out_buffer, *out_buffer_len);
#endif

  return SNMPv3_USM_OK;
}



int PrivDES::decrypt(const unsigned char *key,
                     const unsigned int   /*key_len*/,
                     const unsigned char *buffer,
                     const unsigned int   buffer_len,
                     unsigned char *outBuffer,
                     unsigned int  *outBuffer_len,
                     const unsigned char *privacy_params,
                     const unsigned int   privacy_params_len,
                     const unsigned long  /*engine_boots*/,
                     const unsigned long  /*engine_time*/)
{
  unsigned char initVect[8];

  /* Privacy params length has to be 8  && Length has to be a multiple of 8 */
  if (( buffer_len % 8 ) || (privacy_params_len != 8))
    return SNMPv3_USM_DECRYPTION_ERROR;

  for (int i=0; i<8; i++)
    initVect[i] = privacy_params[i] ^ key[i+8];

  memset((char*)outBuffer, 0, *outBuffer_len);

#ifdef __DEBUG
  debughexcprintf(21, "apDESDecryptData: Data to decrypt",
                  buffer, buffer_len);
  debughexcprintf(21, "apDESDecryptData: used key (only 8 bytes used)",
                  key, 16);
  debughexcprintf(21, "apDESDecryptData: used privacy_params",
                  privacy_params, 8);
  debughexcprintf(21, "apDESDecryptData: used iv",
                  initVect, 8);
#endif

  DESCBCType symcbc;
  DES_CBC_START_DECRYPT(cipher, initVect, key, 8, 16, symcbc);
  for(unsigned int j=0; j<buffer_len; j+=8 ) {
    DES_CBC_DECRYPT(buffer + j, outBuffer + j, symcbc, initVect, 8);
  }
  /* Clear context (paranoia!) */
  DES_MEMSET(symcbc, 0, sizeof(symcbc));

  *outBuffer_len = buffer_len;

#ifdef __DEBUG
  debughexcprintf(21, "apDESDecryptData: decrypted Data",
                  outBuffer, *outBuffer_len);
#endif

  return SNMPv3_USM_OK;
}


/* ----------------------- PrivIDEA --------------------------------------*/

#ifdef _USE_IDEA

int PrivIDEA::encrypt(const unsigned char *key,
                      const unsigned int   /*key_len*/,
                      const unsigned char *buffer,
                      const unsigned int   buffer_len,
                      unsigned char       *out_buffer,
                      unsigned int        *out_buffer_len,
                      unsigned char       *privacy_params,
                      unsigned int        *privacy_params_len,
                      const unsigned long  engine_boots,
                      const unsigned long  /*engine_time*/)
{
  IDEAContext CFB_Context;
  pp_uint64 my_salt = (*salt)++;

#ifdef INVALID_ENCRYPTION
  debugprintf(-10, "\nWARNING: Encrypting with zeroed salt!\n");
  my_salt = 0;
#endif

  /* check space in privacy_params buffer */
  if (*privacy_params_len < 8)
  {
    debugprintf(4, "Buffer too small: should be 8, is (%i).", *privacy_params_len);
    return SNMPv3_USM_ENCRYPTION_ERROR;
  }
  /* Length is always 8 */
  *privacy_params_len = 8;

  // last 8 bytes of key are used as base for initialization vector
  unsigned char iv[8];

  memcpy((char*)iv, key+8, 8);

  // put salt in privacy_params
  for (int j=0; j<4; j++)
  {
    privacy_params[3-j] = (unsigned char) (0xFF & (engine_boots >> (8*j)));
    privacy_params[7-j] = (unsigned char) (0xFF & (my_salt >> (8*j)));
  }
  // xor iv with privacy_params
  for (int i=0; i<8; i++)
    iv[i] ^= privacy_params[i];

  idea_set_key(&CFB_Context, key);

  idea_cfb_encrypt(&CFB_Context, iv, out_buffer,
                   buffer, buffer_len);

  /* Clear context (paranoia!) */
  idea_destroy_context(&CFB_Context);

  *out_buffer_len = buffer_len;

#ifdef __DEBUG
  debughexcprintf(21, "apIDEAEncryptData: Data to encrypt",
                  buffer, buffer_len);
  debughexcprintf(21, "apIDEAEncryptData: key",
                  key, 16);
  debughexcprintf(21, "apIDEAEncryptData: privacy_params",
                  privacy_params, 8);
  debughexcprintf(21, "apIDEAEncryptData: encrypted Data",
                  out_buffer, *out_buffer_len);
#endif

  return SNMPv3_USM_OK;
}

int PrivIDEA::decrypt(const unsigned char *key,
                      const unsigned int   /*key_len*/,
                      const unsigned char *buffer,
                      const unsigned int   buffer_len,
                      unsigned char *out_buffer,
                      unsigned int  *out_buffer_len,
                      const unsigned char *privacy_params,
                      const unsigned int   privacy_params_len,
                      const unsigned long  /*engine_boots*/,
                      const unsigned long  /*engine_time*/)
{
  unsigned char iv[8];
  IDEAContext CFB_Context;

  /* privacy params length has to be 8 */
  if (privacy_params_len != 8)
    return SNMPv3_USM_DECRYPTION_ERROR;

  idea_set_key(&CFB_Context, key);

  memset((char*)out_buffer, 0, *out_buffer_len);

  /* Initialize iv with last 8 bytes of key and xor with privacy_params */
  memcpy((char*)iv, key+8, 8);
  for (int i=0; i<8; i++)
    iv[i] ^= privacy_params[i];

  idea_cfb_decrypt(&CFB_Context, iv, out_buffer,
                   buffer, buffer_len);

  /* Clear context (paranoia!) */
  idea_destroy_context(&CFB_Context);
  memset((char*)iv, 0, 8);

  *out_buffer_len = buffer_len;

#ifdef __DEBUG
  debughexcprintf(21, "apIDEADecryptData: Data to decrypt",
                  buffer, buffer_len);
  debughexcprintf(21, "apIDEADecryptData: key", key, 16);
  debughexcprintf(21, "apIDEAEncryptData: privacy_params", privacy_params, 8);
  debughexcprintf(21, "apIDEADecryptData: decrypted Data",
                  out_buffer, *out_buffer_len);
#endif

  return SNMPv3_USM_OK;
}

#endif // _USE_IDEA

#if defined(_USE_LIBTOMCRYPT) || defined(_USE_OPENSSL)

PrivAES::PrivAES(const int aes_type_)
  : aes_type(aes_type_)
{
#if defined(_USE_LIBTOMCRYPT) && !defined(_USE_OPENSSL)
  cipher = find_cipher("rijndael");
#endif

  switch (aes_type)
  {
    case SNMP_PRIVPROTOCOL_AES128:
      key_bytes = 16;
      rounds = 10;
      break;
    case SNMP_PRIVPROTOCOL_AES192:
      key_bytes = 24;
      rounds = 12;
      break;
    case SNMP_PRIVPROTOCOL_AES256:
      key_bytes = 32;
      rounds = 14;
      break;
    default:
      debugprintf(0, "Wrong AES type: %i.", aes_type);
      key_bytes = 0;
      rounds = 0;
      aes_type = -1; // will cause an error in AuthPriv::add_priv()
  }

  unsigned int testswap = htonl(0x01020304);
  if (testswap == 0x01020304)
    need_byteswap = false;
  else
    need_byteswap = true;
}

const char *PrivAES::get_id_string() const
{
  switch (aes_type)
  {
    case SNMP_PRIVPROTOCOL_AES128: return "AES128";  break;
    case SNMP_PRIVPROTOCOL_AES192: return "AES192";  break;
    case SNMP_PRIVPROTOCOL_AES256: return "AES256";  break;
    default:                       return "error";   break;
  }
}

int PrivAES::encrypt(const unsigned char *key,
                     const unsigned int   key_len,
                     const unsigned char *buffer,
                     const unsigned int   buffer_len,
                     unsigned char       *out_buffer,
                     unsigned int        *out_buffer_len,
                     unsigned char       *privacy_params,
                     unsigned int        *privacy_params_len,
                     const unsigned long  engine_boots,
                     const unsigned long  engine_time)
{
  if (*out_buffer_len < buffer_len) {
    debugprintf(0, "Output buffer too small (%d < %d)", *out_buffer_len, buffer_len);
    return SNMPv3_USM_ENCRYPTION_ERROR;
  }

  unsigned char initVect[16];
  pp_uint64 my_salt = (*salt)++;

#ifdef INVALID_ENCRYPTION
  debugprintf(-10, "\nWARNING: Encrypting with zeroed salt!\n");
  my_salt = 0;
#endif

  /* check space in privacy_params buffer */
  if (*privacy_params_len < 8)
  {
    debugprintf(4, "Buffer too small: should be 8, is (%i).",
                *privacy_params_len);
    return SNMPv3_USM_ENCRYPTION_ERROR;
  }
  /* Length is always 8 */
  *privacy_params_len = 8;

  /* Set IV as engine_boots + engine_time + salt */
  unsigned int *tmpi = (unsigned int *)initVect;
  *tmpi++ = htonl(engine_boots);
  *tmpi++ = htonl(engine_time);
  if (need_byteswap)
  {
    *tmpi++ = htonl(my_salt & 0xFFFFFFFF);
    *tmpi   = htonl((my_salt >> 32) & 0xFFFFFFFF);
  }
  else
    memcpy(tmpi, &my_salt, 8);

  /* put byteswapped salt in privacy_params */
  memcpy(privacy_params, initVect + 8, 8);
  debughexcprintf(21, "aes initVect:", initVect, 16);

#ifdef _USE_OPENSSL
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
  {
	debugprintf(1, "EVP_CIPHER_CTX_new() failed.");
	return SNMPv3_USM_ENCRYPTION_ERROR;
  }

  const EVP_CIPHER *evp_cipher = NULL;
  switch (aes_type)
  {
    case SNMP_PRIVPROTOCOL_AES128:
      evp_cipher = EVP_aes_128_cfb128();
      break;
    case SNMP_PRIVPROTOCOL_AES192:
      evp_cipher = EVP_aes_192_cfb128();
      break;
    case SNMP_PRIVPROTOCOL_AES256:
      evp_cipher = EVP_aes_256_cfb128();
      break;
  }

  if (EVP_EncryptInit_ex(ctx, evp_cipher, NULL, key, initVect) != 1)
  {
	debugprintf(1, "EVP_EncryptInit_ex() failed.");
	EVP_CIPHER_CTX_free(ctx);
	return SNMPv3_USM_ENCRYPTION_ERROR;
  }

  int len1 = *out_buffer_len;
  if (EVP_EncryptUpdate(ctx, out_buffer, &len1, buffer, buffer_len) != 1)
  {
    debugprintf(1, "EVP_EncryptUpdate() failed.");
    EVP_CIPHER_CTX_free(ctx);
    return SNMPv3_USM_ENCRYPTION_ERROR;
  }

  unsigned char *out_buffer_ptr = out_buffer + len1;
  int len2 = *out_buffer_len - len1;
  if (EVP_EncryptFinal_ex(ctx, out_buffer_ptr, &len2) != 1)
  {
	debugprintf(1, "EVP_EncryptFinal_ex() failed.");
    EVP_CIPHER_CTX_free(ctx);
	return SNMPv3_USM_ENCRYPTION_ERROR;
  }

  EVP_CIPHER_CTX_free(ctx);

  if (len1 + len2 != static_cast<int>(buffer_len)) {
    debugprintf(1, "Encryption wrote (%d + %d) bytes instead of (%d)", len1, len2, buffer_len);
    return SNMPv3_USM_ENCRYPTION_ERROR;
  }
#else
  symmetric_CFB symcfb;

  cfb_start(cipher, initVect, key, key_bytes, rounds, &symcfb);
  cfb_encrypt((unsigned char*)buffer, out_buffer, buffer_len, &symcfb);

  /* Clear context (paranoia!)*/
  memset(&symcfb, 0, sizeof(symcfb));
#endif

  *out_buffer_len = buffer_len;

#ifdef __DEBUG
  debughexcprintf(21, "aes EncryptData: Data to encrypt", buffer, buffer_len);
  debughexcprintf(21, "aes EncryptData: used key", key, key_len);
  debughexcprintf(21, "aes EncryptData: created privacy_params",
                  privacy_params, 8);
  debughexcprintf(21, "aes EncryptData: encrypted Data",
                  out_buffer, *out_buffer_len);
#endif

  return SNMPv3_USM_OK;
}

int PrivAES::decrypt(const unsigned char *key,
                     const unsigned int   key_len,
                     const unsigned char *buffer,
                     const unsigned int   buffer_len,
                     unsigned char       *out_buffer,
                     unsigned int        *out_buffer_len,
                     const unsigned char *privacy_params,
                     const unsigned int   privacy_params_len,
                     const unsigned long  engine_boots,
                     const unsigned long  engine_time)
{
  if (*out_buffer_len < buffer_len) {
    debugprintf(0, "Output buffer too small (%d < %d)", *out_buffer_len, buffer_len);
    return SNMPv3_USM_ENCRYPTION_ERROR;
  }

  unsigned char initVect[16];

  /* Privacy params length has to be 8 */
  if (privacy_params_len != 8)
    return SNMPv3_USM_DECRYPTION_ERROR;

  /* build IV */
  unsigned int *tmp;
  tmp = (unsigned int *)initVect;
  *tmp++ = htonl(engine_boots);
  *tmp = htonl(engine_time);
  memcpy(initVect + 8, privacy_params, 8);
  debughexcprintf(21, "aes initVect:", initVect, 16);

#ifdef _USE_OPENSSL
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  if (!ctx)
  {
    debugprintf(1, "EVP_CIPHER_CTX_new() failed.");
    return SNMPv3_USM_DECRYPTION_ERROR;
  }

  const EVP_CIPHER *evp_cipher = NULL;
  switch (aes_type)
  {
    case SNMP_PRIVPROTOCOL_AES128:
      evp_cipher = EVP_aes_128_cfb128();
      break;
    case SNMP_PRIVPROTOCOL_AES192:
      evp_cipher = EVP_aes_192_cfb128();
      break;
    case SNMP_PRIVPROTOCOL_AES256:
      evp_cipher = EVP_aes_256_cfb128();
      break;
  }

  if (EVP_DecryptInit_ex(ctx, evp_cipher, NULL, key, initVect) != 1)
  {
    debugprintf(1, "EVP_DecryptInit_ex() failed.");
    EVP_CIPHER_CTX_free(ctx);
    return SNMPv3_USM_DECRYPTION_ERROR;
  }

  int len1 = *out_buffer_len;
  if (EVP_DecryptUpdate(ctx, out_buffer, &len1, buffer, buffer_len) != 1)
  {
    debugprintf(1, "EVP_DecryptUpdate() failed.");
    EVP_CIPHER_CTX_free(ctx);
    return SNMPv3_USM_DECRYPTION_ERROR;
  }

  unsigned char *out_buffer_ptr = out_buffer + len1;
  int len2 = *out_buffer_len - len1;
  if (EVP_DecryptFinal_ex(ctx, out_buffer_ptr, &len2) != 1)
  {
    debugprintf(1, "EVP_DecryptFinal_ex() failed.");
    EVP_CIPHER_CTX_free(ctx);
    return SNMPv3_USM_DECRYPTION_ERROR;
  }

  EVP_CIPHER_CTX_free(ctx);

  if (len1 + len2 != static_cast<int>(buffer_len)) {
    debugprintf(1, "Encryption wrote (%d + %d) bytes instead of (%d)", len1, len2, buffer_len);
    return SNMPv3_USM_DECRYPTION_ERROR;
  }
#else
  symmetric_CFB symcfb;

  cfb_start(cipher, initVect, key, key_bytes, rounds, &symcfb);
  cfb_decrypt((unsigned char*)buffer, out_buffer, buffer_len, &symcfb);

  /* Clear context (paranoia!)*/
  memset(&symcfb, 0, sizeof(symcfb));
#endif

  *out_buffer_len = buffer_len;

#ifdef __DEBUG
  debughexcprintf(21, "aes DecryptData: Data to decrypt", buffer, buffer_len);
  debughexcprintf(21, "aes DecryptData: used key", key, key_len);
  debughexcprintf(21, "aes DecryptData: used privacy_params",
                  privacy_params, 8);
  debughexcprintf(21, "aes DecryptData: decrypted Data",
                  out_buffer, *out_buffer_len);
#endif

  return SNMPv3_USM_OK;
}

int PrivAES::extend_short_key(const unsigned char *password,
                              const unsigned int   password_len,
                              const unsigned char *engine_id,
                              const unsigned int   engine_id_len,
                              unsigned char       *key,
                              unsigned int        *key_len,
                              const unsigned int   max_key_len,
                              Auth                *auth)
{
  (void)password; (void)password_len; (void)engine_id; (void)engine_id_len;
  if (max_key_len < (unsigned)key_bytes)
      return SNMPv3_USM_ERROR;

  int res = 0;
  unsigned char *hash_buf = new unsigned char[auth->get_hash_len()];

  if (!hash_buf)
  {
    debugprintf(0, "Out of mem. Did not get %i bytes.", auth->get_hash_len());
    return SNMPv3_USM_ERROR;
  }

  while (*key_len < (unsigned)key_bytes)
  {
    res = auth->hash(key, *key_len, hash_buf);
    if (res != SNMPv3_USM_OK)
      break;

    int copy_bytes = key_bytes - *key_len;
    if (copy_bytes > auth->get_hash_len())
      copy_bytes = auth->get_hash_len();
    if (*key_len + copy_bytes > max_key_len)
        copy_bytes = max_key_len - *key_len;
    memcpy(key + *key_len, hash_buf, copy_bytes);
    *key_len += copy_bytes;
  }

  if (hash_buf) delete [] hash_buf;

  return res;
}

PrivAESW3DESKeyExt::PrivAESW3DESKeyExt(const int aes_type_)
    : PrivAES(PrivAESW3DESKeyExt::map_aes_type(aes_type_))
{
        if (PrivAES::get_id() != -1)
                own_aes_type = aes_type_;
        else
                own_aes_type = -1;
}

int PrivAESW3DESKeyExt::map_aes_type(const int t)
{
  switch (t)
  {
    case SNMP_PRIVPROTOCOL_AES128W3DESKEYEXT: return SNMP_PRIVPROTOCOL_AES128; break;
    case SNMP_PRIVPROTOCOL_AES192W3DESKEYEXT: return SNMP_PRIVPROTOCOL_AES192; break;
    case SNMP_PRIVPROTOCOL_AES256W3DESKEYEXT: return SNMP_PRIVPROTOCOL_AES256; break;
    default:                                  return -1; break;
  }
}


int PrivAESW3DESKeyExt::extend_short_key(const unsigned char *password,
                                         const unsigned int   password_len,
                                         const unsigned char *engine_id,
                                         const unsigned int   engine_id_len,
                                         unsigned char       *key,
                                         unsigned int        *key_len,
                                         const unsigned int   max_key_len,
                                         Auth                *auth)
{
  return des3_extend_short_key(password, password_len,
                               engine_id, engine_id_len,
                               key, key_len,
                               max_key_len,
                               auth,
                               (unsigned)get_min_key_len());
}

const char *PrivAESW3DESKeyExt::get_id_string() const
{
  switch (own_aes_type)
  {
    case SNMP_PRIVPROTOCOL_AES128W3DESKEYEXT: return "AES128W3DESKeyExt";  break;
    case SNMP_PRIVPROTOCOL_AES192W3DESKEYEXT: return "AES192W3DESKeyExt";  break;
    case SNMP_PRIVPROTOCOL_AES256W3DESKEYEXT: return "AES256W3DESKeyExt";  break;
    default:                       return "error";   break;
  }
}

#endif // _USE_LIBTOMCRYPT or _USE_OPENSSL


#ifdef _USE_3DES_EDE

#if defined(_USE_LIBTOMCRYPT) && !defined(_USE_OPENSSL)
Priv3DES_EDE::Priv3DES_EDE()
{
  cipher = find_cipher("3des");
  debugprintf(10, "tomcrypt returned cipher %d", cipher);
}
#endif


int
Priv3DES_EDE::encrypt(const unsigned char *key,
                      const unsigned int   key_len,
                      const unsigned char *buffer,
                      const unsigned int   buffer_len,
                      unsigned char       *out_buffer,
                      unsigned int        *out_buffer_len,
                      unsigned char       *privacy_params,
                      unsigned int        *privacy_params_len,
                      const unsigned long  engine_boots,
                      const unsigned long  /* engine_time */)
{
  unsigned char initVect[8];
  pp_uint64     my_salt = (*salt)++;

#ifdef INVALID_ENCRYPTION
  debugprintf(-10, "\nWARNING: Encrypting with zeroed salt!\n");
  my_salt = 0;
#endif

  /* check space in privacy_params buffer */
  if (*privacy_params_len < 8)
  {
    debugprintf(4, "Buffer too small: should be 8, is (%i).",
                *privacy_params_len);
    return SNMPv3_USM_ENCRYPTION_ERROR;
  }
  /* Length is always 8 */
  *privacy_params_len = 8;

  /* check key length */
  if (key_len < TRIPLEDES_EDE_KEY_LEN)
  {
    debugprintf(4, "Key too small: should be %d, is (%d).",
                TRIPLEDES_EDE_KEY_LEN, key_len);
    return SNMPv3_USM_ENCRYPTION_ERROR;
  }

  /* TODO: check if K1 != K2 != K3 */

  // last 8 bytes of key are used as base for initialization vector
  memcpy((char*)initVect, key+24, 8);

  /* TODO: generate salt as specified in draft */

  // put salt in privacy_params
  for (int j=0; j<4; j++)
  {
    privacy_params[3-j] = (unsigned char) (0xFF & (engine_boots >> (8*j)));
    privacy_params[7-j] = (unsigned char) (0xFF & (my_salt >> (8*j)));
  }

  // xor initVect with salt
  for (int i=0; i<8; i++)
    initVect[i] ^= privacy_params[i];


#ifdef __DEBUG
  debughexcprintf(21, "3DES Data to encrypt", buffer, buffer_len);
  debughexcprintf(21, "3DES used iv", initVect, 8);
  debughexcprintf(21, "3DES key", key, key_len);
#endif

  // The first 24 octets of the 32-octet secret are used as a 3DES-EDE
  // key. Since 3DES-EDE uses only 168 bits the least significant bit
  // in each octet is disregarded

#if defined(_USE_LIBTOMCRYPT) && !defined(_USE_OPENSSL)
  DESCBCType symcbc;
  DES_CBC_START_ENCRYPT(cipher, initVect, key, 24, 16, symcbc);

  for(unsigned int k = 0; k <= buffer_len - 8; k += 8) {
    DES_CBC_ENCRYPT(buffer + k, out_buffer + k, symcbc, initVect, 8);
  }

  /* last part of buffer */
  if (buffer_len % 8)
  {
    unsigned char tmp_buf[8];
    unsigned char *tmp_buf_ptr = tmp_buf;
    int start = buffer_len - (buffer_len % 8);
    memset(tmp_buf, 0, 8);
    for (unsigned int l = start; l < buffer_len; l++)
      *tmp_buf_ptr++ = buffer[l];
    DES_CBC_ENCRYPT(tmp_buf, out_buffer + start, symcbc, initVect, 8);
    *out_buffer_len = buffer_len + 8 - (buffer_len % 8);
  }
  else
    *out_buffer_len = buffer_len;

  /* Clear context buffer (paranoia!)*/
  DES_MEMSET(symcbc, 0, sizeof(symcbc));

#else
  DESCBCType ks1, ks2, ks3;

  DES_CBC_START_ENCRYPT(unused, unused, key, unused, unused, ks1);
  DES_CBC_START_ENCRYPT(unused, unused, key+8, unused, unused, ks2);
  DES_CBC_START_ENCRYPT(unused, unused, key+16, unused, unused, ks3);

  if (buffer_len >= 8)
    for(unsigned int k = 0; k <= (buffer_len - 8); k += 8)
    {
      DES_EDE3_CBC_ENCRYPT(buffer+k, out_buffer+k, 8,
                           ks1, ks2, ks3, initVect);
    }

  // Last part
  if (buffer_len % 8)
    {
      unsigned char tmp_buf[8];
      unsigned char *tmp_buf_ptr = tmp_buf;
      int start = buffer_len - (buffer_len % 8);
      memset(tmp_buf, 0, 8);
      for (unsigned int l = start; l < buffer_len; l++)
        *tmp_buf_ptr++ = buffer[l];
      DES_EDE3_CBC_ENCRYPT(tmp_buf, out_buffer + start, 8,
                           ks1, ks2, ks3, initVect);

      *out_buffer_len = buffer_len + 8 - (buffer_len % 8);
    }
  else
    *out_buffer_len = buffer_len;

  /* Clear context buffer (paranoia!)*/
  DES_MEMSET(ks1, 0, sizeof(ks1));
  DES_MEMSET(ks2, 0, sizeof(ks2));
  DES_MEMSET(ks3, 0, sizeof(ks3));
#endif

#ifdef __DEBUG
  debughexcprintf(21, "3DES created privacy_params", privacy_params, 8);
  debughexcprintf(21, "3DES encrypted Data", out_buffer, *out_buffer_len);
#endif

  return SNMPv3_USM_OK;
}


int
Priv3DES_EDE::decrypt(const unsigned char *key,
                      const unsigned int   key_len,
                      const unsigned char *buffer,
                      const unsigned int   buffer_len,
                      unsigned char       *out_buffer,
                      unsigned int        *out_buffer_len,
                      const unsigned char *privacy_params,
                      const unsigned int   privacy_params_len,
                      const unsigned long  /* engine_boots */,
                      const unsigned long  /* engine_time */)
{
  unsigned char initVect[8];

  /* Privacy params length has to be 8  && Length has to be a multiple of 8 */
  if (( buffer_len % 8 ) || (privacy_params_len != 8))
    return SNMPv3_USM_DECRYPTION_ERROR;

  /* check key length */
  if (key_len < TRIPLEDES_EDE_KEY_LEN)
  {
    debugprintf(4, "Key too small: should be %d, is (%d).",
                TRIPLEDES_EDE_KEY_LEN, key_len);
    return SNMPv3_USM_DECRYPTION_ERROR;
  }

  for (int i=0; i<8; i++)
    initVect[i] = privacy_params[i] ^ key[i+24];

  memset((char*)out_buffer, 0, *out_buffer_len);

#ifdef __DEBUG
  debughexcprintf(21, "3DES Data to decrypt", buffer, buffer_len);
  debughexcprintf(21, "3DES privacy_params",  privacy_params, 8);
  debughexcprintf(21, "3DES used iv",   initVect, 8);
  debughexcprintf(21, "3DES key", key, key_len);
#endif

#if defined(_USE_LIBTOMCRYPT) && !defined(_USE_OPENSSL)
  DESCBCType symcbc;
  DES_CBC_START_DECRYPT(cipher, initVect, key, 24, 16, symcbc);
  for(unsigned int j=0; j<buffer_len; j+=8 ) {
    DES_CBC_DECRYPT(buffer + j, out_buffer + j, symcbc, initVect, 8);
  }
  /* Clear context (paranoia!) */
  DES_MEMSET(symcbc, 0, sizeof(symcbc));

#else
  DESCBCType ks1, ks2, ks3;

  DES_CBC_START_DECRYPT(unused, unused, key, unused, unused, ks1);
  DES_CBC_START_DECRYPT(unused, unused, key+8, unused, unused, ks2);
  DES_CBC_START_DECRYPT(unused, unused, key+16, unused, unused, ks3);

  for(unsigned int k=0; k<buffer_len; k+=8 )
    {
      DES_EDE3_CBC_DECRYPT(buffer+k, out_buffer+k, 8,
                           ks1, ks2, ks3, initVect);
    }
  /* Clear context (paranoia!) */
  DES_MEMSET(ks1, 0, sizeof(ks1));
  DES_MEMSET(ks2, 0, sizeof(ks2));
  DES_MEMSET(ks3, 0, sizeof(ks3));
#endif

  *out_buffer_len = buffer_len;

#ifdef __DEBUG
  debughexcprintf(21, "3DES decrypted Data", out_buffer, *out_buffer_len);
#endif

  return SNMPv3_USM_OK;
}


int
Priv3DES_EDE::extend_short_key(const unsigned char *password,
                               const unsigned int   password_len,
                               const unsigned char *engine_id,
                               const unsigned int   engine_id_len,
                               unsigned char       *key,
                               unsigned int        *key_len,
                               const unsigned int   max_key_len,
                               Auth                *auth)
{
  return des3_extend_short_key(password, password_len,
                               engine_id, engine_id_len,
                               key, key_len,
                               max_key_len,
                               auth,
                               (unsigned)get_min_key_len());
}


#ifdef _TEST
bool Priv3DES_EDE::test()
{
  int status;
  AuthPriv ap(status);
  if (status != SNMPv3_USM_OK)
      return false;

  if (ap.add_auth(new AuthSHA()) != SNMP_ERROR_SUCCESS)
  {
      debugprintf(0, "Error: could not add AuthSHA.");
      return false;
  }

  if (ap.add_auth(new AuthMD5()) != SNMP_ERROR_SUCCESS)
  {
      debugprintf(0, "Error: could not add AuthMD5.");
      return false;
  }

  if (ap.add_priv(new Priv3DES_EDE()) != SNMP_ERROR_SUCCESS)
  {
      debugprintf(0, "Error: could not add Priv3DES_EDE.");
      return false;
  }

  unsigned char password[11] = "maplesyrup";
  unsigned char engine_id[12];

  memset(engine_id, 0, 11);
  engine_id[11] = 2;

  unsigned char key[TRIPLEDES_EDE_KEY_LEN];
  unsigned int key_len = TRIPLEDES_EDE_KEY_LEN;

  status = ap.password_to_key_priv(SNMP_AUTHPROTOCOL_HMACSHA,
                                   SNMP_PRIVPROTOCOL_3DESEDE,
                                   password, 10,
                                   engine_id, 12,
                                   key,  &key_len);

  debughexcprintf(1, "result key 3DES SHA",
                  key, key_len);

  key_len = TRIPLEDES_EDE_KEY_LEN;
  status = ap.password_to_key_priv(SNMP_AUTHPROTOCOL_HMACMD5,
                                   SNMP_PRIVPROTOCOL_3DESEDE,
                                   password, 10,
                                   engine_id, 12,
                                   key,  &key_len);

  debughexcprintf(1, "result key 3DES MD5",
                  key, key_len);

  unsigned char msg[80] = "This is the secret message, that has to be encrypted!";
  unsigned char enc_buffer[80];
  unsigned int enc_buffer_len = 80;
  unsigned char dec_buffer[80];
  unsigned int dec_buffer_len = 80;
  unsigned char priv_params[64];
  unsigned int priv_params_len = 64;


  status = ap.encrypt_msg(SNMP_PRIVPROTOCOL_3DESEDE,
                          key, key_len, msg, 53,
                          enc_buffer, &enc_buffer_len,
                          priv_params, &priv_params_len, 0x5abc, 0x6def);

  debughexcprintf(1, "encrypted text",
                  enc_buffer, enc_buffer_len);

  status = ap.decrypt_msg(SNMP_PRIVPROTOCOL_3DESEDE,
                          key, key_len, enc_buffer, enc_buffer_len,
                          dec_buffer, &dec_buffer_len,
                          priv_params, priv_params_len, 0x5abc, 0x6def);

  dec_buffer[dec_buffer_len] = 0;
  debugprintf(1, "decrypted text: %s",
                  dec_buffer);
  // TODO: check keys and return real value
  return true;
}
#endif

#endif // _USE_3DES_EDE


/* ----------------------- AuthSHABase ----------------------------------*/

int AuthSHABase::password_to_key(const unsigned char *password,
                                  const unsigned int   password_len,
                                  const unsigned char *engine_id,
                                  const unsigned int   engine_id_len,
                                  unsigned char *key,
                                  unsigned int *key_len)
{
#ifdef __DEBUG
  debugprintf(5,"password_to_key SHA: password: (%s).",
              OctetStr(password, password_len).get_printable());
  debugprintf(5,"password_to_key SHA: engine_id: (%s).",
              OctetStr(engine_id, engine_id_len).get_printable());
#endif

  unsigned char password_buf[72];
  unsigned long password_index = 0;
  unsigned long count = 0;

  std::unique_ptr<Hasher> h(get_hasher());
  h->init(); /* initialize SHA */

  *key_len = h->get_key_length();

  /**********************************************/
  /* Use while loop until we've done 1 Megabyte */
  /**********************************************/
  while (count < 1048576) {
    unsigned char *cp = password_buf;
    for (int i = 0; i < 64; i++) {
      /*************************************************/
      /* Take the next octet of the password, wrapping */
      /* to the beginning of the password as necessary.*/
      /*************************************************/
      *cp++ = password[password_index++ % password_len];
    }

    h->update(password_buf, 64);
    count += 64;
  }

  h->final(key);          /* tell SHA we're done */

#ifdef __DEBUG
  debughexcprintf(21, "key", key, *key_len);
#endif

  /*****************************************************/
  /* Now localize the key with the engine_id and pass  */
  /* through SHA to produce final key                  */
  /*****************************************************/
  h->init();
  h->update(key,      *key_len);
  h->update(engine_id, engine_id_len);
  h->update(key,      *key_len);
  h->final(key);

#ifdef __DEBUG
  debughexcprintf(21, "localized key", key, *key_len);
#endif

  return SNMPv3_USM_OK;
}

int AuthSHABase::hash(const unsigned char *data,
                  const unsigned int   data_len,
                  unsigned char       *digest) const
{
  std::unique_ptr<Hasher> h(get_hasher());

  h->init();
  h->update(data, data_len);
  h->final(digest);

  return SNMPv3_USM_OK;
}

int AuthSHABase::auth_out_msg(const unsigned char *key,
                               unsigned char *msg,
                               const int msg_len,
                               unsigned char *auth_par_ptr)
{
  std::unique_ptr<Hasher> h(get_hasher());
  int block_size = h->get_block_size();
  int key_len    = h->get_key_length();
  unsigned char digest[SNMPv3_AP_MAXLENGTH_AUTHPARAM];
  Buffer<unsigned char> ipad(block_size);
  Buffer<unsigned char> opad(block_size);
  unsigned char *k_ipad = ipad.get_ptr(); /* inner padding - key XORd with ipad */
  unsigned char *k_opad = opad.get_ptr(); /* outer padding - key XORd with opad */

  memset(auth_par_ptr, 0, get_auth_params_len());

#ifdef __DEBUG
  debughexcprintf(21, "key", key, h->get_key_length());
#endif

  /* the HMAC_SHA transform looks like:
   *
   * SHA(K XOR opad, SHA(K XOR ipad, msg))
   *
   * where K is an n byte key
   * ipad is filled with byte 0x36
   * opad is filled with byte 0x5c
   * and msg is the data being protected
   */

  /* start out by storing ipads and opads in pads */
  memset(k_ipad, 0x36, block_size);
  memset(k_opad, 0x5c, block_size);

  /* XOR pads with key */
  for (int i=0; i < key_len; ++i) {
    k_ipad[i] ^= key[i];
    k_opad[i] ^= key[i];
  }

  /* perform inner SHA */
  h->init();                     /* init sha_hash_state for 1st pass */
  h->update(k_ipad, block_size); /* start with inner pad      */
  h->update(msg, msg_len); /* then text of datagram     */
  h->final(digest);        /* finish up 1st pass        */
  /* perform outer SHA */
  h->init();                     /* init sha_hash_state for 2nd pass */
  h->update(k_opad, block_size); /* start with outer pad      */
  h->update(digest, get_hash_len());   /* then results of 1st hash  */
  h->final(digest);        /* finish up 2nd pass        */

#ifdef __DEBUG
  debughexcprintf(21,"digest", digest,  get_hash_len());
#endif

  memcpy(auth_par_ptr, digest, get_auth_params_len());

  return SNMPv3_USM_OK;
}


int AuthSHABase::auth_inc_msg(const unsigned char *key,
                               unsigned char *msg,
                               const int msg_len,
                               unsigned char *auth_par_ptr,
                               const int      auth_par_len)
{
  unsigned char receivedDigest[SNMPv3_AP_MAXLENGTH_AUTHPARAM];

  if (auth_par_len != get_auth_params_len())
  {
    debugprintf(4, "SHA illegal digest length (%d), expected (%d), authentication FAILED.",
                auth_par_len, get_auth_params_len());
    return SNMPv3_USM_AUTHENTICATION_FAILURE;
  }

#ifdef __DEBUG
  std::unique_ptr<Hasher> h(get_hasher());
  debughexcprintf(21, "digest in Message", auth_par_ptr, auth_par_len);
  debughexcprintf(21, "key", key, h->get_key_length());
#endif

  /* Save received digest */
  memcpy(receivedDigest, auth_par_ptr, auth_par_len);

  if (SNMPv3_USM_OK != auth_out_msg(key, msg, msg_len, auth_par_ptr))
  {
    /* copy digest back into message and return error */
    memcpy(auth_par_ptr, receivedDigest, auth_par_len);
    debugprintf(4, "SHA authentication FAILED (1).");
    return SNMPv3_USM_AUTHENTICATION_FAILURE;
  }

  /* compare digest to received digest */
  for (int i=0; i < auth_par_len ; ++i)
  {
    if (auth_par_ptr[i] != receivedDigest[i])
    {
      /* copy digest back into message and return error */
      memcpy(auth_par_ptr, receivedDigest, auth_par_len);
      debugprintf(4, "SHA authentication FAILED.");
      return SNMPv3_USM_AUTHENTICATION_FAILURE;
    }
  }
  debugprintf(4, "SHA authentication OK.");
  return SNMPv3_USM_OK;
}


class AuthSHA::HasherSHA1 : public AuthSHABase::Hasher
{
public:
  HasherSHA1() {}
  virtual ~HasherSHA1() {}

  int init()
  {
    return SHA1_INIT(&sha_hash_state);
  }

  int update(const unsigned char *data,
             const unsigned int   data_len)
  {
    return SHA1_PROCESS(&sha_hash_state, data, data_len);
  }

  int final(unsigned char *digest)
  {
    return SHA1_DONE(&sha_hash_state, digest);
  }
  int get_key_length() const { return 20; }
  int get_block_size() const { return 64; }

private:
  SHAHashStateType sha_hash_state;
};

AuthSHABase::Hasher *AuthSHA::get_hasher() const
{
  return new HasherSHA1();
}

#if defined(_USE_OPENSSL)

class AuthHMAC128SHA224::Hasher224 : public AuthSHABase::Hasher
{
public:
  Hasher224() {}
  virtual ~Hasher224() {}

  int init()
  {
    return evpAllocAndInit(&ctx, EVP_sha224());
  }

  int update(const unsigned char *data,
             const unsigned int   data_len)
  {
    return evpDigestUpdate(&ctx, data, data_len);
  }

  int final(unsigned char *digest)
  {
    return evpDigestFinalAndFree(&ctx, digest);
  }
  int get_key_length() const { return 28; }
  int get_block_size() const { return 64; }

private:
  EVPHashStateType ctx;
};


AuthSHABase::Hasher *AuthHMAC128SHA224::get_hasher() const
{
  return new Hasher224();
}


class AuthHMAC192SHA256::Hasher256 : public Hasher
{
public:
  Hasher256() {}
  virtual ~Hasher256() {}

  int init()
  {
    return evpAllocAndInit(&ctx, EVP_sha256());
  }

  int update(const unsigned char *data,
             const unsigned int   data_len)
  {
    return evpDigestUpdate(&ctx, data, data_len);
  }

  int final(unsigned char *digest)
  {
    return evpDigestFinalAndFree(&ctx, digest);
  }
  int get_key_length() const { return 32; }
  int get_block_size() const { return 64; }

private:
  EVPHashStateType ctx;
};



AuthSHABase::Hasher *AuthHMAC192SHA256::get_hasher() const
{
  return new Hasher256();
}


class AuthHMAC256SHA384::Hasher384 : public Hasher
{
public:
  Hasher384() {}
  virtual ~Hasher384() {}

  int init()
  {
    return evpAllocAndInit(&ctx, EVP_sha384());
  }

  int update(const unsigned char *data,
             const unsigned int   data_len)
  {
    return evpDigestUpdate(&ctx, data, data_len);
  }

  int final(unsigned char *digest)
  {
    return evpDigestFinalAndFree(&ctx, digest);
  }
  int get_key_length() const { return 48; }
  int get_block_size() const { return 128; }

private:
  EVPHashStateType ctx;
};



AuthSHABase::Hasher *AuthHMAC256SHA384::get_hasher() const
{
  return new Hasher384();
}



class AuthHMAC384SHA512::Hasher512 : public Hasher
{
public:
  Hasher512() {}
  virtual ~Hasher512() {}

  int init()
  {
    return evpAllocAndInit(&ctx, EVP_sha512());
  }

  int update(const unsigned char *data,
             const unsigned int   data_len)
  {
    return evpDigestUpdate(&ctx, data, data_len);
  }

  int final(unsigned char *digest)
  {
    return evpDigestFinalAndFree(&ctx, digest);
  }
  int get_key_length() const { return 64; }
  int get_block_size() const { return 128; }

private:
  EVPHashStateType ctx;
};

AuthSHABase::Hasher *AuthHMAC384SHA512::get_hasher() const
{
  return new Hasher512();
}

#endif // defined(_USE_OPENSSL)


#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif

#endif // _SNMPv3
