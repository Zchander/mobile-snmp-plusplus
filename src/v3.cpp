/*_############################################################################
  _## 
  _##  v3.cpp  
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

#include "snmp_pp/log.h"
#include "snmp_pp/v3.h"
#include "snmp_pp/octet.h"

#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

static const char *loggerModuleName = "snmp++.v3";

#define MAX_LINE_LEN 100

int debug_level = 19;

// Set the amount of log messages you want to get.
void debug_set_level(const int db_level)
{
  debug_level = db_level;
}

#ifdef _DEBUG

void debughexcprintf(int db_level, const char *comment,
                     const unsigned char *data, const unsigned int len)
{
    if (db_level > debug_level) return;

    char *buf = new char[MAX_LOG_SIZE];

    if (NULL == buf) return;	// not good!

    if (comment && (strlen(comment) < MAX_LOG_SIZE - 25))
    {
	sprintf(buf, "%s (length %u): ", comment, len);
	LOG_BEGIN(loggerModuleName, DEBUG_LOG | 3);
	LOG(buf);
	LOG_END;
    }

    char *tmp = new char[4];

    if (NULL == tmp) { delete [] buf ; return; }

    buf[0] = '\0';
    for (unsigned int i=0; i<len; i++)
    {
	sprintf(tmp, "%02X ", data[i]);
	strcat(buf, tmp);

	if ((i+1)%4==0)
	{
	    sprintf(tmp, " ");
	    strcat(buf, tmp);
	}

	if ((i+1)%16==0)
	{
	    LOG_BEGIN(loggerModuleName, DEBUG_LOG | 3);
	    LOG(buf);
	    LOG_END;

	    // reset the buf
	    buf[0] = '\0';
	}
    }

    if (buf[0] != '\0')
    {
	// print the last part of the message
	LOG_BEGIN(loggerModuleName, DEBUG_LOG | 3);
	LOG(buf);
	LOG_END;
    }

    // and cleanup...
    delete [] tmp;
    delete [] buf;
}

void debugprintf(int db_level, const char *format, ...)
{
    if (db_level > debug_level) return;

    char *buf = new char[MAX_LOG_SIZE];

    if (!buf) return;

    va_list  args;
    va_start(args, format);
      
    vsnprintf(buf, MAX_LOG_SIZE, format, args);
    buf[MAX_LOG_SIZE - 1] = 0;

    LOG_BEGIN(loggerModuleName, DEBUG_LOG | 1);
    LOG(buf);
    LOG_END;

    va_end(args);
    delete [] buf;
}

#else
#if (defined (__STRICT_ANSI__) || !defined (__GNUC__)) && !defined (_MSC_VER)
void debugprintf(int, const char*, ...)
{
}
#endif

#endif

#ifdef _SNMPv3

unsigned char *v3strcpy(const unsigned char *src, const int srclen)
{
  unsigned char *res = new unsigned char[srclen+1];
  if (!res) return NULL;
  memcpy(res, src, srclen);
  res[srclen] = '\0';
  return res;
}


int unsignedCharCompare(const unsigned char *str1, const long int ptr1len,
                        const unsigned char *str2, const long int ptr2len)
{
  if (ptr1len != ptr2len) return 0;

  const unsigned char *ptr1 = str1;
  const unsigned char *ptr2 = str2;

  for (int i=0; i < ptr1len; ++i)
    if (*ptr1++ != *ptr2++) return 0;

  return 1;
}

// Encode the given string into the output buffer.
void encodeString(const unsigned char* in, const int in_length, char* out)
{
  char* out_ptr = out;
  const unsigned char* in_ptr = in;

  for (int i=0; i<in_length; i++)
  {
    *out_ptr++ = 64 + ((*in_ptr >> 4) & 0xF);
    *out_ptr++ = 64 + (*in_ptr++ & 0xF);
  }
}

// Decode the given encoded string into the output buffer.
void decodeString(const unsigned char* in, const int in_length, char* out)
{
  char* out_ptr = out;
  const unsigned char* in_ptr = in;

  if ((in_length % 2) || (in_length < 0))
  {
    LOG_BEGIN(loggerModuleName, WARNING_LOG | 3);
    LOG("decodeString: Illegal input length (len)");
    LOG(in_length);
    LOG_END;

    *out = 0;
    return;
  }

  for (int i= in_length / 2; i > 0; i--)
  {
    *out_ptr = (*in_ptr++ & 0xF) << 4;
    *out_ptr++ |= (*in_ptr++ & 0xF);
  }
  *out_ptr = 0; // make sure it is null terminated
}

// Read the bootCounter of the given engineID stored in the given file.
int getBootCounter(const char *fileName,
                   const OctetStr &engineId, unsigned int &boot)
{
  char line[MAX_LINE_LEN];
  char encoded[MAXLENGTH_ENGINEID * 2 + 2];
  int len = engineId.len();
  FILE *file = fopen(fileName, "r");;

  boot = 0; // set to default

  if (!file)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
    LOG("getBootCounter: Could not open (file)");
    LOG(fileName);
    LOG_END;

    return SNMPv3_FILEOPEN_ERROR;
  }

  if (len > MAXLENGTH_ENGINEID)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 3);
    LOG("getBootCounter: engine id too long, ignoring last bytes (len) (max)");
    LOG(len);
    LOG(MAXLENGTH_ENGINEID);
    LOG_END;

    len = MAXLENGTH_ENGINEID;
  }

  encodeString(engineId.data(), len, encoded);
  encoded[2*len]=' ';
  encoded[2*len + 1] = 0;

  while (fgets(line, MAX_LINE_LEN, file))
  {
    line[MAX_LINE_LEN - 1] = 0;
    /* ignore comments */
    if (line[0]=='#')
      continue;

    if (!strncmp(encoded, line, len*2 + 1))
    {
      /* line starts with engineId */
      char* ptr = line;
      /* skip until first space */
      while (*ptr != 0 && *ptr != ' ')
        ptr++;

      if (*ptr == 0)
      {
        fclose(file);

        LOG_BEGIN(loggerModuleName, ERROR_LOG | 3);
        LOG("getBootCounter: Illegal line: (file) (line)");
        LOG(fileName);
        LOG(line);
        LOG_END;

        return SNMPv3_FILE_ERROR;
      }
      boot = atoi(ptr);
      fclose(file);

      LOG_BEGIN(loggerModuleName, DEBUG_LOG | 3);
      LOG("getBootCounter: found entry (file) (engine id) (boot counter)");
      LOG(fileName);
      LOG(engineId.get_printable());
      LOG(boot);
      LOG_END;

      return SNMPv3_OK;
    }
  }
  fclose(file);

  LOG_BEGIN(loggerModuleName, WARNING_LOG | 3);
  LOG("getBootCounter: No entry found (file) (engine id)");
  LOG(fileName);
  LOG(engineId.get_printable());
  LOG_END;

  return SNMPv3_NO_ENTRY_ERROR;
}

// Store the bootCounter of the given engineID in the given file.
int saveBootCounter(const char *fileName,
                    const OctetStr &engineId, const unsigned int boot)
{
  char tmpFileName[MAXLENGTH_FILENAME];
  int len = engineId.len();
  FILE *file_in, *file_out;

  tmpFileName[0] = 0;
  sprintf(tmpFileName, "%s.tmp",fileName);
  if (len > MAXLENGTH_ENGINEID)
  {
    LOG_BEGIN(loggerModuleName, ERROR_LOG | 3);
    LOG("saveBootCounter: engine id too long, ignoring last bytes (len) (max)");
    LOG(len);
    LOG(MAXLENGTH_ENGINEID);
    LOG_END;

    len = MAXLENGTH_ENGINEID;
  }

  file_in = fopen(fileName, "r");
  if (!file_in)
  {
    file_in = fopen(fileName, "w");
    if (!file_in)
    {
      LOG_BEGIN(loggerModuleName, ERROR_LOG | 3);
      LOG("saveBootCounter: could not create new file (file)");
      LOG(fileName);
      LOG_END;

      return SNMPv3_FILECREATE_ERROR;
    }

    LOG_BEGIN(loggerModuleName, INFO_LOG | 3);
    LOG("saveBootCounter: created new file (file)");
    LOG(fileName);
    LOG_END;

    fputs("# \n",file_in);
    fputs("# This file was created by an SNMP++v3 application,\n", file_in);
    fputs("# it is used to store the snmpEngineBoots counters.\n", file_in);
    fputs("# \n",file_in);
    fputs("# Lines starting with '#' are comments.\n", file_in);
    fputs("# The snmpEngineBoots counters are stored as\n", file_in);
    fputs("# <encoded snmpEngineId> <bootCounter>\n", file_in);
    fputs("# \n", file_in);
    fclose(file_in);
    file_in = fopen(fileName, "r");
  }

  file_out = fopen(tmpFileName, "w");

  if ((file_in) && (file_out))
  {
    char line[MAX_LINE_LEN];
    char encoded[MAXLENGTH_ENGINEID * 2 + 2];
    bool found = false;

    encodeString(engineId.data(), len, encoded);
    encoded[len*2] = ' ';
    encoded[len*2 + 1] = 0;

    while (fgets(line, MAX_LINE_LEN, file_in))
    {
      line[MAX_LINE_LEN - 1] = 0;
      if (!strncmp(encoded, line, len*2 + 1))
      {
        if (found)
        {
          LOG_BEGIN(loggerModuleName, WARNING_LOG | 3);
          LOG("saveBootCounter: Removing doubled entry (file) (line)");
          LOG(fileName);
          LOG(line);
          LOG_END;

          continue;
        }
        sprintf(line,"%s%u\n", encoded, boot);
        fputs(line, file_out);
        found = true;
        continue;
      }
      fputs(line, file_out);
    }
    if (!found)
    {
      sprintf(line, "%s%u\n", encoded, boot);
      fputs(line, file_out);
    }
    fclose(file_in);
    fclose(file_out);
#ifdef WIN32
    _unlink(fileName);
#endif
    if (rename(tmpFileName, fileName))
    {
      LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
      LOG("saveBootCounter: Failed to rename temporary file (tmp file) (file)");
      LOG(tmpFileName);
      LOG(fileName);
      LOG_END;

      return SNMPv3_FILERENAME_ERROR;
    }

    LOG_BEGIN(loggerModuleName, INFO_LOG | 5);
    LOG("saveBootCounter: Saved counter (file) (engine id) (boot)");
    LOG(fileName);
    LOG(engineId.get_printable());
    LOG(boot);
    LOG_END;

    return SNMPv3_OK;
  }

  LOG_BEGIN(loggerModuleName, ERROR_LOG | 1);
  LOG("saveBootCounter: Failed to open both files (file) (tmp file)");
  LOG(fileName);
  LOG(tmpFileName);
  LOG_END;

  return SNMPv3_FILEOPEN_ERROR;
}

#endif

#ifdef SNMP_PP_NAMESPACE
} // end of namespace Snmp_pp
#endif 
