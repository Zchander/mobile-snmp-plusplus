/*_############################################################################
  _## 
  _##  log.cpp  
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

#ifndef WIN32
#include <unistd.h>
#else
#include <process.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <signal.h>
#include <string.h>

#include <snmp_pp/log.h>

#ifdef WIN32
#ifdef __BCPLUSPLUS__
#define _getpid getpid
#endif
#endif

#if defined (CPU) && CPU == PPC603
#include <taskLib.h>
#endif

#ifdef SNMP_PP_NAMESPACE
using namespace Snmp_pp;
#endif

// default log filter: logs with level less or equal filter value are logged
// error, warning, event, info, debug:
static unsigned char default_logfilter[] = { 9, 9, 4, 6, 7, 15};

#undef   LOG_INDENT


/*--------------------------- class LogEntry --------------------------*/

 /**
  * Initialize a log entry, showing timestamp, class, and level.
  * 
  */  
void LogEntry::init(void)
{
#ifdef WIN32
	int pid = _getpid();
#elif defined (CPU) && CPU == PPC603
	int pid = taskIdSelf();
#else
	int pid = getpid();
#endif

	add_timestamp();
	add_string(": ");
	add_integer(pid);
	add_string(": ");

	char buf[20];
	sprintf(buf, "(%X)", get_level());
	add_string(buf);

	switch (type & 0xF0) {
	case DEBUG_LOG:   add_string("DEBUG  : "); break;
	case INFO_LOG:	  add_string("INFO   : "); break;
	case WARNING_LOG: add_string("WARNING: "); break;
	case ERROR_LOG:	  add_string("ERROR  : "); break;
	case EVENT_LOG:	  add_string("EVENT  : "); break;
	case USER_LOG:	  add_string("USER   : "); break;
	}

#ifdef LOG_INDENT
	// indent log by level
	for (int i=0; i<(type & 0x0F); i++) 
		add_string(" ");
#endif
}

/**
 * Add a string value to the log entry.
 *
 * @param l - A numeric value.
 */
LogEntry& LogEntry::operator+=(const char* s)
{
	// The convention for Agent++ log messages is that the
	// timestamp, etc. is followed by the class and method name,
	// then by the list of arguments.
	if (count == 0) 
		add_string(s);
	else {
	  if (count == 1) 
		add_string(": ");
	  else 
		add_string(", ");

	  add_string("(");
	  add_string(s);
	  add_string(")");
	}
	count++;
	return *this;
}

/**
 * Add a numeric value to the log entry.
 *
 * @param l - A numeric value.
 */
LogEntry& LogEntry::operator+=(const long l)
{
	if (count == 1) 
		add_string(": ");
	else 
		add_string(", ");

	count++;
	add_string("(");
	add_integer(l);
	add_string(")");
	return *this;
}

/**
 * Add an integer to the log.
 *
 * @param s - An integer value.
 * @return TRUE if the value has been added and FALSE if the log
 *         entry is full.
 */
bool LogEntry::add_integer(long l)
{
	char buf[40];
	sprintf(buf, "%ld", l);
	return add_string(buf);
}

/**
 * Add the current time to the log entry.
 */
bool LogEntry::add_timestamp(void)
{
	return add_string(DefaultLog::log()->now());
}


/*------------------------- class LogEntryImpl ------------------------*/

/**
 * Constructor for the standard log entry implementation.
 */  
LogEntryImpl::LogEntryImpl(unsigned char t) : LogEntry(t)
{
	value = new char[MAX_LOG_SIZE];
        value[0] = '\0';
	ptr = value;
	output_stopped = FALSE;
}

/**
 * Destructor for the standard log entry implementation.
 */  
LogEntryImpl::~LogEntryImpl()
{
	delete [] value;
}

/**
 * Add a string to the log.
 *
 * @param s - A string value.
 * @return TRUE if the value has been added and FALSE if the log
 *         entry is full.
 */
bool LogEntryImpl::add_string(const char* s)
{
	if (output_stopped)
		return FALSE;

	size_t len = strlen(s);
	if (len <= bytes_left()) {
		strcat(ptr, s);
		ptr += len;
		return TRUE;
	}

	if (bytes_left() >= 3) {
		strcat(ptr, "...");
		ptr += 3;
	}
	output_stopped = TRUE;
	return FALSE;
}	


/*-------------------------- class AgentLog ---------------------------*/

/**
 * Default constructor.
 */
AgentLog::AgentLog()
{
	for (int i=0; i<LOG_TYPES; i++)
		logfilter[i] = default_logfilter[i];
}

void AgentLog::set_filter(int logclass, unsigned char filter)
{ 
	int idx = (logclass/16)-1;
	if ((idx >=0) && (idx < LOG_TYPES) && (filter<16)) 
		logfilter[idx] = filter; 
}

unsigned char AgentLog::get_filter(int logclass) const
{
	int idx = (logclass/16)-1;	
	if ((idx >= 0) && (idx < LOG_TYPES)) { 
		return logfilter[idx]; 
	}
	return 0;
}

const char* AgentLog::now(char* buf)
{
	if (buf == NULL) buf = static_buf;

	time_t t;
	time(&t);
	struct tm *stm = localtime(&t);
	if (stm)
		strftime(buf, 18, "%Y%m%d.%H:%M:%S", localtime(&t));
	else
		buf[0] = 0;
	return buf;
}	

/*static*/ const char* AgentLog::get_current_time() 
{
	char* buf = new char[18];
        strcpy(buf, DefaultLog::log()->now());
	return buf;
}	


/*------------------------ class AgentLogImpl -------------------------*/

/**
 * Default constructor. Log is directed to stdout.
 */
AgentLogImpl::AgentLogImpl(FILE* fp) : AgentLog()
{
	set_dest(fp);
}

/**
 * Constructor with file name of a log file. Log is directed
 * to the given file.
 *
 * @param fname - The file name of a log file.
 */ 
AgentLogImpl::AgentLogImpl(const char* fname) : AgentLog()
{
	set_dest(fname);
}

/**
 * Destructor.
 */
AgentLogImpl::~AgentLogImpl()
{
	if (close_needed) fclose(logfile);
}

/**
 * Set destination of logs to a given file.
 * 
 * @param fname - A file name. "" directs logs to stdout.
 */
void AgentLogImpl::set_dest(const char* fname)
{
	close_needed = FALSE;
	if ((!fname) || (strlen(fname) == 0)) 
		logfile = stdout;
	else {
		logfile = fopen(fname, "a");
		if (logfile == NULL)
			logfile = stdout;
		else
			close_needed = TRUE;
	}
}

/**
 * Set destination of logs to a given file.
 * 
 * @param fname - A pointer to an open log file. 0 directs logs to stdout.
 */
void AgentLogImpl::set_dest(FILE* fp)
{
	logfile = fp ? fp : stdout;
	close_needed = FALSE;
}

/**
 * Create a new LogEntry.
 *
 * @param t - The type of the log entry.
 * @return A new instance of LogEntry (or of a derived class).
 */
LogEntry* AgentLogImpl::create_log_entry(unsigned char t) const
{
	return new LogEntryImpl(t);
}

/**
 * Add a LogEntry to the receiver Log.
 *
 * @param log - A log entry.
 * @return The receiver log itself.
 */
AgentLog& AgentLogImpl::operator+=(const LogEntry* log)
{
	fprintf(logfile, "%s\n", log->get_value());

	// check if critical error
	if ((log->get_class() == ERROR_LOG) && (log->get_level() == 0))
	{
	  fprintf(logfile, "Exiting now\n");
	  raise(SIGTERM);
	}

	return *this;
}


// define the default logs

#ifdef _THREADS
#ifndef _WIN32THREADS
#if !(defined (CPU) && CPU == PPC603)
pthread_mutex_t logmutex = PTHREAD_MUTEX_INITIALIZER;
#endif
#endif
#endif

AgentLog* DefaultLog::instance = 0;
LogEntry* DefaultLog::entry = 0;
SnmpSynchronized DefaultLog::mutex;

/*------------------------ class DefaultLog -------------------------*/

void DefaultLog::cleanup() 
{
  mutex.lock(); 
  if (instance) delete instance; 
  instance = 0; 
  mutex.unlock();
}

AgentLog* DefaultLog::init_ts(AgentLog* logger)
{ 
  AgentLog* r = instance;
  if (!instance) { 
    mutex.lock(); 
    if (!instance) { 
      instance = logger;
      r = instance;
    } 
    mutex.unlock(); 
  }
  return r;
}

AgentLog* DefaultLog::log() 
{ 
  AgentLog* r = instance;
  if (!r) {
    r = new AgentLogImpl();
    AgentLog* l = init_ts(r);
    if (r != l) delete r;
    r = l;
  } 
  return r; 
}
