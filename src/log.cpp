/*_############################################################################
  _## 
  _##  log.cpp  
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

#include <snmp_pp/log.h>
#include <snmp_pp/octet.h>

#if defined (CPU) && CPU == PPC603
#include <taskLib.h>
#endif

#ifdef SNMP_PP_NAMESPACE
using namespace Snmp_pp;
#endif

// default log filter: logs with level less or equal filter value are logged
// error, warning, event, info, debug:
#define LOG_DEFAULT_OFF      {  0, -1, -1, -1, -1, -1 }
#define LOG_DEFAULT_QUIET    { 15, 15, -1, -1, -1, -1 }
#define LOG_DEFAULT_STD      { 15, 15,  5, -1, -1, -1 }
#define LOG_DEFAULT_EVENTS   { 15, 15, 15, -1, -1, -1 }
#define LOG_DEFAULT_VERBOSE  { 15, 15, 15,  5, -1, -1 }
#define LOG_DEFAULT_FULL     { 15, 15, 15, 15, -1, -1 }
#define LOG_DEFAULT_DEBUG    { 15, 15, 15, 15,  5, -1 }
#define LOG_DEFAULT_ALL      { 15, 15, 15, 15, 15, 15 }
#define LOG_DEFAULT_ORIGINAL {  9,  9,  4,  6,  7, 15 }

#if defined(WITH_LOG_PROFILES)
#include <map>

using namespace std;

static map<string, int *> logfilter_profiles;
#endif
static int default_logfilter[] = LOG_DEFAULT_ORIGINAL;

#undef   LOG_INDENT

/*---------------------------- log profiles ---------------------------*/

#if defined(WITH_LOG_PROFILES)
static void
initLogProfiles()
{
    static int log_profile_off[6] = LOG_DEFAULT_OFF;
    static int log_profile_quiet[6] = LOG_DEFAULT_QUIET;
    static int log_profile_std[6] = LOG_DEFAULT_STD;
    static int log_profile_events[6] = LOG_DEFAULT_EVENTS;
    static int log_profile_verbose[6] = LOG_DEFAULT_VERBOSE;
    static int log_profile_full[6] = LOG_DEFAULT_FULL;
    static int log_profile_debug[6] = LOG_DEFAULT_DEBUG;
    static int log_profile_all[6] = LOG_DEFAULT_ALL;
    static int log_profile_original[6] = LOG_DEFAULT_ORIGINAL;

    logfilter_profiles["off"] = log_profile_off;
    logfilter_profiles["quiet"] = log_profile_quiet;
    logfilter_profiles["std"] = log_profile_std;
    logfilter_profiles["events"] = log_profile_events;
    logfilter_profiles["verbose"] = log_profile_verbose;
    logfilter_profiles["full"] = log_profile_full;
    logfilter_profiles["debug"] = log_profile_debug;
    logfilter_profiles["all"] = log_profile_all;
    logfilter_profiles["original"] = log_profile_original;
}
#endif

/*--------------------------- class LogEntry --------------------------*/

 /**
  * Initialize a log entry, showing timestamp, class, and level.
  *
  */
void LogEntry::init(void)
{
	add_timestamp();
	add_string(": ");

#if defined (CPU) && CPU == PPC603
	int pid = taskIdSelf();
#else
#ifdef POSIX_THREADS
        pthread_t pid = pthread_self();
	if (sizeof(pthread_t) == sizeof(long))
	{
	  add_integer(*(long*)(void*)(&pid));
	}
	else
	{
	  unsigned char *ptc = (unsigned char*)(void*)(&pid);
	  OctetStr os;
	  os.set_data(ptc, sizeof(pthread_t));
	  add_string(os.get_printable_hex());
	}
#else
#ifdef HAVE_GETPID
	pid_t pid = getpid();
#else
        int pid = 0;
#endif
	add_integer(pid);
#endif
#endif

	add_string(": ");

	char buf[20];
	sprintf(buf, "(%X)", get_level());
	add_string(buf);

	switch (type & LOG_CLASS_MASK) {
	case DEBUG_LOG:   add_string("DEBUG  : "); break;
	case INFO_LOG:	  add_string("INFO   : "); break;
	case WARNING_LOG: add_string("WARNING: "); break;
	case ERROR_LOG:	  add_string("ERROR  : "); break;
	case EVENT_LOG:	  add_string("EVENT  : "); break;
	case USER_LOG:	  add_string("USER   : "); break;
	}

#ifdef LOG_INDENT
	// indent log by level
	for (int i=0; i<(type & LOG_LEVEL_MASK); i++)
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
 * @return true if the value has been added and false if the log
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
 * Add a string to the log.
 *
 * @param s - A string value.
 * @return true if the value has been added and false if the log
 *         entry is full.
 */
bool LogEntryImpl::add_string(const char* s)
{
	if (output_stopped)
		return false;

	size_t len = strlen(s);
	if (len <= bytes_left()) {
		strcat(ptr, s);
		ptr += len;
		return true;
	}

	if (bytes_left() >= 3) {
		strcat(ptr, "...");
		ptr += 3;
	}
	output_stopped = true;
	return false;
}


/*-------------------------- class AgentLog ---------------------------*/

/**
 * Default constructor.
 */
AgentLog::AgentLog()
{
        int *log_profile;
#if defined(WITH_LOG_PROFILES) && defined(DEFAULT_LOG_PROFILE)
        map<string, int *>::const_iterator item = logfilter_profiles.find(DEFAULT_LOG_PROFILE);
        if( item != logfilter_profiles.end() )
                log_profile = item->second;
        else
#endif
                log_profile = default_logfilter;

	for (int i=0; i<LOG_TYPES; i++)
		logfilter[i] = log_profile[i];
}

#if defined(WITH_LOG_PROFILES)
void
AgentLog::set_profile(const char * const logprofile)
{
        int *log_profile;
        map<string, int *>::const_iterator item = logfilter_profiles.find(logprofile);
        if( item != logfilter_profiles.end() )
                log_profile = item->second;
        else
                log_profile = default_logfilter;

	for (int i=0; i<LOG_TYPES; i++)
		logfilter[i] = log_profile[i];
}
#endif

void AgentLog::set_filter(int logclass, unsigned char filter)
{
	int idx = (logclass/16)-1;
	if ((idx >=0) && (idx < LOG_TYPES) && ((filter<16)||(filter==0xFF)))
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
#ifdef HAVE_LOCALTIME_R
        struct tm tm_buffer;
        struct tm *stm = localtime_r(&t, &tm_buffer);
#else
	struct tm *stm = localtime(&t);
#endif
	if (stm)
		strftime(buf, 18, "%Y%m%d.%H:%M:%S", stm);
	else
		buf[0] = 0;
	return buf;
}

/*static*/ const char* AgentLog::get_current_time()
{
	char* buf = new char[18];
        DefaultLog::log()->now(buf);
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
	close_needed = false;
	if ((!fname) || (strlen(fname) == 0))
		logfile = stdout;
	else {
		logfile = fopen(fname, "a");
		if (logfile == NULL)
			logfile = stdout;
		else
			close_needed = true;
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
	close_needed = false;
}

/**
 * Create a new LogEntry.
 *
 * @param name - The name of the logging module
 * @param t - The type of the log entry.
 * @return A new instance of LogEntry (or of a derived class).
 */
LogEntry* AgentLogImpl::create_log_entry(const char * const name, unsigned char t) const
{
	return new LogEntryImpl(name, t);
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


/*------------------------ class DefaultLog -------------------------*/

// define the default logs

AgentLog* DefaultLog::instance = 0;
LogEntry* DefaultLog::entry = 0;
#ifdef _THREADS
SnmpSynchronized DefaultLog::mutex;
#endif

void DefaultLog::cleanup()
{
  lock();
  if (instance) delete instance;
  instance = 0;
  unlock();
}

AgentLog* DefaultLog::init_ts(AgentLog* logger)
{
  AgentLog* r = instance;
  if (!r)
  {
    lock();
    if (!instance)
    {
#ifdef WITH_LOG_PROFILES
#ifdef DEFAULT_LOG_PROFILE
      initLogProfiles();
#endif
#endif
      if(!logger)
        logger = new AgentLogImpl();
      instance = logger;
    }
    r = instance;
    unlock();
  }
  return r;
}
