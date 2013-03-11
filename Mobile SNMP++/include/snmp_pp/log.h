/*_############################################################################
  _## 
  _##  log.h  
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



#ifndef _log_h_
#define _log_h_

#include "snmp_pp/config_snmp_pp.h"
#include "snmp_pp/reentrant.h"

#ifndef WIN32
#include <sys/types.h>
#endif
#include <stdio.h>
#include <string.h>


#ifdef SNMP_PP_NAMESPACE
namespace Snmp_pp {
#endif

// Log entry class
#define ERROR_LOG	0x10
#define WARNING_LOG	0x20
#define EVENT_LOG	0x30
#define INFO_LOG	0x40
#define DEBUG_LOG	0x50
#define USER_LOG	0x60

#define LOG_TYPES       6

#ifdef _NO_LOGGING
 
#define LOG_BEGIN(x)	
#define LOG(x)		
#define LOG_END		

#define LOG_UNUSED(x)

#else

#define LOG_BEGIN(x)						\
{								\
	if (DefaultLog::log()->log_needed(x))			\
	{							\
		DefaultLog::log()->lock();			\
		DefaultLog::create_log_entry(x);	

#define LOG(x)		*DefaultLog::log_entry() += x

#define LOG_END							\
		*DefaultLog::log() += DefaultLog::log_entry();	\
		DefaultLog::delete_log_entry();			\
		DefaultLog::log()->unlock();			\
	}							\
}

#define LOG_UNUSED(x) x

#endif


/*--------------------------- class LogEntry --------------------------*/

/**
 * The LogEntry class represents log entries. An instance of LogEntry can be
 * added to a Log. Each LogEntry can be classified into the log classes
 * ERROR_LOG, WARNING_LOG, EVENT_LOG, INFO_LOG, DEBUG_LOG and USER_LOG with up
 * to 16 severity levels. A log entry consists of a descriptor string and
 * optional several string or numeric values.
 *
 * The log class USER_LOG can be used for applications, it is not used
 * within snmp++ and agent++.
 *
 * @note A error log of level 0 will stop program execution!
 *
 * @see Log
 * 
 * @author Frank Fock
 * @author Marty Janzen
 * @version 3.5f
 */

class DLLOPT LogEntry {
public:
	/**
	 * Constructor with log class and severity level
	 * 
	 * @param t - The type of the log entry. The type is composed 
	 *            by a logical OR of the log entry class with a level
	 *            of 0 up to 15. 
	 * @note A error log of level 0 will stop program execution!
	 */  
	LogEntry(unsigned char t) : type(t), count(0) {}

	/**
	 * Virtual destructor.
	 */  
	virtual ~LogEntry() {}

	/**
	 * Initialize a new log entry, showing timestamp, class, and level.
	 */ 
	virtual void init(void);

	/**
	 * Add a numeric value to the log entry.
	 *
	 * @param l - A numeric value.
	 */
	virtual LogEntry& operator+=(const long);

	/**
	 * Add a string value to the log entry.
	 *
	 * @param l - A numeric value.
	 */
	virtual LogEntry& operator+=(const char*);

	/**
	 * Get the contents of this log entry.
         *
	 * @return Current contents of this log entry.
	 */ 
	virtual const char* get_value(void) const { return ""; }

	/**
	 * Get the class of this log entry.
         *
	 * @return Log entry class.
	 */ 
	unsigned char get_class(void) const { return type & 0xF0; }

	/**
	 * Get the level of this log entry.
         *
	 * @return Log entry level.
	 */ 
	unsigned char get_level(void) const { return type & 0x0F; }

protected:
	/**
	 * Add a string to the log.
	 *
	 * @param s - A string value.
	 * @return TRUE if the value has been added and FALSE if the log
	 *         entry is full.
	 */
	virtual bool	add_string(const char*) = 0;

	/**
	 * Add an integer to the log.
	 *
	 * @param s - An integer value.
	 * @return TRUE if the value has been added and FALSE if the log
	 *         entry is full.
	 */
	virtual bool	add_integer(long);

	/**
	 * Add the current time to the log.
	 */
	virtual bool add_timestamp(void);

protected:
	unsigned char  	type;
	int		count;
};


/*------------------------- class LogEntryImpl ------------------------*/

#define MAX_LOG_SIZE	2550 // increased until debugprintf is not used!

/**
 * The LogEntryImpl class implements a log entry using a dynamically
 * allocated, but fixed-size buffer.
 * @see Log
 * 
 * @author Marty Janzen
 * @version 3.5f
 */

class DLLOPT LogEntryImpl : public LogEntry {
public:
	/**
	 * Constructor with log class and severity level
	 * 
	 * @param t - The type of the log entry. The type is composed 
	 *            by logical or the log entry class with a level
	 *            of 0 up to 15. 
	 * @note A error log of level 0 will stop program execution!
	 */  
	LogEntryImpl(unsigned char);

	/**
	 * Destructor.
	 */  
	~LogEntryImpl();

	/**
	 * Get the contents of this log entry.
         *
	 * @return Current contents of this log entry.
	 */ 
	virtual const char* get_value(void) const { return value; }

protected:
	/**
	 * Count the bytes left for additional values.
	 *
	 * @return The number of bytes left in this log entry.
	 */  
	unsigned int		bytes_left() 
	    { return (unsigned int)(MAX_LOG_SIZE-(ptr-value)-1); }

	/**
	 * Add a string to the log.
	 *
	 * @param s - A string value.
	 * @return TRUE if the value has been added and FALSE if the log
	 *         entry is full.
	 */
	bool		add_string(const char*);

private:
        char*		value;
	char*		ptr;
	bool		output_stopped;
};


/*--------------------------- class AgentLog --------------------------*/

/**
 * The AgentLog class is an abstract base class representing a log for
 * information that is generated during the run time of an AGENT++
 * SNMP agent.  A derived class only needs to provide appropriate
 * create_log_entry() and operator+= methods.
 * @see LogEntry
 *
 * @author Frank Fock
 * @version 3.5.14
 */
 
class DLLOPT AgentLog {
public:
	/**
	 * Default constructor.
	 */ 
	AgentLog();

	/**
	 * Virtual destructor.
	 */
	virtual ~AgentLog() {}

	/**
	 * Lock the receiver.  Default action is to perform no locking.
	 */
	virtual void	lock() {}

	/**
	 * Unlock the receiver.  Default action is to perform no locking.
	 */
	virtual void	unlock() {}

	/**
	 * Set a filter on a specified log class. Only log entries with
	 * a level less or equal than the specified level will be logged.
	 *
	 * @param logclass - A log entry class. @see LogEntry
	 * @param filter - A value between 0 and 15.
	 */ 
	virtual void	set_filter(int logclass, unsigned char filter);

	/**
	 * Gets the log level for the given log class.
	 * @return
	 *    a unsigned char value between 0 and 15 
	 */
	virtual unsigned char get_filter(int logclass) const; 

	/**
	 * Create a new LogEntry.
	 *
	 * @param t - The type of the log entry.
	 * @return A new instance of LogEntry (or of a derived class).
	 */
	virtual LogEntry* create_log_entry(unsigned char) const = 0;

	/**
	 * Add a LogEntry to the receiver Log.
	 *
	 * @param log - A log entry.
	 * @return The receiver log itself.
	 */
	virtual AgentLog& operator+=(const LogEntry*) = 0;

	/**
	 * Check whether a logging for the given type of LogEntry
	 * has to be done or not.
	 *
	 * @param type
	 *    the type of the log entry. The type is composed 
	 *    by logical or the log entry class with a level
	 *    of 0 up to 15.
	 * @return
	 *    TRUE if logging is needed, FALSE otherwise.
	 */
	virtual bool	log_needed(unsigned char t) 
	  { return ((t & 0x0F) <= logfilter[(t / 16) - 1]); }

	/**
	 * Return the current time as a string.
	 * 
	 * @param
	 *    a buffer (of at least 18 characters, for the default method)
         *    into which to place a string containg the current time.
         *    If no buffer is supplied, a static area is used.
	 * @return
	 *    a string containing the current time. Either the supplied
	 *    buffer or the static area.
	 */
	virtual const char*	now(char* = 0);

	/**
	 * Return the current time as a string, using the current
         * default log object.  (For backward compatibility.)
	 * @note that the user is responsible for deleting the returned
	 * string, using delete [].
	 * 
	 * @return
	 *    a string containg the current time.
	 */
	static const char*	get_current_time();

protected:
	unsigned char		logfilter[LOG_TYPES];
	char			static_buf[18];
};


/*------------------------- class AgentLogImpl ------------------------*/

/**
 * The AgentLogImpl class is an implementation of AgentLog which writes
 * log messages to a file, or to stdout or stderr.
 * @see LogEntry 
 *
 * @author Frank Fock
 * @version 3.5f
 */
 
class DLLOPT AgentLogImpl : public AgentLog {
public:
	/**
	 * Default constructor, with optional pointer to an open log file.
         * Log is directed to the file if given, otherwise to stdout
	 *
	 * @param fp - An open log file.  0 implies stdout.
	 */ 
	AgentLogImpl(FILE* = stdout);

	/**
	 * Constructor with file name of a log file. Log is directed
	 * to the given file.
	 *
	 * @param fname - The file name of a log file.
	 */ 
	AgentLogImpl(const char*);

	/**
	 * Destructor.
	 */
	~AgentLogImpl();

	/**
	 * Set destination of logs to a given file.
	 * 
	 * @param fname - A file name. "" directs logs to stdout.
	 */
	void		set_dest(const char*);

	/**
	 * Set destination of logs to a given file.
	 * 
	 * @param fp - A pointer to an open file.  0 directs logs to stdout.
	 */
	void		set_dest(FILE*);

	/**
	 * Lock the receiver.
	 */
	void lock()
	{
#ifdef _THREADS
		logLock.lock();
#endif
	}

	/**
	 * Unlock the receiver.
	 */
	 void unlock()
	{
#ifdef _THREADS
		logLock.unlock();
#endif
	}

	/**
	 * Create a new LogEntry.
	 *
	 * @param t - The type of the log entry.
	 * @return A new instance of LogEntry (or of a derived class).
	 */
	virtual LogEntry* create_log_entry(unsigned char) const;

	/**
	 * Add a LogEntry to the receiver Log.
	 *
	 * @param log - A log entry.
	 * @return The receiver log itself.
	 */
	virtual AgentLog& operator+=(const LogEntry*);

protected:
	SnmpSynchronized	logLock;
	FILE*			logfile;
	bool			close_needed;
};


/*--------------------------- class DefaultLog --------------------------*/

/**
 * The DefaultLog class has a static Log member, that is used by the
 * AGENT++ API for logging.
 *
 * @version 3.5.24
 * @author Frank Fock (singleton pattern -> Philippe Roger)
 */  

class DLLOPT DefaultLog {
public:
	DefaultLog() { }
	~DefaultLog() { }

	/**
	 * Initialize the default logger with the given logging implementation.
	 *
	 * @note Call cleanup function before the application exits
	 * @note The DefaultLog class takes ownership of the pointer. Do
	 *       not delete it yourself.
	 * @note This method is NOT THREADSAFE. It must be called in main()
	 *       before any logging takes place.
	 * 
	 * @param logger
	 *    an AgentLog instance to be used as default logger. A previously
	 *    set logger will be deleted.
	 */
	static void init(AgentLog* logger) 
	  { if (instance) delete instance; instance = logger; }

	/**
	 * Initialize the default logger with the given logging implementation
	 * if there is currently no logger instance set.
	 *
	 * @note Call cleanup function before the application exits
	 * @note The DefaultLog class takes ownership of the pointer. Do
	 *       not delete it yourself.
	 * @note This method is THREADSAFE. 
	 * 
	 * @param logger
	 *    an AgentLog instance to be used as default logger.
	 * @return
	 *    the existing logger (if there was any) or the new logger pointer.
	 * @since 3.5.24
	 */
	static AgentLog* init_ts(AgentLog* logger);

	/**
	 * Free the logging implementation.
	 * @note This method is THREADSAFE. 
	 */
	static void cleanup();

	/**
	 * Return the default logger. 
	 *
	 * @return
	 *    a pointer to an AgentLog instance.
	 */
	static AgentLog* log(); 

	/**
	 * Create a new log entry or reuse an existing one.
	 *
	 * @param type
	 *    the type of the log entry as bitwise or of log class and level. 
	 */
	static void create_log_entry(unsigned char t)
	  { if (!entry) { entry = log()->create_log_entry(t); entry->init();} }

	/**
	 * Return the current log entry. If there is none, an ERROR_LOG entry
	 * with level 1 will be created.
	 *
	 * @return
	 *    a pointer to a LogEntry instance.
	 */
	static LogEntry* log_entry() 
	  { if (!entry) create_log_entry(ERROR_LOG | 1); return entry; } 

	/**
	 * Delete current log entry.
	 */
	static void delete_log_entry() 
	  { if (entry) delete entry; entry = 0; }

protected:

	static AgentLog* instance;
	static LogEntry* entry;
	static SnmpSynchronized mutex;
};


#ifdef SNMP_PP_NAMESPACE
}
#endif
#endif // _log_h_
