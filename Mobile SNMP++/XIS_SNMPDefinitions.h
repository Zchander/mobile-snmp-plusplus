//
//  XIS_SNMPDefinitions.h
//  Generic SNMP++ Class Definition for Objective-C
//
//  Created by Xander Maas on 18-07-12.
//  Copyright (c) 2012 Xander Maas
//
//  This software is based on SNMP++3.2.25 from Jochem Katz, Frank Fock
//
//      Copyright (c) 2001-2010 Jochen Katz, Frank Fock
//
//  This software is based on SNMP++2.6 from Hewlett Packard
//
//      Copyright (c) 1996
//      Hewlett-Packard Company
//
//  ATTENTION: USE OF THIS SOFTWARE IS SUBJECT TO THE FOLLOWING TERMS.
//  Permission to use, copy, modify, distribute and/or sell this software
//  and/or its documentation is hereby granted without fee. User agrees
//  to display the above copyright notice and this license notice in all
//  copies of the software and any documentation of the software. User
//  agrees to assume all liability for the use of the software;
//  Hewlett-Packard, Jochen Katz and Xander Maas make no representations
//  about the suitability of this software for any purpose. It is provided
//  "AS-IS" without warranty of any kind, either express or implied. User
//  hereby grants a royalty-free license to any and all derivatives based
//  upon this software code base.

/*
 
 _############################################################################
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
 _##########################################################################

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

 */

/** Some default definitions which are useful within Mobile SNMP++
 */
#ifndef XIS_SNMPDefinitions_h

#define XIS_SNMPDefinitions_h

// Some of the default oids
/// ---------------------------------------------------------------------------------------
/// @name Constant SNMP OID addresses
/// ---------------------------------------------------------------------------------------
/** sysDescr definition - 1.3.6.1.2.1.1.1.0
 sysDescr        1.3.6.1.2.1.1.1.0
 sysObjectID     1.3.6.1.2.1.1.2.0
 sysUpTime       1.3.6.1.2.1.1.3.0
 sysContact      1.3.6.1.2.1.1.4.0
 sysName         1.3.6.1.2.1.1.5.0
 sysLocation     1.3.6.1.2.1.1.6.0
 */
#define sysDescr        "1.3.6.1.2.1.1.1.0"
#define sysObjectID     "1.3.6.1.2.1.1.2.0"
#define sysUpTime       "1.3.6.1.2.1.1.3.0"
#define sysContact      "1.3.6.1.2.1.1.4.0"
#define sysName         "1.3.6.1.2.1.1.5.0"
#define sysLocation     "1.3.6.1.2.1.1.6.0"

// These are the error codes we return when
/// ---------------------------------------------------------------------------------------
/// @name Mobile SNMP++ error codes
/// ---------------------------------------------------------------------------------------
/**
 Code   Error                       Description
 0      NO_ERR_FOUND                No error found
 10     ERR_INVALID_DESTINATION     The destination address is invalid
 20     ERR_INVALID_TARGET          Unused at this moment
 30     ERR_NO_SNMP_SESSION         Could not create a SNMP session, 
 40     ERR_NO_SNMP_GET             Could not perform a SNMP GET, client might not support SNMP
 
 */
#define NO_ERR_FOUND            0
#define ERR_INVALID_DESTINATION 10
#define ERR_INVALID_TARGET      20
#define ERR_NO_SNMP_SESSION     30
#define ERR_NO_SNMP_GET         40


#endif
