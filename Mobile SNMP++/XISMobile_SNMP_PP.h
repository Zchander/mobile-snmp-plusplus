//
//  XISMobile_SNMP_PP.h 
//  Mobile SNMP++
//
//  Created by Xander Maas on 22-08-12.
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


#import <Foundation/Foundation.h>

#import "XIS_SNMPDefinitions.h"

/** Main class, containing three common commandline commands as methods
 
 This class implements three common commands, so these are available to the programmer in Objective-C or Objective-C++
 
 The project is based on SNMP++v3.2.25 from Jochen Katz, Frank Fock
 
 @warning 
 **LICENSE**
 Mobile SNMP++
 
 Created by Xander Maas on 22-08-12.
 Copyright (c) 2012 Xander Maas
 
 This software is based on SNMP++3.2.25 from Jochem Katz, Frank Fock
 
 Copyright (c) 2001-2010 Jochen Katz, Frank Fock
 
 This software is based on SNMP++2.6 from Hewlett Packard
 
 Copyright (c) 1996
 Hewlett-Packard Company
 
 **ATTENTION: USE OF THIS SOFTWARE IS SUBJECT TO THE FOLLOWING TERMS.**
 
 Permission to use, copy, modify, distribute and/or sell this software
 and/or its documentation is hereby granted without fee. User agrees
 to display the above copyright notice and this license notice in all
 copies of the software and any documentation of the software. User
 agrees to assume all liability for the use of the software;
 Hewlett-Packard, Jochen Katz and Xander Maas make no representations
 about the suitability of this software for any purpose. It is provided
 "AS-IS" without warranty of any kind, either express or implied. User
 hereby grants a royalty-free license to any and all derivatives based
 upon this software code base.
 
 **SNMP++v3.2.25**
 
 Copyright (c) 2001-2010 Jochen Katz, Frank Fock
 
 This software is based on SNMP++2.6 from Hewlett Packard:
 
   Copyright (c) 1996
   Hewlett-Packard Company
 
 **ATTENTION: USE OF THIS SOFTWARE IS SUBJECT TO THE FOLLOWING TERMS.**
 
 Permission to use, copy, modify, distribute and/or sell this software
 and/or its documentation is hereby granted without fee. User agrees
 to display the above copyright notice and this license notice in all
 copies of the software and any documentation of the software. User
 agrees to assume all liability for the use of the software;
 Hewlett-Packard and Jochen Katz make no representations about the
 suitability of this software for any purpose. It is provided
 "AS-IS" without warranty of any kind, either express or implied. User
 hereby grants a royalty-free license to any and all derivatives based
 upon this software code base.
 
 Stuttgart, Germany, Thu Sep  2 00:07:47 CEST 2010
 
 **SNMP++2.6**
 
 Copyright (c) 1999
 Hewlett-Packard Company
 
 **ATTENTION: USE OF THIS SOFTWARE IS SUBJECT TO THE FOLLOWING TERMS.**
 
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

@interface XISMobile_SNMP_PP : NSObject

// Converted consoleExamples
/// ---------------------------------------------------------------------------------------
/// @name Commandline tools converted into methods
/// ---------------------------------------------------------------------------------------

/** command: snmpDiscover - Returns an array with found SNMP agents on the specified network address
 
 @param onBroadcast The broadcast address of the network you wish to scan
 @param version The SNMP version you wish to use 
 1. SNMP version 1
 2. SNMP Version 2c
 @param aPort The UDP port used for the SNMP agent(s), defaults to 161
 @param community The readonly community string to identify yourself to the agent(s)
 @param retries The number of retries before returning the results
 @param timeout The timeout in msec
 @param error Is an autoreleased NSNumber containing the error code
 @return Returns an array containing the IP addresses of discovered SNMP agents
 
 @see [Mobile SNMP++ error codes]
 
 */
- (NSArray *)discoverAgents:(NSString *)onBroadcast
                snmpVersion:(uint)version
                 remotePort:(NSNumber *)aPort
              withCommunity:(NSString *)community
                      retry:(uint)retries
                    timeout:(uint)timeout
                      error:(NSNumber * __autoreleasing*)error;

/** Converted command: snmpGet - Returns the value corresponding to the requested OID
 
 @param oid The OID you wish to request
 @param hostAddress The address of the host you wish to query, might be an IPv4 address or a hostname
 @param version The SNMP version you wish to use
 1. SNMP version 1
 2. SNMP Version 2c
 @param aPort The UDP port used for the SNMP agent(s), defaults to 161
 @param community The readonly community string to identify yourself to the agent(s)
 @param retries The number of retries before returning the results
 @param timeout The timeout in msec
 @param error Is an autoreleased NSNumber containing the error code
 @return Returns a NSDictionary containing the OID and the corresponding value as NSString
 
 @see [Mobile SNMP++ error codes]
 
 */
- (NSDictionary *)getOid:(NSString *)oid
                 address:(NSString *)hostAddress
             snmpVersion:(uint)version
              remotePort:(NSNumber *)aPort
           withCommunity:(NSString *)community
                   retry:(uint)retries
                 timeout:(uint)timeout
                   error:(NSNumber * __autoreleasing*)error;

/** Converted command: snmpGet - Returns the value corresponding to the requested OID
 
 @param oid The top level OID you wish to start the request
 @param hostAddress The address of the host you wish to query, might be an IPv4 address or a hostname
 @param version The SNMP version you wish to use
 1. SNMP version 1
 2. SNMP Version 2c
 @param aPort The UDP port used for the SNMP agent(s), defaults to 161
 @param community The readonly community string to identify yourself to the agent(s)
 @param retries The number of retries before returning the results
 @param timeout The timeout in msec
 @param subTree A boolean which indicates wether you wish to walk only the subtree, or the whole tree. `YES` means you wish to walk only the subtree. `NO` means you want to read the whole SNMP tree.
 @param error Is an autoreleased NSNumber containing the error code
 @return Returns a NSDictionary containing the OIDs and the corresponding values as NSString
 
 @see [Mobile SNMP++ error codes]
 
 */
- (NSDictionary *)walkOid:(NSString *)oid
                  address:(NSString *)hostAddress
              snmpVersion:(uint)version
               remotePort:(NSNumber *)aPort
            withCommunity:(NSString *)community
                    retry:(uint)retries
                  timeout:(uint)timeout
          walkSubTreeOnly:(BOOL)subTree
                    error:(NSNumber * __autoreleasing*)error;

@end
