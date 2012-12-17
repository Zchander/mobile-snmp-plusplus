//
//  XISMobile_SNMP_PP.m 
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

#import "XISMobile_SNMP_PP.h"

#import "snmp_pp/snmp_pp.h"

#ifdef SNMP_PP_NAMESPACE
using namespace Snmp_pp;
#endif

// When no BULK_MAX has been defined, define it as 10
#ifndef BULK_MAX
#define BULK_MAX 10
#endif

@interface XISMobile_SNMP_PP ()

// Private methods
// (Sub)System initialization
- (void)socketStartUp;
- (void)socketCleanUp;
@end

@implementation XISMobile_SNMP_PP

#pragma mark - Lifecycle methods
- (id)init
{
    if ( self ) {
        self = [super init];
        
        // Start the socket subsystem right away...
        [self socketStartUp];
    }
    return self;
}

- (void)dealloc
{
    [self socketCleanUp];
}

#pragma mark - Public methods
#pragma mark -- Converted consoleExamples
- (NSArray *)discoverAgents:(NSString *)onBroadcast
                snmpVersion:(uint)version
                 remotePort:(NSNumber *)aPort
              withCommunity:(NSString *)community
                      retry:(uint)retries
                    timeout:(uint)timeout
                      error:(NSError * __autoreleasing*)error
{
    int status;
    
    uint l_retries;
    uint l_timeout;
    NSNumber *localPort;
    
    NSMutableArray *discoveryArray = [[NSMutableArray alloc] init];
    NSString *responder;
    
    snmp_version snmpVersion = version1;
    OctetStr snmpCommunity([community UTF8String]);
    
    if ( aPort == nil ) {
        localPort = [NSNumber numberWithInteger:161];
    } else localPort = aPort;
    
    if ( retries > 100 ) {
        l_retries = 100;
    } else l_retries = retries;
    
    if ( timeout < 100 ) {
        l_timeout = 100;
    } else if ( timeout > 500 ) {
        l_timeout = 500;
    } else l_timeout = timeout;
    
    switch ( version ) {
        case 1:
            snmpVersion = version1;
            break;
        case 2:
            snmpVersion = version2c;
            break;
        default:
            snmpVersion = version1;
            break;
    }
    
    // Create an oid we want to check (one of the default one(s))
    Oid oid(sysDescr);
    
    // Generate a SNMP++ Generic address
    UdpAddress udpAddr([onBroadcast UTF8String]);
    
    // Check if it is a valid address
    // It the address is invalid, we return a 'nil' for the array AND the *error ival
    // will contain the error code
    if ( !udpAddr.valid()) {
        
        *error = [self constructError:ERR_INVALID_DESTINATION];
        
#ifdef DEBUG
        NSLog(@"ERROR SNMPController (discoverAgents:onBroadcast:snmpVersion:remotePort:withCommunity:retry:timeout:error:)");
        NSLog(@"ERROR SNMP++ Invalid host address or IP: %@", onBroadcast);
        NSLog(@"ERROR ====================");
#endif
        return nil;
    }
    
    // Create the SNMP session
    Snmp snmp(status, 0, (udpAddr.get_ip_version() == Address::version_ipv6));
    
    if ( status != SNMP_CLASS_SUCCESS ) {
#ifdef DEBUG
        NSLog(@"ERROR SNMPController (discoverAgents:onBroadcast:snmpVersion:remotePort:withCommunity:retry:timeout:error:)");
        NSLog(@"ERROR SNMP++ Could not create session: %s", snmp.error_msg(status));
        NSLog(@"ERROR ====================");
#endif
        *error = [self constructError:ERR_NO_SNMP_SESSION];
        return nil;
    }
    // Next we are going to issue the broadcast, blocked mode
    
    // Set the port
    udpAddr.set_port([aPort integerValue]);
    
#ifdef DEBUG
    NSLog(@"DEBUG SNMPController (discoverAgents:onBroadcast:snmpVersion:remotePort:withCommunity:retry:timeout:error:)");
    NSLog(@"DEBUG SNMP++ broadcast to %@ with version %d on Port: %d using community %@ with retries %d and timeout %d", onBroadcast, version, [aPort integerValue], community, retries, timeout);
    NSLog(@"DEBUG SNMP++ What is the actual community we are sending.... %s", snmpCommunity.get_printable());
    NSLog(@"DEBUG ====================");
#endif
    
    UdpAddressCollection addresses;
    
    // Perform multiple loops as requested from retries
    for ( uint loops = 1; loops <= l_retries; ++loops)
    {
        
        status = snmp.broadcast_discovery(addresses,
                                          (l_timeout + 99) / 100,
                                          udpAddr,
                                          snmpVersion,
                                          &snmpCommunity);
        
#ifdef DEBUG
        if ( status == SNMP_CLASS_SUCCESS )
        {
            NSLog(@"DEBUG SNMPController (discoverAgents:onBroadcast:snmpVersion:remotePort:withCommunity:retry:timeout:error:)");
            NSLog(@"DEBUG SNMP++ broadcast sent succesfull: %d", loops);
            NSLog(@"DEBUG ====================");
        } else
        {
            NSLog(@"DEBUG SNMPController (discoverAgents:onBroadcast:snmpVersion:remotePort:withCommunity:retry:timeout:error:)");
            NSLog(@"DEBUG SNMP++ broadcast error: %s (%d)", snmp.error_msg(status), status);
            NSLog(@"DEBUG ====================");
        }
#endif
    }
    
    // Filter out all the duplicates
    UdpAddressCollection filteredAddresses;
    int dummy_pos;
    
    for ( int n=0; n < addresses.size(); ++n)
        if ( filteredAddresses.find(addresses[n], dummy_pos) == FALSE )
            filteredAddresses += addresses[n];
    
    // Add all the new addresses to the array
    // And log them in DEBUG
#ifdef DEBUG
    NSLog(@"DEBUG SNMPController (discoverAgents:onBroadcast:snmpVersion:remotePort:withCommunity:retry:timeout:error:)");
    NSLog(@"DEBUG SNMP++ broadcast found %d agents", filteredAddresses.size());
#endif
    
    for ( int m = 0; m < filteredAddresses.size(); ++m) {
    
        responder = [NSString stringWithUTF8String:filteredAddresses[m].get_printable()];
        
#ifdef DEBUG
        NSLog(@"DEBUG SNMP++ got answer from: %@", responder);
#endif
        // Also add the printer to the array
        [discoveryArray addObject:responder];
    }
    
#ifdef DEBUG
    NSLog(@"DEBUG SNMP++ Contents of array is:\n%@", discoveryArray);
    NSLog(@"DEBUG ====================");
#endif
    
    NSArray *results = [[NSArray alloc] initWithArray:discoveryArray];
    
    // Make sure error is nil!
    
    *error = nil;
    
    return results;
}

- (NSDictionary *)getOid:(NSString *)oid
                 address:(NSString *)hostAddress
             snmpVersion:(uint)version
              remotePort:(NSNumber *)aPort
           withCommunity:(NSString *)community
                   retry:(uint)retries
                 timeout:(uint)timeout
                   error:(NSError * __autoreleasing*)error
{
    int status;
    
    uint l_retries;
    uint l_timeout;
    NSNumber *localPort;
    
    snmp_version snmpVersion = version1;
    OctetStr snmpCommunity([community UTF8String]);
    
    if ( aPort == nil ) {
        localPort = [NSNumber numberWithInteger:161];
    } else localPort = aPort;
    
    if ( retries > 100 ) {
        l_retries = 100;
    } else l_retries = retries;
    
    if ( timeout < 100 ) {
        l_timeout = 100;
    } else if ( timeout > 500 ) {
        l_timeout = 500;
    } else l_timeout = timeout;
    
    switch ( version ) {
        case 1:
            snmpVersion = version1;
            break;
        case 2:
            snmpVersion = version2c;
            break;
        default:
            snmpVersion = version1;
            break;
    }
    
    // Generate a SNMP++ generic address
    UdpAddress udpAddress([hostAddress UTF8String]);
    
    // Check if it is a valid address, if we got an invalid address
    // we return a 'nil' dictionary and an error code
    if ( !udpAddress.valid() ) {
        *error = [self constructError:ERR_INVALID_DESTINATION];
#ifdef DEBUG
        NSLog(@"ERROR SNMPController (getOid:hostAddress:oid:snmpVersion:remotePort:withCommunity:retry:timeout:error:)");
        NSLog(@"ERROR SNMP++ Invalid host address or IP: %@", hostAddress);
        NSLog(@"ERROR ====================");
#endif
        return nil;
    }
    
    // Check if we got a valid Oid, otherwise use sysDescr
    Oid localOid([oid UTF8String]);
    if ( !localOid.valid() ) {
#ifdef DEBUG
        NSLog(@"ERROR SNMPController (getOid:hostAddress:oid:snmpVersion:remotePort:withCommunity:retry:timeout:error:)");
        NSLog(@"ERROR SNMP++ We got an invalid Oid (%@), we are using sysDescr for now (.1.3.6.1.2.1.1.1.0)", oid);
        NSLog(@"ERROR ====================");
#endif
        Oid localOid("1.3.6.1.2.1.1.1.0");
    }
    
    // Create the SNMP session
    Snmp snmp(status, 0, (udpAddress.get_ip_version() == Address::version_ipv6));
    
    if ( status != SNMP_CLASS_SUCCESS ) {
#ifdef DEBUG
        NSLog(@"ERROR SNMPController (getOid:hostAddress:oid:snmpVersion:remotePort:withCommunity:retry:timeout:error:)");
        NSLog(@"ERROR SNMP++ Could not create session: %s", snmp.error_msg(status));
        NSLog(@"ERROR ====================");
#endif
        *error = [self constructError:ERR_NO_SNMP_SESSION];
        return nil;
    }
    
    // We are ready to build the SNMP++ object we need
    Pdu pdu;                                    // construct a Pdu object
    Vb vb;                                      // construct a Vb object
    vb.set_oid(localOid);                       // set the Oid portion of the Vb
    pdu += vb;                                  // add the vb to the Pdu
    
    // Set the port
    udpAddress.set_port([localPort integerValue]);
    CTarget ctarget(udpAddress);                // Make a target using the address
    
    ctarget.set_version(snmpVersion);           // Set the SNMP version
    ctarget.set_retry(l_retries);               // Set the number of retries
    ctarget.set_timeout(l_timeout);             // Set the timeout for the request
    ctarget.set_readcommunity(snmpCommunity);   // Set the read community name
    
    // Issue the request, in blocked mode
#ifdef DEBUG
    NSLog(@"DEBUG SNMPController (getOid:hostAddress:oid:snmpVersion:remotePort:withCommunity:retry:timeout:error:)");
    NSLog(@"DEBUG SNMP++ GET to %@ (oid: %@) with version %d on Port: %d using community %@ with retries %d and timeout %d", hostAddress, oid, version, [aPort integerValue], community, retries, timeout);
    NSLog(@"DEBUG SNMP++ What is the community we are sending.... %s", snmpCommunity.get_printable());
    NSLog(@"DEBUG ====================");
#endif
    
    SnmpTarget *target;
    target = &ctarget;
    
    status = snmp.get(pdu, *target);
    
    NSMutableDictionary *resultsDict = [[NSMutableDictionary alloc] init];
    
    if ( status == SNMP_CLASS_SUCCESS ) {
        pdu.get_vb(vb, 0);
        
#ifdef DEBUG
        NSLog(@"DEBUG SNMPController (getOid:hostAddress:oid:snmpVersion:remotePort:withCommunity:retry:timeout:error:)");
        NSLog(@"DEBUG SNMP++ -- Oid: %s", vb.get_printable_oid());
        NSLog(@"DEBUG SNMP++ -- Value: %s", vb.get_printable_value());
#endif
        
        // Add the result(s) to the resultsDict
        [resultsDict setObject:[NSString stringWithUTF8String:vb.get_printable_value()] forKey:[NSString stringWithUTF8String:vb.get_printable_oid()]];
        
        if ( (vb.get_syntax() == sNMP_SYNTAX_ENDOFMIBVIEW) ||
             (vb.get_syntax() == sNMP_SYNTAX_NOSUCHINSTANCE) ||
             (vb.get_syntax() == sNMP_SYNTAX_NOSUCHOBJECT)) {
            
            NSLog(@"ERROR SNMP++ Exception found: %lu", vb.get_syntax());

        } else {
            
            NSLog(@"ERROR SNMP++ GET Error: %s (%d)", snmp.error_msg(status), status);
            
        }
#ifdef DEBUG
        NSLog(@"DEBUG ====================");
#endif
    }
    
    // Make sure error is nil!
    
    *error = nil;
    
    return ( resultsDict != nil ) ? [NSDictionary dictionaryWithDictionary:resultsDict] : nil;
    
}

- (NSDictionary *)walkOid:(NSString *)oid
                  address:(NSString *)hostAddress
              snmpVersion:(uint)version
               remotePort:(NSNumber *)aPort
            withCommunity:(NSString *)community
                    retry:(uint)retries
                  timeout:(uint)timeout
          walkSubTreeOnly:(BOOL)subTree
                    error:(NSError * __autoreleasing*)error
{
    int requests = 0;                           // Track the number of requests
    int objects = 0;                            // Track the number of objects
    
    int status;
    
    uint l_retries;
    uint l_timeout;
    NSNumber *localPort;
    NSMutableDictionary *resultsDict = [[NSMutableDictionary alloc] init];
    
    snmp_version snmpVersion = version1;
    OctetStr snmpCommunity([community UTF8String]);
    
    if ( aPort == nil ) {
        localPort = [NSNumber numberWithInteger:161];
    } else localPort = aPort;
    
    if ( retries > 100 ) {
        l_retries = 100;
    } else l_retries = retries;
    
    if ( timeout < 100 ) {
        l_timeout = 100;
    } else if ( timeout > 500 ) {
        l_timeout = 500;
    } else l_timeout = timeout;
    
    switch ( version ) {
        case 1:
            snmpVersion = version1;
            break;
        case 2:
            snmpVersion = version2c;
            break;
        default:
            snmpVersion = version1;
            break;
    }
    
    // Generate a SNMP++ generic address
    UdpAddress udpAddress([hostAddress UTF8String]);
    
    // Check if it is a valid address, if we got an invalid address
    // we return a 'nil' dictionary and an error code
    if ( !udpAddress.valid() ) {
        *error = [self constructError:ERR_INVALID_DESTINATION];
#ifdef DEBUG
        NSLog(@"ERROR SNMPController (walkOid:address:snmpVersion:remotePort:withCommunity:retry:timeout:walkSubTreeOnly:error:)");
        NSLog(@"ERROR SNMP++ Invalid host address or IP: %@", hostAddress);
        NSLog(@"ERROR ====================");
#endif
        return nil;
    }
    
    // Check if we got a valid Oid, otherwise use sysDescr
    Oid localOid([oid UTF8String]);
    if ( !localOid.valid() ) {
#ifdef DEBUG
        NSLog(@"ERROR SNMPController (walkOid:address:snmpVersion:remotePort:withCommunity:retry:timeout:walkSubTreeOnly:error:)");
        NSLog(@"ERROR SNMP++ We got an invalid Oid (%@), we are starting at .1", oid);
        NSLog(@"ERROR ====================");
#endif
        Oid localOid("1");
    }
    
    Snmp snmp(status, 0, (udpAddress.get_ip_version() == Address::version_ipv6));
    
    if ( status != SNMP_CLASS_SUCCESS ) {
#ifdef DEBUG
        NSLog(@"ERROR SNMPController (walkOid:address:snmpVersion:remotePort:withCommunity:retry:timeout:walkSubTreeOnly:error:)");
        NSLog(@"ERROR SNMP++ Could not create session: %s", snmp.error_msg(status));
        NSLog(@"ERROR ====================");
#endif
        *error = [self constructError:ERR_NO_SNMP_SESSION];
        return nil;
    }
    
    // We are going to create our SNMP++ object
    Pdu pdu;                                    // construct a Pdu object
    Vb vb;                                      // construct a Vb object
    vb.set_oid(localOid);                       // set the Oid portion of the Vb
    pdu += vb;                                  // add the vb to the Pdu
    
    // Set the port
    udpAddress.set_port([localPort integerValue]);
    CTarget ctarget(udpAddress);                // Make a target using the address
    
    ctarget.set_version(snmpVersion);           // Set the SNMP version
    ctarget.set_retry(l_retries);               // Set the number of retries
    ctarget.set_timeout(l_timeout);             // Set the timeout for the request
    ctarget.set_readcommunity(snmpCommunity);   // Set the read community name
    
    // Issue the request, in blocked mode
#ifdef DEBUG
    NSLog(@"DEBUG SNMPController (walkOid:address:snmpVersion:remotePort:withCommunity:retry:timeout:walkSubTreeOnly:error:)");
    NSLog(@"DEBUG SNMP++ Walk to %@ (start at oid: %@) with version %d on Port: %d using community %@ with retries %d and timeout %d (walk subTree: %@)", hostAddress, oid, version, [aPort integerValue], community, retries, timeout, (subTree) ? @"YES" : @"NO");
    NSLog(@"DEBUG SNMP++ What is the community we are sending.... %s", snmpCommunity.get_printable());
    NSLog(@"DEBUG ====================");
#endif
    
    SnmpTarget *target;
    target = &ctarget;
    
    while ( (status = snmp.get_bulk(pdu, *target, 0, BULK_MAX)) == SNMP_CLASS_SUCCESS ) {
        requests++;
        
        for ( int z = 0; z < pdu.get_vb_count(); z++ ) {
            
            pdu.get_vb(vb, z);
            Oid tmp;
            vb.get_oid(tmp);
            if ( subTree && (localOid.nCompare(localOid.len(), tmp) != 0) ) {
#ifdef DEBUG
                NSLog(@"DEBUG SNMPController (walkOid:address:snmpVersion:remotePort:withCommunity:retry:timeout:walkSubTreeOnly:error:)");
                NSLog(@"DEBUG SNMP++ End of (sub)tree reached");
                NSLog(@"DEBUG SNMP++ Total # of requests: %d", requests);
                NSLog(@"DEBUG SNMP++ Total # of objects: %d", objects);
                NSLog(@"DEBUG ====================");
#endif
#warning WE MUST STILL RETURN SOMETHING FROM THE SUBTREE 
                return ( resultsDict != nil ) ? [NSDictionary dictionaryWithDictionary:resultsDict] : nil;
            }
            
            objects++;
            
            // We have to look for var bind exception (SNMPv2c only!)
            if ( vb.get_syntax() != sNMP_SYNTAX_ENDOFMIBVIEW ) {
#ifdef DEBUG
                NSLog(@"DEBUG SNMPController (walkOid:address:snmpVersion:remotePort:withCommunity:retry:timeout:walkSubTreeOnly:error:)");
                NSLog(@"DEBUG SNMP++ Got an object");
                NSLog(@"DEBUG SNMP++ oid: %s", vb.get_printable_oid());
                NSLog(@"DEBUG SNMP++ value: %s", vb.get_printable_value());
                NSLog(@"DEBUG ====================");
#endif
                [resultsDict setObject:[NSString stringWithUTF8String:vb.get_printable_value()] forKey:[NSString stringWithUTF8String:vb.get_printable_oid()]];
            } else {
#ifdef DEBUG
                NSLog(@"DEBUG SNMPController (walkOid:address:snmpVersion:remotePort:withCommunity:retry:timeout:walkSubTreeOnly:error:)");
                NSLog(@"DEBUG SNMP++ End of MIB reached");
                NSLog(@"DEBUG SNMP++ Total # of requests: %d", requests);
                NSLog(@"DEBUG SNMP++ Total # of objects: %d", objects);
                NSLog(@"DEBUG ====================");
#endif
                return ( resultsDict != nil ) ? [NSDictionary dictionaryWithDictionary:resultsDict] : nil;
            }
        }
        
        // Last vb becomes seed of the next request
        pdu.set_vblist(&vb, 1);
    }
    
    if ( status != SNMP_ERROR_NO_SUCH_NAME ) {
        NSLog(@"DEBUG SNMPController (walkOid:address:snmpVersion:remotePort:withCommunity:retry:timeout:walkSubTreeOnly:error:)");
        NSLog(@"DEBUG SNMP++ Walk Error");
        NSLog(@"DEBUG SNMP++ Total # of requests: %d", requests);
        NSLog(@"DEBUG SNMP++ Total # of objects: %d", objects);
        NSLog(@"DEBUG ====================");
    }
    
    // Make sure error is nil!
    
    *error = nil;
    
#warning IS THIS CORRECT??
    return ( resultsDict != nil ) ? [NSDictionary dictionaryWithDictionary:resultsDict] : nil;
}

/*
 * To be re-implemented/corrected
 *
 
- (NSDictionary *)getBulk:(NSArray *)oids
             address:(NSString *)hostAddress
         snmpVersion:(uint)version
          remotePort:(NSNumber *)aPort
       withCommunity:(NSString *)community
               retry:(uint)retries
             timeout:(uint)timeout
        nonRepeaters:(uint)nonRepeaters
       maxRepetition:(uint)maxRepetitions
               error:(NSError *__autoreleasing *)error
{
    int status;
    __block int errorCode = 0;
    
    uint l_retries;
    uint l_timeout;
    uint l_repeaters;
    uint l_repetitions;
    NSNumber *localPort;
    
    snmp_version snmpVersion = version1;
    OctetStr snmpCommunity([community UTF8String]);
    
    if ( aPort == nil || aPort == 0 ) {
        localPort = [NSNumber numberWithInt:161];
    } else localPort = aPort;
    
    if ( retries > 100 ) {
        l_retries = 100;
    } else l_retries = retries;
    
    if ( timeout < 100 ) {
        l_timeout = 100;
    } else if ( timeout > 500 ) {
        l_timeout = 500;
    } else l_timeout = timeout;
    
    if ( nonRepeaters > 10 ) {
        l_repeaters = 0;
    } else l_repeaters = nonRepeaters;
    
    if ( maxRepetitions > 50 ) {
        l_repetitions = 50;
    } else l_repetitions = maxRepetitions;
    
    switch ( version ) {
        case 1:
            snmpVersion = version1;
            break;
        case 2:
            snmpVersion = version2c;
            break;
        default:
            snmpVersion = version1;
            break;
    }
    
    // Generate a SNMP++ generic address
    UdpAddress udpAddress([hostAddress UTF8String]);
    
    // Check if it is a valid address, if we got an invalid address
    // we return a 'nil' dictionary and an error code
    if ( !udpAddress.valid() ) {
        *error = [self constructError:ERR_INVALID_DESTINATION];
#ifdef DEBUG
        NSLog(@"ERROR SNMPController (getBulk:hostAddress:snmpVersion:remotePort:withCommunity:retry:timeout:nonRepeaters:maxRepetitions:error:)");
        NSLog(@"ERROR SNMP++ Invalid host address or IP: %@", hostAddress);
        NSLog(@"ERROR ====================");
#endif
        return nil;
    }

    // Create a Pdu and a Vb object
    __block Pdu pdu;
    __block Vb vb;
    
    // Loop through the array with OIDs and check them
    if ( (oids.count == 0) || oids == nil ) {
        // Seems we got an empty or no array, use the standard sysDescr OID
        Oid l_oid("1.3.6.1.2.1.1.1");
        vb.set_oid(l_oid);
        pdu += vb;
    } else {
        [oids enumerateObjectsUsingBlock:^(id oid, NSUInteger idx, BOOL *stop){
            
#ifdef DEBUG
            NSLog(@"DEBUG SNMPController (getBulk:hostAddress:snmpVersion:remotePort:withCommunity:retry:timeout:nonRepeaters:maxRepetitions:error:)");
            NSLog(@"DEBUG We are querying: %@ (index %d)", oid, idx);
            NSLog(@"DEBUG ====================");
#endif
            
            if ( oid == nil || ![oid isKindOfClass:[NSString class]] ) {
                // Seems we got an empty oid or the object has the wrong class,
                // return a 'nil' dictionary and an error code
                errorCode = ERR_INVALID_OID_OBJECT;
                
                // Force a stop!
                *stop =YES;
                
            }
            
#ifdef DEBUG
            
#endif
            Oid l_oid([oid UTF8String]);
            
            if ( !l_oid.valid() ) {
                errorCode = ERR_INVALID_OID;
                
                // Force a stop!
                *stop = YES;
                
            } else {
                vb.set_oid(l_oid);
                pdu += vb;
                
                // Might not be required, but to be sure...
                errorCode = 0;
            }
        }];
    }
    
    if ( errorCode != 0 ) {
        // Seems some error occured, return 'nil' and the error code
        *error = [NSNumber numberWithInteger:errorCode];
        return nil;
    }

    // So far, so good, create the SNMP session
    Snmp snmp(status, 0, (udpAddress.get_ip_version() == Address::version_ipv6));
    
    if ( status != SNMP_CLASS_SUCCESS ) {
#ifdef DEBUG
        NSLog(@"ERROR SNMPController (getBulk:hostAddress:snmpVersion:remotePort:withCommunity:retry:timeout:nonRepeaters:maxRepetitions:error:)");
        NSLog(@"ERROR SNMP++ Could not create session: %s", snmp.error_msg(status));
        NSLog(@"ERROR ====================");
#endif
        *error = [self constructError:ERR_NO_SNMP_SESSION];
        return nil;
    }
    
    // Set the port
    udpAddress.set_port([localPort integerValue]);
    CTarget ctarget(udpAddress);                // Make a target using the address
    
    ctarget.set_version(snmpVersion);           // Set the SNMP version
    ctarget.set_retry(l_retries);               // Set the number of retries
    ctarget.set_timeout(l_timeout);             // Set the timeout for the request
    ctarget.set_readcommunity(snmpCommunity);   // Set the read community name
    
    // Issue the request, in blocked mode
#ifdef DEBUG
    NSLog(@"ERROR SNMPController (getBulk:hostAddress:snmpVersion:remotePort:withCommunity:retry:timeout:nonRepeaters:maxRepetitions:error:)");
    NSLog(@"DEBUG SNMP++ GET to %@ (oid: %@) with version %d on Port: %d using community %@ with retries %d and timeout %d", hostAddress, oids, version, [aPort integerValue], community, retries, timeout);
    NSLog(@"DEBUG SNMP++ What is the community we are sending.... %s", snmpCommunity.get_printable());
    NSLog(@"DEBUG ====================");
#endif
    
    SnmpTarget *target;
    target = &ctarget;

    status = snmp.get_bulk(pdu, *target, l_repeaters, l_repetitions);
    
    NSMutableDictionary *resultsDict = [[NSMutableDictionary alloc] init];
    
    if ( status == SNMP_CLASS_SUCCESS ) {
        for ( int z = 0; z < pdu.get_vb_count(); z++ ) {
            pdu.get_vb(vb, z);
            
            if ( vb.get_syntax() != sNMP_SYNTAX_ENDOFMIBVIEW ) {
#ifdef DEBUG
                NSLog(@"ERROR SNMPController (getBulk:hostAddress:snmpVersion:remotePort:withCommunity:retry:timeout:nonRepeaters:maxRepetitions:error:)");
                NSLog(@"DEBUG SNMP++ -- Oid: %s", vb.get_printable_oid());
                NSLog(@"DEBUG SNMP++ -- Value: %s", vb.get_printable_value());
#endif
                // Add the results to the resultDict
                [resultsDict setObject:[NSString stringWithUTF8String:vb.get_printable_value()] forKey:[NSString stringWithUTF8String:vb.get_printable_oid()]];
            }

        }
    } else {
        NSLog(@"ERROR SNMP++ GET Error: %s (%d)", snmp.error_msg(status), status);
        *error = [self constructError:ERR_NO_SNMP_GET];
        return nil;
    }
    
    return ( resultsDict != nil ) ? [NSDictionary dictionaryWithDictionary:resultsDict] : nil;
}
 *
 */

#pragma mark - Private Methods
#pragma mark -- (Sub)System initialization
- (void)socketStartUp
{
#ifdef DEBUG
    NSLog(@"DEBUG SNMPController (socketStartUp)");
    NSLog(@"DEBUG SNMP++ Socket (sub)system will be initialized");
    NSLog(@"DEBUG ====================");
#endif
    Snmp::socket_startup();
}

- (void)socketCleanUp
{
#ifdef DEBUG
    NSLog(@"DEBUG SNMPController (socketCleanUp)");
    NSLog(@"DEBUG SNMP++ Socket (sub)system will be closed");
    NSLog(@"DEBUG ====================");
#endif
    Snmp::socket_cleanup();
}

#pragma mark - Private methods
#pragma mark -- Error handling
- (NSError *)constructError:(int)errorCode {
    
    NSMutableDictionary *errorDetail = [NSMutableDictionary dictionary];
    
    switch ( errorCode ) {
            
        case ERR_INVALID_DESTINATION:
            
            [errorDetail setValue:NSLocalizedString(@"Invalid host address", @"Error Detail: Invalid address") forKey:NSLocalizedDescriptionKey];
            return [NSError errorWithDomain:@"nl.xjmaas" code:ERR_INVALID_DESTINATION userInfo:errorDetail];
            break;
            
        case ERR_INVALID_OID:
            
            [errorDetail setValue:NSLocalizedString(@"Invalid OID", @"Error Detail: Invalid OID") forKey:NSLocalizedDescriptionKey];
            return [NSError errorWithDomain:@"nl.xjmaas" code:ERR_INVALID_OID userInfo:errorDetail];
            break;
            
        case ERR_INVALID_OID_OBJECT:
            
            [errorDetail setValue:NSLocalizedString(@"Invalid OID object", @"Error Detail: Invalid OID object") forKey:NSLocalizedDescriptionKey];
            return [NSError errorWithDomain:@"nl.xjmaas" code:ERR_INVALID_OID_OBJECT userInfo:errorDetail];
            break;
            
        case ERR_INVALID_TARGET:
            
            [errorDetail setValue:NSLocalizedString(@"Invalid target", @"Error Detail: Invalid target") forKey:NSLocalizedDescriptionKey];
            return [NSError errorWithDomain:@"nl.xjmaas" code:ERR_INVALID_TARGET userInfo:errorDetail];
            break;
            
        case ERR_NO_SNMP_GET:
            
            [errorDetail setValue:NSLocalizedString(@"Could not perform GET", @"Error Detail: No GET") forKey:NSLocalizedDescriptionKey];
            return [NSError errorWithDomain:@"nl.xjmaas" code:ERR_NO_SNMP_GET userInfo:errorDetail];
            break;
            
        case ERR_NO_SNMP_SESSION:
            
            [errorDetail setValue:NSLocalizedString(@"Could not establish session", @"Error Detail: No session") forKey:NSLocalizedDescriptionKey];
            return [NSError errorWithDomain:@"nl.xjmaas" code:ERR_NO_SNMP_SESSION userInfo:errorDetail];
            break;
            
        default:
            return nil;
            break;
    }
    
    return nil;
}

@end
