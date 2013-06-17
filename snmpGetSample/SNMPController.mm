//
//  SNMPController.mm
//  Mobile SNMP++
//
//  Created by Xander Maas on 17-06-13.
//  Copyright (c) 2013 Xander Maas. All rights reserved.
//

#import "SNMPController.h"

// Import the Mobile SNMP++ header file(s)
#import "XISMobile_SNMP_PP.h"

@interface SNMPController ()
@end

@implementation SNMPController {
    XISMobile_SNMP_PP *_snmp;
}

#pragma mark - Class Methods
/** Create a shared controller we can re-use
 
 This methods just returns a sharedController, we can re-use
 */
+ (SNMPController *)sharedController {

    static SNMPController *sharedController = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        sharedController = [[SNMPController alloc] init];
    });
    return sharedController;
}

#pragma mark - Instance Methods

- (id)init {
    if ( self = [super init] ) {
        _snmp = [[XISMobile_SNMP_PP alloc] init];
    }
    return self;
}

- (void)dealloc {
    _snmp = nil;
}

/** Return the NSString with the sysDescr value for the OID .1.3.6.1.2.1.1.1
 */
- (BOOL)sysDescription:(NSString *__autoreleasing *)sysDescrValue
               forHost:(NSString *)host
                 error:(NSError *__autoreleasing *)error {
    
    NSError *queryError = nil;
    
    // Let's assume we are querying the standard UDP port for SNMP
    NSNumber *port = @161;
    
    // We also assume, for this example, SNMP v2c
    int snmpVersion = 2;
    
    // For the readonly community we also use the 'default': public
    NSString *community = @"public";
    
    // Get the result(s) from the SNMP query in a NSDictionary
    NSMutableDictionary *result = [[NSMutableDictionary alloc] init];
    result = [NSMutableDictionary dictionaryWithDictionary:[_snmp getOid:@"1.3.6.1.2.1.1.1.0"
                                                                     address:host
                                                                 snmpVersion:snmpVersion
                                                                  remotePort:port
                                                               withCommunity:community
                                                                       retry:2
                                                                     timeout:300
                                                                       error:&queryError]];
    
    if ( queryError == nil && result.count > 0 ) {
        // Seems we got result, proces it and return it through sysDescrValue
        [result enumerateKeysAndObjectsUsingBlock:^(id key, id obj, BOOL *stop) {
             *sysDescrValue = [obj description];
        }];
        
        // We got a result, which we return through sysDescrValue, also we return YES
        return YES;
        
    } else {
        *error = queryError;
        
        // We got an error, so we set the *error and set the return value to NO
        return NO;
        
    }
}
 

@end
