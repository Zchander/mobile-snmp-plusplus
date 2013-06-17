//
//  SNMPController.h
//  Mobile SNMP++
//
//  Created by Xander Maas on 17-06-13.
//  Copyright (c) 2013 Xander Maas. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface SNMPController : NSObject

+ (SNMPController *)sharedController;

- (BOOL)sysDescription:(NSString *__autoreleasing *)sysDescrValue
               forHost:(NSString *)host
                 error:(NSError *__autoreleasing *)error;

@end
