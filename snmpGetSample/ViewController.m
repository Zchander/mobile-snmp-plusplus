//
//  ViewController.m
//  snmpGetSample
//
//  Created by Xander Maas on 17-06-13.
//  Copyright (c) 2013 Xander Maas. All rights reserved.
//

#import "ViewController.h"

#import "SNMPController.h"

@interface ViewController () <UITextFieldDelegate>
@property (weak, nonatomic) IBOutlet UITextField *hostAddressTextField;
@property (weak, nonatomic) IBOutlet UITextView *queryResultsTextView;

@property (nonatomic, strong) SNMPController *sharedController;

@end

@implementation ViewController

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Clear all the textField/Views
    self.hostAddressTextField.text = @"";
    self.queryResultsTextView.text = @"";
    
    // Make the TextField the firstResponder
    [self.hostAddressTextField becomeFirstResponder];
    
    // Call the SNMPController and create our shared controller
    self.sharedController = [SNMPController sharedController];
}

- (void)didReceiveMemoryWarning
{
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

- (IBAction)startQuery:(id)sender {
    
    // Reset the results TextView from previous run(s)
    self.queryResultsTextView.text = @"";
    NSLog(@"%@", self.hostAddressTextField.text);
    
    NSError *error;
    NSString *sysDescrString;
    BOOL querySuccess = [self.sharedController sysDescription:&sysDescrString
                                                      forHost:self.hostAddressTextField.text
                                                        error:&error];
    NSLog(@"%@", error);
    if ( error != nil || !querySuccess ) {
        UIAlertView *alert = [[UIAlertView alloc] initWithTitle:@"Error Running Query"
                                                        message:[NSString stringWithFormat:@"An error has occured while performing the query: %@ (%d)", error.localizedDescription, error.code]
                                                       delegate:nil
                                              cancelButtonTitle:@"OK"
                                              otherButtonTitles: nil];
        [alert show];
        return;
    }
    self.queryResultsTextView.text = sysDescrString.description;
}

#pragma mark - UITextField Delegate
-(BOOL) textFieldShouldReturn:(UITextField *)textField{
    
    [textField resignFirstResponder];
    return YES;
}

@end
