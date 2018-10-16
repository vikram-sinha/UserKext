//
//  AppDelegate.m
//  NetworkApp
//
//  Created by AMRA on 29/08/18.
//  Copyright © 2018 innovanathinklabs. All rights reserved.
//

#import "AppDelegate.h"
#import "MainVc.h"

@interface AppDelegate ()

@property (weak) IBOutlet NSWindow *window;
@property (nonatomic, strong) MainVc *mainVc;
@end

@implementation AppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
    // Insert code here to initialize your application
    [self setUpMainVc];
}

-(void)setUpMainVc{
    self.mainVc = [[MainVc alloc] init];
    self.window.contentView = self.mainVc.view;
}

- (void)applicationWillTerminate:(NSNotification *)aNotification {
    // Insert code here to tear down your application
}


@end
