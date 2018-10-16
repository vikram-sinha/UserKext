//
//  MainVc.m
//  NetworkApp
//
//  Created by AMRA on 29/08/18.
//  Copyright © 2018 in. All rights reserved.
//

#import "MainVc.h"
#import "Constant.h"

#define BUNDLE_ID "com.in.NetworKext"
#define HELLO_CONTROL_GET_STRING  1
#define HELLO_CONTROL_SET_STRING  2
#define DEFAULT_STRING            "Hello World"
#define MAX_STRING_LEN            256


struct connectionEvent
{
    //process pid
    pid_t pid;
    
    //local socket address
    struct sockaddr localAddress;
    
    //remote socket address
    struct sockaddr remoteAddress;
    
    //socket type
    int socketType;
    
    //socket type
    char dtString[0];
};


@interface MainVc ()

@end

@implementation MainVc

- (void)viewDidLoad {
    [super viewDidLoad];

    // using kernel event api
//        [self creatKernelEventSocket];

    //  using kernel control api
    [self creatKernelControlSocket];
    // Do view setup here.
}

-(void)creatKernelControlSocket{
    
    struct ctl_info ctl_info;
    struct sockaddr_ctl sc;
    char str[MAX_STRING_LEN];
    int sock = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (sock < 0)
        NSLog(@"exit with code -1");
    
    bzero(&ctl_info, sizeof(struct ctl_info));
    strcpy(ctl_info.ctl_name, BUNDLE_ID);
    if (ioctl(sock, CTLIOCGINFO, &ctl_info) == -1)
        NSLog(@"exit with error code -1");
    bzero(&sc, sizeof(struct sockaddr_ctl));
    sc.sc_len = sizeof(struct sockaddr_ctl);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = SYSPROTO_CONTROL;
    sc.sc_id = ctl_info.ctl_id;
    sc.sc_unit = 0;
    if (connect(sock, (struct sockaddr *)&sc, sizeof(struct sockaddr_ctl)))
        NSLog(@"exit with error code -1");
    /* Get an existing string from the kernel */
    unsigned int size = MAX_STRING_LEN;
    if (getsockopt(sock, SYSPROTO_CONTROL, HELLO_CONTROL_GET_STRING, &str, &size) == -1)
        NSLog(@"exit with error code -1");
    printf("kernel string is: %s\n", str);
    /* Set a new string */
    strcpy(str, "Hello Kernel, here's your new string, enjoy!");
    size_t sizeA = strlen(str);
    NSLog(@"size: %zu", sizeA);
    if (setsockopt(sock, SYSPROTO_CONTROL, HELLO_CONTROL_SET_STRING,
                   str, (socklen_t)strlen(str)) == -1)
        NSLog(@"exit with error code -1");
    close(sock);
}

-(void)creatKernelEventSocket{
    //system socket
    int systemSocket = -1;
    //create system socket to receive kernel event data
    systemSocket = socket(PF_SYSTEM, SOCK_RAW, SYSPROTO_EVENT);
    
    
//    struct kev_request req;
//    req.vendor_code=KEV_VENDOR_APPLE;
//    req.kev_class=KEV_APPLESHARE_CLASS;
//    req.kev_subclass=KEV_ANY_SUBCLASS;
//
//    if (ioctl(systemSocket, SIOCSKEVFILT, &req)) {
//        NSLog(@"%lu", SIOCSKEVFILT);
//        exit(-1);
//    }
//
//    struct kev_vendor_code vc;
//    strcpy(vc.vendor_string, "com.objective-see");
//    if (ioctl(systemSocket, SIOCGKEVVENDOR, &vc)) exit(-1);
//    NSLog(@"Vendor code returned was %d\n", vc.vendor_code);
//
//    uint32_t id;
//    if (ioctl(systemSocket, SIOCGKEVID, &id)) exit(-1);
//    NSLog(@"systemSocket returned was %d\n", id);

    //struct for vendor code
    // ->set via call to ioctl/SIOCGKEVVENDOR
    struct kev_vendor_code vendorCode = {0};
    
    //set vendor name string
    strncpy(vendorCode.vendor_string, "com.objective-see", KEV_VENDOR_CODE_MAX_STR_LEN);

    //get vendor name -> vendor code mapping
    // ->vendor id, saved in 'vendorCode' variable
    ioctl(systemSocket, SIOCGKEVVENDOR, &vendorCode);


    //struct for kernel request
    // ->set filtering options
    struct kev_request kevRequest = {0};

    //    init filtering options
    //    only interested in objective-see's events
    kevRequest.vendor_code = vendorCode.vendor_code;
    //    vendorCode.vendor_code = vendorCode.vendor_code;

    
    //...any class
    kevRequest.kev_class = KEV_ANY_CLASS;

    //...any subclass
    kevRequest.kev_subclass = KEV_ANY_SUBCLASS;

    //tell kernel what we want to filter on
    ioctl(systemSocket, SIOCSKEVFILT, &kevRequest);

    //foreverz
    // ->listen/parse process creation events from kext
    while(YES)
    {
        //bytes received from system socket
        ssize_t bytesReceived = -1;

        //message from kext
        // ->size is cumulation of header, struct, and max length of a proc path
        char kextMsg[KEV_MSG_HEADER_SIZE + sizeof(struct connectionEvent)] = {0};

        //ask the kext for process began events
        // ->will block until event is broadcast
        bytesReceived = recv(systemSocket, kextMsg, sizeof(kextMsg), 0);

        //struct for broadcast data from the kext
        struct kern_event_msg *kernEventMsg = {0};

        //type cast
        // ->to access kev_event_msg header
        kernEventMsg = (struct kern_event_msg*)kextMsg;

        //sanity check
        // ->make sure data recv'd looks ok, sizewise
//        if( (bytesReceived < KEV_MSG_HEADER_SIZE) ||
//           (bytesReceived != kernEventMsg->total_size))
//        {
//            //ignore
//            continue;
//        }

        //only care about 'process began' events
        if(PROCESS_BEGAN_EVENT != kernEventMsg->event_code)
        {
            //skip
            continue;
        }

        //custom struct
        // ->process data from kext
        struct connectionEvent* connection = NULL;

        //type cast custom data
        // ->begins right after header
        connection = (struct connectionEvent*)&kernEventMsg->event_data[0];
        
        //dbg msg
        NSLog(@"%@", [NSString stringWithFormat:@"connection event: pid: %d \n", connection->pid]);
//        NSLog(@"%@", [NSString stringWithFormat:@"connection event: local socket: %@ \n", convertSocketAddr(&connection->localAddress)]);
//        NSLog(@"%@", [NSString stringWithFormat:@"connection event: remote socket: %@ \n", convertSocketAddr(&connection->remoteAddress)]);
        NSLog(@"%@", [NSString stringWithFormat:@"connection event: socket type: %d \n", connection->socketType]);
        
        NSLog(@"%@", [NSString stringWithFormat:@"connection event: data string: %s \n", connection->dtString]);

        self.lblKextEvent.stringValue = [NSString stringWithFormat:@"connection event: pid: %d, socket type: %d ", connection->pid, connection->socketType];
    }
}

@end
