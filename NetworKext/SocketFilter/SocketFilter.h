//
//  SocketFilter.h
//  NetworKext
//
//  Created by AMRA on 28/08/18.
//  Copyright © 2018 in. All rights reserved.
//

#ifndef SocketFilter_h
#define SocketFilter_h

#endif /* SocketFilter_h */

static struct sflt_filter SfltTCPIPv4;
static struct sflt_filter SfltUDPIPv4;

struct dnsHeader {
    unsigned short id;
    unsigned short flags;
    unsigned short qdcount;
    unsigned short ancount;
    unsigned short nscount;
    unsigned short arcount;
};

kern_return_t socket_filter_stop (void);
kern_return_t socket_filter_start (void);
