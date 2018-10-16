//
//  IPCHelper.h
//  NetworKext
//
//  Created by AMRA on 29/08/18.
//  Copyright © 2018 in. All rights reserved.
//

#ifndef IPCHelper_h
#define IPCHelper_h

#include "Constant.h"

#endif /* IPCHelper_h */

/*
 **************************************************************
 **************************************************************
 
 Kernel event implementation
 
 **************************************************************
 **************************************************************
 */


//init
int initBroadcast(void);

//broadcast an event to user mode
int broadcastEvent(int type, socket_t so, const struct sockaddr *to, mbuf_t *data);

/*
 **************************************************************
 **************************************************************
 
 Kernel control implementation
 
 **************************************************************
 **************************************************************
 */

//kern_return_t stop(kmod_info_t *info, void *data);
//errno_t connect(kern_ctl_ref ctlref, sockaddr_ctl *addr, void **unitinfo);
//errno_t disconnect(kern_ctl_ref ctlref, u_int32_t unit, void *unitinfo);
//errno_t send(kern_ctl_ref ctlref, u_int32_t unit, void *unitinfo, mbuf_t data, int flags);
//errno_t setopt(kern_ctl_ref ctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t data_len);
//errno_t getopt(kern_ctl_ref ctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *data_len);

