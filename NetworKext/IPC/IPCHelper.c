//
//  IPCHelper.c
//  NetworKext
//
//  Created by AMRA on 29/08/18.
//  Copyright © 2018 in. All rights reserved.
//

#include "IPCHelper.h"

/*
    **************************************************************
    **************************************************************
 
    Kernel event implementation
 
    **************************************************************
    **************************************************************
*/

//kext's/objective-see's vendor id
u_int32_t objSeeVendorID = 0;

//init broadcast
// ->basically just set vendor code
int initBroadcast()
{
    //result var
    bool result = false;
    
    //status var
    errno_t status = KERN_FAILURE;
    
    //grab vendor id
    status = kev_vendor_code_find(OBJECTIVE_SEE_VENDOR, &objSeeVendorID);
    if(KERN_SUCCESS != status)
    {
        //err msg
        printf("kev_vendor_code_find() failed to get vendor code (%#x)\n", status);
        
        //bail
        goto bail;
    }
    
    //happy
    result = true;
    
bail:
    
    return result;
}

//broadcast an event to user mode
int broadcastEvent(int type, socket_t so, const struct sockaddr *to, mbuf_t *data)
{
    printf("broadcastEvent");
    //return var
    bool result = false;
    
    //kernel event message
    struct kev_msg kEventMsg = {0};
    
    //process id
    int processID = 0;
    
    //local socket address
    struct sockaddr_in6 localAddress = {0};
    
    //remote socket address
    struct sockaddr_in6 remoteAddress = {0};
    
    //socket type
    int socketType = 0;
    
    //length of socket type
    int socketTypeLength = 0;
    
    //zero out local socket address
    bzero(&localAddress, sizeof(localAddress));
    
    //zero out remote socket address
    bzero(&remoteAddress, sizeof(remoteAddress));
    
    //zero out kernel message
    bzero(&kEventMsg, sizeof(kEventMsg));
    
    //get pid
    processID = proc_selfpid();
    
    //get local address of a socket
    if(KERN_SUCCESS != sock_getsockname(so, (struct sockaddr *)&localAddress, sizeof(localAddress)))
    {
        //err msg
        printf("sock_getsockname() failed\n");
        
        //bail
        goto bail;
    }
    
    //UDP sockets destination socket might be null
    // so grab via 'getpeername' into remote socket
    if(NULL == to)
    {
        //copy into 'remote addr' for user mode
        if(0 != sock_getpeername(so, (struct sockaddr*)&remoteAddress, sizeof(remoteAddress)))
        {
            //err msg
            printf("sock_getpeername() failed\n");
            
            //bail
            goto bail;
        }
    }
    //copy remote socket for user mode
    else
    {
        //add remote (destination) socket addr
        memcpy(&remoteAddress, to, sizeof(remoteAddress));
    }
    
    //init length
    socketTypeLength = sizeof(socketType);
    
    //get socket type
    sock_getsockopt(so, SOL_SOCKET, SO_TYPE, &socketType, &socketTypeLength);
    
    //set vendor code
    kEventMsg.vendor_code = objSeeVendorID;
    
    //set class
    kEventMsg.kev_class = KEV_ANY_CLASS;
    
    //set subclass
    kEventMsg.kev_subclass = KEV_ANY_SUBCLASS;
    
    //set event code
    // ->connect, data out, etc,
    kEventMsg.event_code = type;
    
    //add pid
    kEventMsg.dv[0].data_length = sizeof(int);
    kEventMsg.dv[0].data_ptr = &processID;
    
    //add local socket
    kEventMsg.dv[1].data_length = sizeof(localAddress);
    kEventMsg.dv[1].data_ptr = &localAddress;
    
    //add remote socket
    kEventMsg.dv[2].data_length = sizeof(remoteAddress);
    kEventMsg.dv[2].data_ptr = &remoteAddress;
    
    //add socket type
    kEventMsg.dv[3].data_length = sizeof(int);
    kEventMsg.dv[3].data_ptr = &socketType;
    
    //chunk pointer
    char* chunkPointer = NULL;
    char queries[MAXPATHLEN+1] = {0};
    
    //zero out path
    bzero(&queries, sizeof(queries));
    //non-path size
    int nonPathSize = 0;
    
    unsigned char *dataString = mbuf_data(*data);
    for (size_t i = 0; i < mbuf_len(*data); i++)
    {
        printf("hella %c", dataString[i]);
//        size_t sLen =  sizeof(dataString[i]);
        char charStr;
        charStr = dataString[i];
        char *asd = &charStr;
        strncat(queries, asd, MAXPATHLEN);
    }
    printf("hella dnsQuery: %s", queries);
    
    chunkPointer = queries;
    
    //add current offset of path
    kEventMsg.dv[4].data_ptr = chunkPointer;
    
    //set size
    // ->either string length (with NULL)
    //   or max size - pid, etc and extra for NULL!
    kEventMsg.dv[4].data_length = (u_int)strlen(chunkPointer)+1;
    
    //    broadcast msg to user-mode
    if(KERN_SUCCESS != kev_msg_post(&kEventMsg))
    {
        //err msg
        printf("kev_msg_post() failed\n");
        
        //bail
        goto bail;
    }
    
    //all happy
    result = true;
    
bail:
    
    return result;
}

/*
 **************************************************************
 **************************************************************
 
 Kernel control implementation
 
 **************************************************************
 **************************************************************
 */

//
//char name[] = "org.example.mymodule";
//struct kern_ctl_ref _ctlref; /* an opaque reference to the control */
//
//kern_return_t start(kmod_info_t *info, void *data)
//{
//    errno_t err ;
//    /* a kern_ctl_reg is an application form for a kernel control */
//    struct kern_ctl_reg ctlreg ;
//    kern_ctl_ref kctlref;
//    bzero(&ctlreg, sizeof(ctlreg));
//    
//    ctlreg.ctl_id = 0 ; /* ask for a dynamically allocated id */
//    ctlreg.ctl_unit = 0 ; /* ditto for unit numbers */
//    strncpy(ctlreg.ctl_name, name, sizeof(ctlreg.ctl_name)) ;
//    ctlreg.ctl_flags = CTL_FLAG_PRIVILEGED & CTL_FLAG_REG_ID_UNIT; /* leave the flags as 0 */
//    ctlreg.ctl_send = send();
//    /* those callbacks in full ... */
////    ctlreg.ctl_connect_func = connect ;
////    ctlreg.ctl_disconnect_func = disconnect ;
////
////    ctlreg.ctl_getopt_func = getopt ;
////    ctlreg.ctl_setopt_func = setopt ;
////    err = ctl_register(&ctlreg, &_ctlref) ;
//    if (err) return KERN_FAILURE ;
//    return KERN_SUCCESS ;
//}
//
//kern_return_t stop(kmod_info_t *info, void *data)
//{
//    /* do we need to switch the control off here? */
//    return KERN_SUCCESS ;
//}
//
//errno_t connect(kern_ctl_ref ctlref, sockaddr_ctl *addr, void **unitinfo)
//{
//    /* nothing much of interest in addr except sc_unit */
//    /* stash stuff into unitinfo here */
//    return 0 ;
//}
//
//errno_t disconnect(kern_ctl_ref ctlref, u_int32_t unit, void *unitinfo)
//{
//    return 0 ;
//}
//
//errno_t send(kern_ctl_ref ctlref, u_int32_t unit, void *unitinfo, mbuf_t data, int flags)
//{
//    /*
//     There's a strong chance that you'll want to send a reply to the
//     client round here; for that, you want the ctl_enqueuedata routine in
//     kern_control.h, which looks like:
//     
//     errno_t ctl_enqueuedata(kern_ctl_ref ctlref, u_int32_t unit, void *data, size_t data_len, u_int32_t flags) ;
//     
//     Which does exactly what it says on the tin - puts some data on the
//     queue of client-bound messages on the socket. The only flag you
//     might want is CTL_DATA_NOWAKEUP, which means 'put the data on the
//     queue, but don't wake the client up so it can read it', a low act if
//     ever there was one.
//     */
//    return 0 ;
//}
//
//errno_t setopt(kern_ctl_ref ctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t data_len)
//{
//    return 0 ;
//}
//
//errno_t getopt(kern_ctl_ref ctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *data_len)
//{
//    /*
//     Note that data_len is a pointer; on the way in, the location it
//     points to contains the length of the buffer pointed to by buf, and
//     on the way out, it should contain the length of the data placed in
//     it.
//     
//     Except that sometimes, data will be NULL, ie you don't have a
//     buffer; that means the kernel is asking you how much space you want,
//     so work that out, and store it in the location pointed to by
//     data_len.
//     */
//    return 0 ;
//}
//
