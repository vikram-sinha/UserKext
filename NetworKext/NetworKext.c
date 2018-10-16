//
//  NetworKext.c
//  NetworKext
//
//  Created by AMRA on 17/08/18.
//  Copyright © 2018 in. All rights reserved.
//

#include "Constant.h"
#include "SocketFilter.h"
#include "IPFilter.h"
#include "IPCHelper.h"
#include "InterfaceFilter.h"




#define BUNDLE_ID "com.in.NetworKext"
#define HELLO_CONTROL_GET_STRING  1
#define HELLO_CONTROL_SET_STRING  2
#define DEFAULT_STRING            "Hello World Vikram"
#define MAX_STRING_LEN            256

int startBrodcastListener(void);
static errno_t ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl* sac, void** unitinfo);
static errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void* unitinfo);
static int hello_ctl_get(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len);
static int hello_ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void* unitinfo, int opt, void* data, size_t len);
static kern_ctl_ref gCtlRef = NULL;

static struct kern_ctl_reg gCtlReg = {
    BUNDLE_ID,             // use a reverse dns name which includes a name unique to your comany
    0,                      // set to 0 for dynamically assigned control ID - CTL_FLAG_REG_ID_UNIT not set
    0,                      // ctl_unit - ignored when CTL_FLAG_REG_ID_UNIT not set
    CTL_FLAG_PRIVILEGED,    // privileged access required to access this filter
    0,                      // use default send size buffer
    0,                      // use default recv size buffer
    ctl_connect,            // Called when a connection request is accepted
    ctl_disconnect,         // called when a connection becomes disconnected
    NULL,                   // ctl_send_func - handles data sent from the client to kernel control
    hello_ctl_set,          // called when the user process makes the setsockopt call
    hello_ctl_get           // called when the user process makes the getsockopt call
};

static int hello_ctl_get(kern_ctl_ref ctl_ref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len)
{
    printf("hello_ctl_get called");
    int ret = 0;
    switch (opt) {
        case HELLO_CONTROL_GET_STRING:{
            // no implementations
            char g_string_buf[] = DEFAULT_STRING;
            *len = min(MAX_STRING_LEN, *len);
            strncpy(data, g_string_buf, *len);
            printf("hello_ctl_get called for the condition HELLO_CONTROL_GET_STRING: %s", g_string_buf);
        }break;
        default:{
            printf("hello_ctl_get called for the condition default");
            ret = ENOTSUP;
        }
        break; }
    return ret;
}
                         
static int hello_ctl_set(kern_ctl_ref ctl_ref, u_int32_t unit, void* unitinfo, int opt, void* data, size_t len)
{
    printf("hello_ctl_set called");
    int ret = 0;
    switch (opt) {
        case HELLO_CONTROL_SET_STRING:{
            char g_string_buf[] = DEFAULT_STRING;
            len = min(MAX_STRING_LEN, len);
            printf("len: %zu", len);
            size_t *lenA = &len;
            strncpy(data, g_string_buf, *lenA);
            strncat(g_string_buf, data, len);
            printf("hello_ctl_set called for the condition HELLO_CONTROL_SET_STRING: %s", g_string_buf);
            // no implementation
        }break;
        default:{
            printf("hello_ctl_set called for the condition default");
            ret = ENOTSUP;
        }
        break; }
    return ret;
}
                         
static errno_t ctl_connect(kern_ctl_ref ctl_ref, struct sockaddr_ctl* sac, void** unitinfo){
    printf("socket connected");
    printf("process with pid=%d connected\n", proc_selfpid());
    return 0;
}

static errno_t ctl_disconnect(kern_ctl_ref ctl_ref, u_int32_t unit, void* unitinfo){
    printf("socket connected");
    printf("process with pid=%d disconnected\n", proc_selfpid());
    return 0;
}
// Kernel extesion startup function
kern_return_t NetworKext_start (kmod_info_t * ki, void * d)
{
    printf("NetworKext has started.\n");
//    starting the socket filter
//    socket_filter_start();

//    starting the ip filter
//    ip_filter_start();
//    MyIPFilter_start();
//    MyInterfaceFilter_start();
    
//    broadcast events to user space app
//    startBrodcastListener();
    
//    implementing kernel control api
    
    int status;
    status = ctl_register(&gCtlReg, &gCtlRef);
    if(status == KERN_SUCCESS){
        printf("ctl register sucessfully");
    }
    else{
        printf("ctl register unsucessfull");
    }
    return KERN_SUCCESS;
}

// Kernel extesion stop function
kern_return_t NetworKext_stop (kmod_info_t * ki, void * d)
{
    printf("NetworKext has stoped.\n");
//    stoping the socket filter
//    socket_filter_stop();

//    stoping the ip filter
//    ip_filter_cleanup();
//    MyIPFilter_stop();
//    MyInterfaceFilter_stop();

//    implementing kernel control api
    
    if (gCtlRef) {
        errno_t res = ctl_deregister(gCtlRef);
        if (res) { // see http://lists.apple.com/archives/darwin-kernel/2005/Jul/msg00035.html
            printf("com.in.NetworKext: cannot unload kext, the client is still connected (%d)\n", res);
            return KERN_FAILURE; // prevent unloading when client is still connected
        }
        gCtlRef = NULL;
    }
    return KERN_SUCCESS;
}

int startBrodcastListener()
{
    //init broadcast
    if(true != initBroadcast())
    {
        //err msg
        printf("LULU ERROR: initBroadcast() failed\n");
        return false;
    }
    return true;
    
}
