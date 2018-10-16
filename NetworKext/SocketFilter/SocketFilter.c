//
//  SocketFilter.c
//  NetworKext
//
//  Created by AMRA on 28/08/18.
//  Copyright © 2018 in. All rights reserved.
//

#include "Constant.h"
#include "SocketFilter.h"
#include "IPCHelper.h"


#define DATA_SIZE 1500
#define BUFFER_SIZE 256
#define ULTIMATE_ANSWER 0x00000042


void FltUnregisteredIPv4(sflt_handle handle);

errno_t FltAttachI(void **cookie, socket_t so);
void FltDetachI(void *cookie, socket_t so);

errno_t FltConnectIn(void *cookie, socket_t so, const struct sockaddr *from);
errno_t FltConnectOut(void *cookie, socket_t so, const struct sockaddr *to);

static errno_t FltDataIn(void *cookie, socket_t so, const struct sockaddr *from, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags);
static errno_t FltDataOut(void *cookie, socket_t so, const struct sockaddr *to, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags);

static struct sflt_filter SfltTCPIPv4 = {
    0xBABABABA, /* sflt_handle - use a registered creator type - <http://developer.apple.com/datatype/> */
    SFLT_GLOBAL,            /* sf_flags */
    "NKEBundleIdNKE",            /* sf_name - cannot be nil else param err results */
    FltUnregisteredIPv4,    /* sf_unregistered_func */
    FltAttachI,          /* sf_attach_func - cannot be nil else param err results */
    FltDetachI,            /* sf_detach_func - cannot be nil else param err results */
    NULL,              /* sf_notify_func */
    NULL,                    /* sf_getpeername_func */
    NULL,                    /* sf_getsockname_func */
    FltDataIn, //NULL,              /* sf_data_in_func FltDataIn, */
    FltDataOut,//NULL,             /* sf_data_out_func FltDataOut, */
    FltConnectIn,           /* sf_connect_in_func */
    FltConnectOut,          /* sf_connect_out_func */
    NULL,                /* sf_bind_func */
    NULL,           /* sf_setoption_func */
    NULL,           /* sf_getoption_func */
    NULL,              /* sf_listen_func */
    NULL                    /* sf_ioctl_func */
};

static struct sflt_filter SfltTCPIPv6 = {
    0xFEBCD789, /* sflt_handle - use a registered creator type - <http://developer.apple.com/datatype/> */
    SFLT_GLOBAL,            /* sf_flags */
    "NKEBundleIdNKE",            /* sf_name - cannot be nil else param err results */
    FltUnregisteredIPv4,    /* sf_unregistered_func */
    FltAttachI,          /* sf_attach_func - cannot be nil else param err results */
    FltDetachI,            /* sf_detach_func - cannot be nil else param err results */
    NULL,              /* sf_notify_func */
    NULL,                    /* sf_getpeername_func */
    NULL,                    /* sf_getsockname_func */
    FltDataIn, //NULL,              /* sf_data_in_func FltDataIn, */
    FltDataOut,//NULL,             /* sf_data_out_func FltDataOut, */
    FltConnectIn,           /* sf_connect_in_func */
    FltConnectOut,          /* sf_connect_out_func */
    NULL,                /* sf_bind_func */
    NULL,           /* sf_setoption_func */
    NULL,           /* sf_getoption_func */
    NULL,              /* sf_listen_func */
    NULL                    /* sf_ioctl_func */
};

static struct sflt_filter SfltUDPIPv4 = {
    0xFEBCD987, /* 0xFEBCD987, sflt_handle - use a registered creator type - <http://developer.apple.com/datatype/> */
    SFLT_GLOBAL,            /* sf_flags */
    "NKEBundleIdNKE",            /* sf_name - cannot be nil else param err results */
    FltUnregisteredIPv4,    /* sf_unregistered_func */
    FltAttachI,          /* sf_attach_func - cannot be nil else param err results */
    FltDetachI,            /* sf_detach_func - cannot be nil else param err results */
    NULL,              /* sf_notify_func */
    NULL,                    /* sf_getpeername_func */
    NULL,                    /* sf_getsockname_func */
    FltDataIn,              /* sf_data_in_func */
    FltDataOut,                 /* sf_data_out_func */
    NULL,           /* sf_connect_in_func FltConnectIn, */
    NULL,          /* sf_connect_out_func FltConnectOut, */
    NULL,                /* sf_bind_func */
    NULL,           /* sf_setoption_func */
    NULL,           /* sf_getoption_func */
    NULL,              /* sf_listen_func */
    NULL                    /* sf_ioctl_func */
};

// Kernel extesion startup function

kern_return_t socket_filter_start ()
{
    errno_t   status = KERN_SUCCESS;
    printf("socket_filter_start called.\n");
    /* Register the NKE */
    // register the filter with AF_INET domain, SOCK_STREAM type, TCP protocol and set the global flag
    status = sflt_register( &SfltTCPIPv4, PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if( KERN_SUCCESS == status ){
        printf("NetworKext registered for TCP IP4, flag: %d.\n", status);
    }
    else{
        printf("NetworKext failed to registered for TCP IP4, flag: %d.\n", status);
    }
    
    status = sflt_register( &SfltTCPIPv6, PF_INET6, SOCK_STREAM, IPPROTO_TCP);
    if( KERN_SUCCESS == status ){
        printf("NetworKext registered for TCP IP6, flag: %d.\n", status);
    }
    else{
        printf("NetworKext failed to registered for TCP IP6, flag: %d.\n", status);
    }
    
    status = sflt_register(&SfltUDPIPv4, PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if( KERN_SUCCESS == status ){
        printf("NetworKext registered for UDP IP4, flag: %d.\n", status);
    }
    else{
        printf("NetworKext failed to registered for UDP IP4, flag: %d.\n", status);
    }
    
    return KERN_SUCCESS;
}

// Kernel extesion stop function

kern_return_t socket_filter_stop ()
{
    errno_t   status = KERN_SUCCESS;
    status = sflt_unregister(0xBABABABA);
    printf("NetworKext FLT_TCPIPV4_HANDLE stopped, flag: %d\n", status);
    status = sflt_unregister(0xFEBCD789);
    printf("NetworKext FLT_TCPIPV6_HANDLE stopped, flag: %d\n", status);
    status = sflt_unregister(0xFEBCD987);
    printf("NetworKext FLT_UDPIPV4_HANDLE stopped, flag: %d\n", status);
    return KERN_SUCCESS;
}

void FltUnregisteredIPv4(sflt_handle handle)
{
//    printf("FltUnregisteredIPv4 called.\n");
}

errno_t FltAttachI(void **cookie, socket_t so)
{
//    printf("FltAttachI called.\n");
    pid_t            tli_pid;
    char             name[PATH_MAX];
    
    tli_pid = proc_selfpid();
    proc_selfname(name, PATH_MAX);
//    printf("pid is: %d attaching to process: %s\n", tli_pid, name);
    return KERN_SUCCESS;
}

void FltDetachI(void *cookie, socket_t so)
{
//    printf("FltDetachI called.\n");
}

errno_t FltConnectIn(void *cookie, socket_t so, const struct sockaddr *from)
{
//    printf("FltConnectIn called.\n");
    return KERN_SUCCESS;
}

errno_t FltConnectOut(void *cookie, socket_t so, const struct sockaddr *to)
{
//    printf("FltConnectOut called.\n");
    return KERN_SUCCESS;
}

static errno_t FltDataIn(void *cookie, socket_t so, const struct sockaddr *from, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags)
{
//    printf("FltDataIn called.\n");
    return KERN_SUCCESS;
}

static errno_t FltDataOut(void *cookie, socket_t so, const struct sockaddr *to, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags)
{
    printf("FltDataOut called.\n");
    unsigned char* dataStr[mbuf_len(*data)];
    char buf[mbuf_len(*data)];
    mbuf_copydata(*data, 0, mbuf_len(*data), dataStr);
    printf("look at dataStr: %s", dataStr[0]);
    printf("look at the data: %s", buf);
    
//    size_t data_lenght;
//    data_lenght = mbuf_pkthdr_len(*data);
//    
//    char data_receive[data_lenght];
//    memcpy(data_receive, ( char * ) mbuf_data(*data), data_lenght );
//    printf("data recied %lu\n",data_lenght);
//    
//    for(int i=0;i<data_lenght;++i)
//    {
//        printf("%X ",data_receive[i]);
//    }
//    
    return KERN_SUCCESS;
}

//static errno_t FltDataOut(void *cookie, socket_t so, const struct sockaddr *to, mbuf_t *data, mbuf_t *control, sflt_data_flag_t flags)
//{
//    printf("FltDataOut called.\n");
//
//    // next memory buffer
//    mbuf_t next_mbuf = mbuf_next(*data);
//    if(next_mbuf == NULL){
////        printf("next buff is null");
//    }else{
////        printf("next buff is available");
//    }
//
//    // next packet memory buffer
//    mbuf_t next_pkt_mbuf = mbuf_nextpkt(*data);
//    if(next_pkt_mbuf == NULL){
////        printf("next packet buff is null");
//    }else{
////        printf("next packet buff is available");
//    }
//
//    int no_of_pkt = 0;
//    int no_of_chained_pkt = 0;
//    for (mbuf_t mb_nxt_pkt = *data; mb_nxt_pkt; mb_nxt_pkt = mbuf_nextpkt(mb_nxt_pkt)){
//        no_of_pkt = no_of_pkt + 1;
//        for (mbuf_t mb = mb_nxt_pkt; mb; mb = mbuf_next(mb)){
//            // packet length
//            no_of_chained_pkt = no_of_chained_pkt + 1;
//            size_t buf_data_size = mbuf_len(mb);
//            printf("the amount of data in mbuf: %zu", buf_data_size);
//
//            mbuf_type_t type_of_mbuf = mbuf_type(mb);
//            printf("mbuf type is: %d", type_of_mbuf);
//
//            mbuf_flags_t flag_of_mbuf = mbuf_flags(mb);
//            printf("(MH_PKTHDR, MH_EXT) mbuf flag is: %d", flag_of_mbuf);
//
//            // packet header length
//            size_t data_size = mbuf_pkthdr_len(mb);
//            printf("The total length of a packet split in multiple mbufs is stored in the m_pkthdr.len field is: %zu", data_size);
//
//            /*
//                The socket layer (and hence the socket filter) is situated between user space and the network protocol stack in the kernel. Because of this, socket filters cannot peek at the IP or TCP header of an outgoing network packet because that happens later in the processing chain.
//                However, it is still possible to filter IP-based traffic using a socket filter, as metadata, such as the IP address the packet is destined for, is known. The same is true for incoming traffic. The protocol stack will strip header information before it enters the socket layer. In effect, we are seeing the reassembled data that will eventually be read by a user space application. Because of this, a socket filter is not suitable for use when information from protocol headers is required, and one should use the lower level IP or interface filters instead.
//            */
//
//            printf("mb_data pointer: %p.\n", mb);
//
//            unsigned char* mb_pkt_hdr = mbuf_pkthdr_header(mb);
//            printf("mb_pkt_hdr: %s", mb_pkt_hdr);
//
//            unsigned char* data = mbuf_data(mb);
//            if(data != NULL){
//                unsigned char* dataString = mbuf_data(mb);
//                int remainData = 256;
//                for (int i = 0; i < remainData; i++)
//                {
//                    printf("hello 1 |%.2X|", data[i]);
//                }
//            }
//
////            errno_t err;
////            int value;
////            mbuf_t dataMb = NULL;
////
////            // Copy the data from the mbuf chain into local storage.
////            err = mbuf_copydata(dataMb, 0, sizeof(value), &value); // Copy 4 bytes at start
////            printf("value from the copy_data: %d", value);
//
//            printf("\n EPHandleWrite called---------------------- \n");
//
//            size_t data_lenght;
//            data_lenght = mbuf_pkthdr_len(mb);
//
//            char data_receive[data_lenght];
//            memcpy( data_receive, ( char * ) mbuf_data(mb) , data_lenght );
//
//            printf("data recied %lu\n",data_lenght);
//
//            for(int i=0;i<data_lenght;++i)
//            {
//                printf("%X ",data_receive[i]);
//            }
//
//
//        }
//    }
//    printf("no_of_pkt count: %d and no_of_chained_pkt count: %d", no_of_pkt, no_of_chained_pkt);
//
//    /*
//     iterate to the next packet in the chain{
//        take first packet, iterate all over the chain using _next kpi till end of the chain.{}
//     }
//    */
//
////    char queries[2048];
////    unsigned char *dataString = mbuf_data(*data);
////    for (size_t i = 0; i < mbuf_len(*data); i++)
////    {
////        printf("%c", dataString[i]);
////        size_t sLen =  sizeof(dataString[i]);
////        char charStr;
////        charStr = dataString[i];
////        char *asd = &charStr;
////        strncat(queries, asd, sLen);
////    }
////    printf("dnsMsg: %s", queries);
//
////    printf("\n-------------\n");
//
////    for (mbuf_t mb_pkt = mb_pkt_hdr; mb_pkt; mb_pkt = mbuf_nextpkt(mb_pkt)){
////        unsigned char* head_pkt = mbuf_pkthdr_header(mb_pkt);
////        printf("next pkthdr: %s", head_pkt);
////        for (mbuf_t mb = mb_pkt; mb; mb = mbuf_next(mb))
////        {
////            unsigned char* dataString = mbuf_data(mb);
////            size_t len = mbuf_len(mb);
////            for (size_t i = 0; i < len; i++)
////            {
////                printf("%c", dataString[i]);
////            }
////        }
////    }
//
//
////    while (offset < data_size) {
////        printf("loop running");
////        size_t buf_data_size = mbuf_len(*data);
////        printf("the amount of data in seprate mbuf: %zu", buf_data_size);
////        offset += data_size;
////        ifnet_t header = mbuf_pkthdr_header(*data);
//
////        mbuf_t nextMbuf = mbuf_next(*data);
////        size_t combined_data_size = mbuf_len(nextMbuf);
////        printf("the amount of data in seprate mbuf: %zu", combined_data_size);
////    }
//
//    /*unsigned char addstr[256];
//    struct sockaddr_in  addr;
//
//    sock_getsockname(so, (struct sockaddr*)&addr, sizeof(addr));
//    inet_ntop(AF_INET, &addr.sin_addr, (char*)addstr, sizeof(addstr));
//    printf("FltDataOut string and port-> %s:%d\n", addstr, ntohs(addr.sin_port));
//    printf("socket data out %zu\n", mbuf_len(*data));
//
//    //remote socket address
//    struct sockaddr_in6 remoteAddress = {0};
//
//    //zero out remote socket address
//    bzero(&remoteAddress, sizeof(remoteAddress));
//
//    //UDP sockets destination socket might be null
//    // so grab via 'getpeername' into remote socket
//    if(NULL == to){
//        //copy into 'remote addr' for user mode
//        if(0 != sock_getpeername(so, (struct sockaddr*)&remoteAddress, sizeof(remoteAddress))){
//            //err msg
//            printf("FltDataOut sock_getpeername on remote address failed");
//        }else{
//            printf("FltDataOut remote address port-> %d\n", ntohs(remoteAddress.sin6_port));
//        }
//    }
//
//    //mem buffer
//    mbuf_t memBuffer = NULL;
//
//    //dns header
//    struct dnsHeader* dnsHeader = NULL;
//
//    //init memory buffer
//    memBuffer = *data;
//    if(NULL == memBuffer){
//        // nothing in header
//    }
//
//    //get memory buffer
//    while(MBUF_TYPE_DATA != mbuf_type(memBuffer)){
//        //get next
//        memBuffer = mbuf_next(memBuffer);
//        if(NULL == memBuffer){
//            // nothing in header
//        }
//    }
//
//    //sanity check length
//    if(mbuf_len(memBuffer) <= sizeof(struct dnsHeader)){
//        // nothing in header
//    }
//
//    //get data
//    // should be a DNS header
//    dnsHeader = (struct dnsHeader*)mbuf_data(memBuffer);
//
//    //ignore everything that isn't a DNS response
//    // top bit flag will be 0x1, for "a name service response"
//    if(0 == ((ntohs(dnsHeader->flags)) & (1<<(15)))){
//        // nothing in header
//    }
//
//    //ignore any errors
//    // bottom (4) bits will be 0x0 for "successful response"
//    if(0 != ((ntohs(dnsHeader->flags)) & (1<<(0)))){
//        // nothing in header
//    }
//
//    //ignore any packets that don't have answers
//    if(0 == ntohs(dnsHeader->ancount)){
//        // nothing in header
//    }
//
//    uint32_t    querySize = 0;
//    uint8_t     dnsQuery[DATA_SIZE];
//    uint8_t     dnsBuff[DATA_SIZE];
//
//    struct dnsHeader* dnsHead = NULL;
//
//    mbuf_copydata(memBuffer, 0, querySize, (void*)dnsQuery);
//    memcpy(dnsBuff, dnsQuery, querySize);
//    dnsHead = (struct dnsHeader*)dnsBuff;
//
//
//    char queries[2048];
//    unsigned char *dataString = mbuf_data(*data);
//    for (size_t i = 0; i < mbuf_len(*data); i++)
//    {
//        printf("%c", dataString[i]);
//        size_t sLen =  sizeof(dataString[i]);
//        char charStr;
//        charStr = dataString[i];
//        char *asd = &charStr;
//        strncat(queries, asd, sLen);
//    }
//    printf("dnsMsg: %s", queries);
//     */
//
////    broadcast to user mode
////    broadcastEvent(EVENT_DATA_OUT, so, to, data);
//
//    return KERN_SUCCESS;
//    //    return 1;
////        return EJUSTRETURN;
//}

