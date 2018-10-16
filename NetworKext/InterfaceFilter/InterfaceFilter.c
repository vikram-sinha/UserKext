//
//  InterfaceFilter.c
//  NetworKext
//
//  Created by AMRA on 20/09/18.
//  Copyright © 2018 innovanathinklabs. All rights reserved.
//

#include "InterfaceFilter.h"
#include "Constant.h"

static boolean_t g_filter_registered = TRUE;
static boolean_t g_filter_detached = FALSE;
static interface_filter_t g_filter_ref;


static errno_t myif_filter_input(void* cookie, ifnet_t interface, protocol_family_t protocol,
                                mbuf_t* data, char** frame_ptr)
{
    printf("incoming packet: %lu bytes\n", mbuf_pkthdr_len(*data));
    return 0;
}

/*static errno_t myif_filter_output(void* cookie, ifnet_t interface, protocol_family_t protocol,
                                  mbuf_t* data)
{
    printf("outgoing packet: %lu bytes\n", mbuf_pkthdr_len(*data));
    return 0;
}*/

static errno_t myif_filter_output(void* cookie, ifnet_t interface, protocol_family_t protocol,
                                  mbuf_t* data)
{
    char                  src[64], dst[64];
    unsigned char*        pktbuf = mbuf_data(*data);
    struct ether_header*  eth = (struct ether_header *)pktbuf;
    if (ifnet_hdrlen(interface) != ETHER_HDR_LEN)
        return 0;
    if (ntohs(eth->ether_type) == ETHERTYPE_IP)
    {
        struct ip* iphdr = (struct ip*)(pktbuf + ETHER_HDR_LEN);
        inet_ntop(AF_INET, &iphdr->ip_src, src, sizeof(src));
        inet_ntop(AF_INET, &iphdr->ip_dst, dst, sizeof(dst));
        printf("outgoing packet: %lu bytes ip_src: %s ip_dst: %s\n",
               mbuf_pkthdr_len(*data), src, dst);
    } else
        printf("outgoing packet: %lu bytes\n", mbuf_pkthdr_len(*data));
    
    unsigned char* dataString = NULL;
    for (mbuf_t mb = *data; mb; mb = mbuf_next(mb))
    {
        dataString = mbuf_data(mb);
        size_t len = mbuf_len(mb);
        for (size_t i = 0; i < len; i++)
        {
            printf("%c", dataString[i]);
        }
    }
    
    return 0;
}


static void myif_filter_detached(void* cookie, ifnet_t interface)
{
    g_filter_detached = TRUE;
}

static struct iff_filter g_my_iff_filter =
{
    NULL,
    "com.innovanathinklabs.NetworKext",
    0,
    myif_filter_input,
    myif_filter_output,
    NULL,
    NULL,
    myif_filter_detached,
};

kern_return_t MyInterfaceFilter_start ()
{
    ifnet_t interface;
    if (ifnet_find_by_name("en1", &interface) != KERN_SUCCESS) // change to your own interface
        return KERN_FAILURE;
    if (iflt_attach(interface, &g_my_iff_filter, &g_filter_ref) == KERN_SUCCESS)
    {
        g_filter_registered = TRUE;
    }
    ifnet_release(interface);
    return KERN_SUCCESS;
}

kern_return_t MyInterfaceFilter_stop ()
{
    if (g_filter_registered)
    {
        iflt_detach(g_filter_ref);
        g_filter_registered = FALSE;
    }
    if (!g_filter_detached)
        return KERN_NO_ACCESS; // Don't allow unload until filter is detached.
    return KERN_SUCCESS;
}
