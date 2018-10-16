//
//  IPFilter.c
//  NetworKext
//
//  Created by AMRA on 28/08/18.
//  Copyright © 2018 innovanathinklabs. All rights reserved.
//

#include "IPFilter.h"
#include "Constant.h"



enum {
    kMyFiltDirIn,
    kMyFiltDirOut,
    kMyFiltNumDirs
};

struct myfilter_stats {
    unsigned long udp_packets[kMyFiltNumDirs];
    unsigned long tcp_packets[kMyFiltNumDirs];
    unsigned long icmp_packets[kMyFiltNumDirs];
    unsigned long other_packets[kMyFiltNumDirs];
};

struct Person
{
    char name[20];
    int age;
};

static struct myfilter_stats g_filter_stats;
static ipfilter_t g_filter_ref;
static boolean_t g_filter_registered = FALSE;
static boolean_t g_filter_detached = FALSE;

static void log_ip_packet(mbuf_t* data, int dir) {
    char src[32], dst[32];
    struct ip *ip = (struct ip*)mbuf_data(*data);
    if (ip->ip_v != 4)
        return;
    bzero(src, sizeof(src));
    bzero(dst, sizeof(dst));
    inet_ntop(AF_INET, &ip->ip_src, src, sizeof(src));
    inet_ntop(AF_INET, &ip->ip_dst, dst, sizeof(dst));
    switch (ip->ip_p) {
        case IPPROTO_TCP:
            printf("TCP: ");
            g_filter_stats.tcp_packets[dir]++;
            break;
        case IPPROTO_UDP:
            printf("UDP: ");
            g_filter_stats.udp_packets[dir]++;
            break;
        case IPPROTO_ICMP:
            printf("ICMP: ");
            g_filter_stats.icmp_packets[dir]++;
        default:
            printf("OTHER: ");
            g_filter_stats.other_packets[dir]++;
            break;
    }
    printf("%s -> %s\n", src, dst);
    
    int no_of_pkt = 0;
    int no_of_chained_pkt = 0;
    for (mbuf_t mb_nxt_pkt = *data; mb_nxt_pkt; mb_nxt_pkt = mbuf_nextpkt(mb_nxt_pkt)){
        no_of_pkt = no_of_pkt + 1;
        for (mbuf_t mb = mb_nxt_pkt; mb; mb = mbuf_next(mb)){
            // packet length
            no_of_chained_pkt = no_of_chained_pkt + 1;
            size_t buf_data_size = mbuf_len(mb);
            printf("the amount of data in mbuf: %zu", buf_data_size);
            
            mbuf_type_t type_of_mbuf = mbuf_type(mb);
            printf("mbuf type is: %d", type_of_mbuf);
            
            mbuf_flags_t flag_of_mbuf = mbuf_flags(mb);
            printf("(MH_PKTHDR, MH_EXT) mbuf flag is: %d", flag_of_mbuf);
            
            // packet header length
            size_t data_size = mbuf_pkthdr_len(mb);
            printf("The total length of a packet split in multiple mbufs is stored in the m_pkthdr.len field is: %zu", data_size);
            
            /*
             The socket layer (and hence the socket filter) is situated between user space and the network protocol stack in the kernel. Because of this, socket filters cannot peek at the IP or TCP header of an outgoing network packet because that happens later in the processing chain.
             However, it is still possible to filter IP-based traffic using a socket filter, as metadata, such as the IP address the packet is destined for, is known. The same is true for incoming traffic. The protocol stack will strip header information before it enters the socket layer. In effect, we are seeing the reassembled data that will eventually be read by a user space application. Because of this, a socket filter is not suitable for use when information from protocol headers is required, and one should use the lower level IP or interface filters instead.
             */
            unsigned char* mb_pkt_hdr = mbuf_pkthdr_header(mb);
            printf("mb_pkt_hdr: %s", mb_pkt_hdr);
            
//            unsigned char *dataString = (unsigned char*)mbuf_data(*data);
//            if(mb_pkt_hdr != NULL){
//                printf("Copied byte array is:\n");
//                for(int i=0;i<data_size;i++)
//                    printf("%02X ",mb_pkt_hdr[i]);
//                printf("\n");
//            }
//            printf("hello pkt dataString: %.*s\n", (int)strlen(dataString), dataString);
//            char queries[2048];
//            unsigned char *dataString = (unsigned char*)mbuf_pkthdr_header(*data);
//            if(dataString != NULL){
//                size_t str_len = mbuf_pkthdr_len(*data);
//                printf("hello logs str_len: %d\n", (int)str_len);
//                printf("hello logs dataString: %s\n", dataString);
//                printf("hello logs: %.*s\n", (int)str_len, dataString);
//
//                for (size_t i = 0; i < str_len; i++)
//                {
//                    printf("hell yeh: %c", dataString[i]);
//                }
//            }
            
//            const char *greetings = "Hello world";
//            printf("|%.8s|\n", greetings);
//            printf("|%.*s|\n", (int)strlen(greetings)+1, greetings);
        }
    }
}

static errno_t myipfilter_output(void* cookie, mbuf_t* data, ipf_pktopts_t options) {
    if (data)
        log_ip_packet(data, kMyFiltDirOut);
    return 0;
}

static errno_t myipfilter_input(void* cookie, mbuf_t* data, int offset, u_int8_t protocol) {
    if (data)
        log_ip_packet(data, kMyFiltDirIn);
    
    struct ip *ih;
    struct tcphdr *th;
    
    if (! (data && *data))
        return 0;
    if (protocol != IPPROTO_TCP)
        return 0;
    
    ih = mbuf_data(*data);
    th = (struct tcphdr *)(((char *)ih) + offset);
    return 0;
}

static void myipfilter_detach(void* cookie) {
    /* cookie isn't dynamically allocated, no need to free in this case */
    struct myfilter_stats* stats = (struct myfilter_stats*)cookie;
    printf("UDP_IN %lu UDP OUT: %lu TCP_IN: %lu TCP_OUT: %lu ICMP_IN: %lu ICMP OUT: %lu OTHER_IN: %lu OTHER_OUT: %lu\n",
           stats->udp_packets[kMyFiltDirIn],
           stats->udp_packets[kMyFiltDirOut],
           stats->tcp_packets[kMyFiltDirIn],
           stats->tcp_packets[kMyFiltDirOut],
           stats->icmp_packets[kMyFiltDirIn],
           stats->icmp_packets[kMyFiltDirOut],
           stats->other_packets[kMyFiltDirIn],
           stats->other_packets[kMyFiltDirOut]);
    g_filter_detached = TRUE;
}

static struct ipf_filter g_my_ip_filter = {
    &g_filter_stats,
    "com.innovanathinklabs.NetworKext",
    myipfilter_input,
    myipfilter_output, //myipfilter_output_redirect,
    myipfilter_detach
};

kern_return_t MyIPFilter_start () {
    printf("MyIPFilter_start called");
    int result;
    bzero(&g_filter_stats, sizeof(struct myfilter_stats));
    result = ipf_addv4(&g_my_ip_filter, &g_filter_ref);
    if (result == KERN_SUCCESS)
        g_filter_registered = TRUE;
    return result;
}

kern_return_t MyIPFilter_stop () {
    printf("MyIPFilter_stop called");
    if (g_filter_registered)
    {
        ipf_remove(g_filter_ref);
        g_filter_registered = FALSE;
    }
    /* We need to ensure filter is detached before we return */
    if (!g_filter_detached)
        return KERN_NO_ACCESS; // Try unloading again.
    return KERN_SUCCESS;
}


static errno_t myipfilter_output_redirect(void* cookie, mbuf_t* data, ipf_pktopts_t options)
{
    printf("MyIPFilter_stop called");
    struct in_addr addr_old;
    struct in_addr addr_new;
    int ret;
    struct ip* ip = (struct ip*)mbuf_data(*data);
    if (ip->ip_v != 4)
        return 0;
    addr_old.s_addr = htonl(134744072); // 8.8.8.8
    addr_new.s_addr = htonl(167837964); // 10.1.1.12
    // redirect packets to 8.8.8.8 to the IP address 10.1.1.12.
    if (ip->ip_dst.s_addr == addr_old.s_addr)
    {
        ip->ip_dst = addr_new;
//        myipfilter_update_cksum(*data);
        ret = ipf_inject_output(*data, g_filter_ref, options);
        return ret == 0 ? EJUSTRETURN : ret;
    }
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


/*
int ip_status = 0;

static ipfilter_t ipv4Filter;
static u_int32_t ipv4COOKIE = 'ipv4';


static ipfilter_t ipv6Filter;
static u_int32_t ipv6COOKIE = 'ipv6';

static struct in_addr ipv4Addr = {0};
static struct in6_addr ipv6Addr = {0};

static int bytes_out_since_reset = 0;
static int bytes_in_since_reset = 0;


void ipf_detach_handler(void *cookie) {
}

kern_return_t ip_filter_setup() {
    kern_return_t ret = KERN_SUCCESS;
    ipv4Filter = NULL;
    ipv6Filter = NULL;
    return ret;
}

errno_t ipf_input_handler(void *cookie, mbuf_t *data, int offset, u_int8_t protocol) {
    bytes_in_since_reset += mbuf_len(*data);
    
    char srcStr[INET6_ADDRSTRLEN] = {0};
    char dstStr[INET6_ADDRSTRLEN] = {0};
    
    if(cookie == &ipv4COOKIE) {
        //DPRINT("ipv4 cookie!\n");
        if(mbuf_len(*data) >= sizeof(struct ip)) {
            struct ip *iii = (struct ip*) data;
            inet_ntop(AF_INET, &(iii->ip_dst), dstStr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(iii->ip_src), srcStr, INET_ADDRSTRLEN);
            //iii->ip_dst;
            //iii->ip_src;
        }
    } else if(cookie == &ipv6COOKIE){
        //DPRINT("ipv6 cookie!\n");
        if(mbuf_len(*data) >= sizeof(struct ip6_hdr)) {
            struct ip6_hdr *iii = (struct ip6_hdr *) data;
            //iii->ip6_dst;
            //iii->ip6_src;
            inet_ntop(AF_INET6, &(iii->ip6_dst), dstStr, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(iii->ip6_src), srcStr, INET6_ADDRSTRLEN);
        }
    } else {
//        DPRINT("Unknown cookie! %p\n", cookie);
        printf("Unknown cookie! %p\n", cookie);
        return 0;
    }
    
    //DPRINT("src %s; dst %s", srcStr, dstStr);
    
    char queries[2048];
    unsigned char *dataString = mbuf_data(*data);
    for (size_t i = 0; i < mbuf_len(*data); i++)
    {
        printf("%c", dataString[i]);
        size_t sLen =  sizeof(dataString[i]);
        char charStr;
        charStr = dataString[i];
        char *asd = &charStr;
        strncat(queries, asd, sLen);
    }
    printf("dnsMsg: %s", queries);
    
    
//    if(user_ip_in_byte_limit != 0 && bytes_in_since_reset > user_ip_in_byte_limit) {
//        return !EJUSTRETURN;
//    }
//
//    if(user_ip_io_byte_limit != 0 && (bytes_in_since_reset + bytes_out_since_reset) > user_ip_io_byte_limit) {
//        return !EJUSTRETURN;
//    }
    
    return 0;
};

errno_t ipf_output_handler(void *cookie, mbuf_t *data, ipf_pktopts_t options) {
    bytes_out_since_reset += mbuf_len(*data);
    
    char srcStr[INET6_ADDRSTRLEN] = {0};
    char dstStr[INET6_ADDRSTRLEN] = {0};
    
    if(cookie == &ipv4COOKIE) {
        //DPRINT("ipv4 cookie!\n");
        if(mbuf_len(*data) >= sizeof(struct ip)) {
            struct ip *iii = (struct ip*) data;
            inet_ntop(AF_INET, &(iii->ip_dst), dstStr, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &(iii->ip_src), srcStr, INET_ADDRSTRLEN);
        }
    } else if(cookie == &ipv6COOKIE){
        //DPRINT("ipv6 cookie!\n");
        if(mbuf_len(*data) >= sizeof(struct ip6_hdr)) {
            struct ip6_hdr *iii = (struct ip6_hdr *) data;
            //iii->ip6_dst;
            //iii->ip6_src;
            inet_ntop(AF_INET6, &(iii->ip6_dst), dstStr, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &(iii->ip6_src), srcStr, INET6_ADDRSTRLEN);                       
        }
    } else {
//        DPRINT("Unknown cookie! %p\n", cookie);
        printf("Unknown cookie! %p\n", cookie);
        return 0;
    }
    
    char queries[2048];
    unsigned char *dataString = mbuf_data(*data);
    for (size_t i = 0; i < mbuf_len(*data); i++)
    {
        printf("%c", dataString[i]);
        size_t sLen =  sizeof(dataString[i]);
        char charStr;
        charStr = dataString[i];
        char *asd = &charStr;
        strncat(queries, asd, sLen);
    }
    printf("dnsMsg: %s", queries);
    
    //DPRINT("src %s; dst %s", srcStr, dstStr);
    
//    if(user_ip_out_byte_limit != 0 && bytes_out_since_reset > user_ip_out_byte_limit) {
//        return !EJUSTRETURN;
//    }
//
//    if(user_ip_io_byte_limit != 0 && (bytes_in_since_reset + bytes_out_since_reset) > user_ip_io_byte_limit) {
//        return !EJUSTRETURN;
//    }
    
    return 0;
}

//
// final cleanup for the ip filter
// @return 0 on success
//
 
kern_return_t ip_filter_cleanup() {
    kern_return_t ret = KERN_SUCCESS;
    
    ret |= ip_filter_stop();
    
    return ret;
}

errno_t ip_filter_start() {
    errno_t ret = KERN_SUCCESS;
    
    bytes_out_since_reset = 0;
    bytes_in_since_reset = 0;
    
    //struct ipf_fiter ipff;
    struct ipf_filter ipff;
    ipff.ipf_detach = ipf_detach_handler;
    ipff.ipf_input = ipf_input_handler;
    ipff.ipf_output = ipf_output_handler;
    
    ipff.cookie = &ipv4COOKIE;
    ipff.name = "netfil ipv4 filter";
    ret |= ipf_addv4(&ipff, &ipv4Filter);
    
    ipff.cookie = &ipv6COOKIE;
    ipff.name = "netfil ipv6 filter";
    ret |= ipf_addv6(&ipff, &ipv6Filter);
    
    ip_status = 1;
    
    return ret;
}
errno_t ip_filter_stop() {
    errno_t ret = KERN_SUCCESS;
    
    ipf_remove(ipv4Filter);
    ipf_remove(ipv6Filter);
    
    ipv4Filter = NULL;
    ipv6Filter = NULL;
    
    bytes_out_since_reset = 0;
    bytes_in_since_reset = 0;

    bzero(&ipv4Addr, sizeof(ipv4Addr));
    bzero(&ipv6Addr, sizeof(ipv6Addr));
    
    ip_status = 0;
    return ret;
}

*/
