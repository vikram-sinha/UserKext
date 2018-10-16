//
//  Constant.h
//  NetworKext

#ifndef Constant_h
#define Constant_h

#include <sys/systm.h>
#include <mach/mach_types.h>

//socket filter classes
#include <sys/kpi_socketfilter.h>
#include <sys/socket.h>
#include <sys/kpi_mbuf.h>
#include <netinet/in.h>

#include <kern/assert.h>
#include <libkern/OSAtomic.h>

//ip filter classes
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/kpi_ipfilter.h>

//interface filter classes
#include <net/kpi_interfacefilter.h>
#include <net/ethernet.h>

// kernel events for broadcasting
#include <sys/kern_event.h>

// kernel control bidirectional api
#include <mach/kern_return.h>
#include <sys/kern_control.h>

#include <net/bpf.h>

#endif /* Constant_h */

//vendor id string
#define OBJECTIVE_SEE_VENDOR "com.objective-see"

//data out (UDP)
#define EVENT_DATA_OUT 0x2

//max data size
#define MAX_MSG_SIZE 200
