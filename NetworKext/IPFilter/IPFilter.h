//
//  IPFilter.h
//  NetworKext
//
//  Created by AMRA on 28/08/18.
//  Copyright © 2018 innovanathinklabs. All rights reserved.
//

#ifndef IPFilter_h
#define IPFilter_h

#include "Constant.h"

#endif /* IPFilter_h */

kern_return_t ip_filter_setup(void);
kern_return_t ip_filter_cleanup(void);

errno_t ip_filter_start(void);
errno_t ip_filter_stop(void);

kern_return_t MyIPFilter_start (void);
kern_return_t MyIPFilter_stop (void);

static errno_t myipfilter_output_redirect(void* cookie, mbuf_t* data, ipf_pktopts_t options);
