#ifndef _PCAP_VYATTA_DATAPLANE_H_
#define _PCAP_VYATTA_DATAPLANE_H_
#include <stdbool.h>

bool device_on_vyatta_dataplane(const char *device);
int vyatta_dataplane_findalldevs(pcap_if_t **alldevsp, char *err_str);
pcap_t *vyatta_dataplane_create(const char *device, char *ebuf, int *is_ours);
#endif /* _PCAP_VYATTA_DATAPLANE_H_ */
