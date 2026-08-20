/*
 * pcap interface to vyatta dataplane.
 *
 * Copyright (c) 2015 by Brocade Communications Systems, Inc.
 * All rights reserved.
 * Copyright (c) 2017-2020, AT&T Intellectual Property.  All rights reserved.
 * SPDX-License-Identifier: BSD-3-Clause
 */
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <libmnl/libmnl.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <linux/netlink.h>
#include <errno.h>
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include "pcap-int.h"
#include "pcap-vyatta-dataplane.h"
#include <czmq.h>
#include <json.h>

/* private data */
struct pcap_vyatta_per_dp {
	zsock_t *sub_socket;
	zsock_t *pcapin_socket;
	int vplane_id;
	u_char cap_slot;
};

struct pcap_vyatta_dp {
	zpoller_t *poller;
	struct timespec last_beat;
	unsigned num_vplanes;
	bool uplink;
	bool swonly;
	int bandwidth;
	char *uplink_endpoint;
	struct pcap_vyatta_per_dp pcap_priv_dp[];
};

static int
send_filter(pcap_t *pcap, struct bpf_program *filter, u_char slot,
	    zsock_t *pcapin_sock)
{
	zmsg_t *msg;
	char *response;
	int ret = 0;

	msg = zmsg_new();
	if (msg == NULL) {
		snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
			 "zmq filter msg alloc failed\n");
		return PCAP_ERROR;
	}

	zmsg_addstr(msg, "FILTER");
	zmsg_addmem(msg, &slot, sizeof(u_char));
	zmsg_addmem(msg, &filter->bf_len, sizeof(u_int));
	zmsg_addmem(msg, filter->bf_insns,
		    filter->bf_len * sizeof(*filter->bf_insns));
	if (zmsg_send(&msg, pcapin_sock) != 0) {
		zmsg_destroy(&msg);
		snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
			 "zmq filter msg send failed\n");
		return PCAP_ERROR;
	}

	msg = zmsg_recv(pcapin_sock);
	if (msg) {
		response = zmsg_popstr(msg);
		if (strcmp(response, "OK FILTER")) {
			snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
				 "setfilter failed %s\n", response);
			ret = PCAP_ERROR;
		}
		free(response);
		zmsg_destroy(&msg);
	}

	return ret;
}

/*
 * Special filter for VDR uplinks.
 *
 * Filters out TCP from the dataplane IP address on the port
 * allocated for publishing captured packets.
 */
static int
compile_uplink_filter(pcap_t *pcap, char *endpoint,
		     struct bpf_program *uplink_filter)
{
	char uplink_address[INET6_ADDRSTRLEN];
	int uplink_port;
	char filter_expression[100];
	int len = strlen(endpoint);
	char *port;

	/*
	 * Endpoint is "tcp://<address>:<port>" but if address is
	 * IPv6 then it has colons, so work back from the end to
	 * find the last one.
	 */
	port = endpoint + len - 1;
	while (*port != ':')
		port--;

	sscanf(port, ":%5d", &uplink_port);
	*port = '\0';
	sscanf(endpoint, "tcp://%s", uplink_address);

	sprintf(filter_expression, "not tcp or not host %s or not port %d",
		uplink_address, uplink_port);

	if (pcap_compile_nopcap(pcap->snapshot, pcap->linktype,
				uplink_filter, filter_expression, 1, 0) < 0) {
		snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
			 "uplink filter %s compile failed\n",
			 filter_expression);
		return PCAP_ERROR;
	}

	return 0;
}

static int
vyatta_dataplane_setfilter(pcap_t *pcap, struct bpf_program *filter)
{
	struct pcap_vyatta_dp *pcap_priv = pcap->priv;
	struct pcap_vyatta_per_dp *pcap_priv_dp;
	struct bpf_program uplink_filter;
	int ret;
	int i;

	for (i = 0; i < pcap_priv->num_vplanes; i++) {
		pcap_priv_dp = &pcap_priv->pcap_priv_dp[i];

		ret = send_filter(pcap, filter, pcap_priv_dp->cap_slot,
				  pcap_priv_dp->pcapin_socket);
		if (ret < 0)
			return ret;
	}

	/*
	 * For capturing on an uplink, set an extra filter to
	 * avoid getting swamped by the captured packets sent over
	 * that uplink. This works in addition to the configured filter.
	 */
	if (pcap_priv->uplink) {
		if (compile_uplink_filter(pcap, pcap_priv->uplink_endpoint,
					  &uplink_filter) < 0)
			return PCAP_ERROR;

		if (send_filter(pcap, &uplink_filter,
				pcap_priv->pcap_priv_dp[0].cap_slot,
				pcap_priv->pcap_priv_dp[0].pcapin_socket) < 0)
			return PCAP_ERROR;

		pcap_freecode(&uplink_filter);
	}

	return 0;
}

/*
 * Send a request to fetch the packet drop count value via ZMQ.
 * This is a new message "DROP STATS". The return contains "OK DROP STATS"
 * followed by the value.
 * Extract and return this value (consolidated sum from all vplane).
 */
static int
dataplane_fetch_drop_count(pcap_t *pcap, uint64_t *pkt_drops)
{
	struct pcap_vyatta_dp *pcap_priv = pcap->priv;
	struct pcap_vyatta_per_dp *pcap_priv_dp;
	zmsg_t *msg;
	char *response;
	uint64_t drop_count;
	int i, rc;

	for (i = 0; i < pcap_priv->num_vplanes; i++) {
		pcap_priv_dp = &pcap_priv->pcap_priv_dp[i];

		rc = -1;

		msg = zmsg_new();
		if (msg == NULL) {
			snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
				 "zmq drop stats msg alloc failed\n");
			return rc;
		}

		zmsg_addstr(msg, "DROP STATS");
		zmsg_addmem(msg, &pcap_priv_dp->cap_slot, sizeof(u_char));

		if (zmsg_send(&msg, pcap_priv_dp->pcapin_socket) != 0) {
			zmsg_destroy(&msg);
			snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
				 "zmq drop stats msg send failed - %s \n",
				 zmq_strerror(errno));
			return rc;
		}

		drop_count = 0;

		rc = zsock_recv(pcap_priv_dp->pcapin_socket, "s8", &response,
				&drop_count);
		if (rc < 0) {
			/*
			 * zsock_recv can fail if its interrupted. Sets errno
			 * accordingly (EINTR)
			 * In this error condition, subsequent zmsg_send()
			 * also fails (Error string being
			 * "Operation cannot be accomplished in current state")
			 * The next message being "STOP" on cleanup fails to
			 * reach the datapath because of the send error.
			 * There is no way to reset the socket other than to
			 * retry and wait for the reply for the earlier
			 * message. In case of any other error return -1 with
			 * the error message.
			 */
			if(errno == EINTR)
				rc = zsock_recv(pcap_priv_dp->pcapin_socket,
						"s8", &response, &drop_count);

			if (rc < 0) {
				snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
					 "zmq drop stats msg receive failed - %s \n",
					 zmq_strerror(errno));
				return rc;
			}
		}

		if ((response == NULL) ||
		    (strcmp(response, "OK DROP STATS") != 0)) {
			/*
			 * rc is 0 here but the response is either
			 * NULL or is not the expected response.
			 * Return an error here. This implies that the drop
			 * count is not valid even if one vplane returns error
			 */
			snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
				 "zmq drop stats failed: %s\n",
				 response == NULL ? "NULL" : response);
			return -1;
		}

		free(response);

		*pkt_drops += drop_count;

	}
	return rc;
}

static int
vyatta_dataplane_stats(pcap_t *pcap, struct pcap_stat *stats)
{
	uint64_t drops = 0;
	int rc;

	rc = dataplane_fetch_drop_count(pcap, &drops);

	stats->ps_recv = 0;
	stats->ps_drop = drops;
	stats->ps_ifdrop = 0;

	return rc;
}

/* Send a heartbeat if we haven't done so in a while. */
static int
dataplane_beat(pcap_t *pcap)
{
	struct pcap_vyatta_dp *pcap_priv = pcap->priv;
	struct pcap_vyatta_per_dp *pcap_priv_dp;
	struct timespec now;
	zmsg_t *msg;
	char *response;
	int ret = 0;
	int i;

	clock_gettime(CLOCK_MONOTONIC_COARSE, &now);
	if (now.tv_sec - pcap_priv->last_beat.tv_sec < 8)
		return 0;

	pcap_priv->last_beat.tv_sec = now.tv_sec;

	for (i = 0; i < pcap_priv->num_vplanes; i++) {
		pcap_priv_dp = &pcap_priv->pcap_priv_dp[i];

		msg = zmsg_new();
		if (msg == NULL) {
			snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
				 "zmq beat msg alloc failed\n");
			return PCAP_ERROR;
		}

		zmsg_addstr(msg, "BEAT");

		if (zmsg_send(&msg, pcap_priv_dp->pcapin_socket) != 0) {
			zmsg_destroy(&msg);
			snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
				 "zmq beat msg send failed\n");
			return PCAP_ERROR;
		}

		msg = zmsg_recv(pcap_priv_dp->pcapin_socket);
		if (msg) {
			response = zmsg_popstr(msg);
			if (strcmp(response, "OK BEAT"))
				ret = PCAP_ERROR;
			free(response);
			zmsg_destroy(&msg);
		}
	}
	return ret;
}

static int
vyatta_dataplane_read(pcap_t *pcap, int max_packets,
		      pcap_handler callback, u_char *user)
{
	struct pcap_vyatta_dp *pcap_priv = pcap->priv;
	struct pcap_vyatta_per_dp *pcap_priv_dp;
	zsock_t *sub_read;
	struct pcap_pkthdr pkth;
	zmsg_t *msg;
	zframe_t *frame;
	u_char *buffer;
	u_char mask;
	int i;

	while(1) {
		if (dataplane_beat(pcap) < 0)
			return PCAP_ERROR;

		if ((sub_read = zpoller_wait(pcap_priv->poller, 5000))) {
			msg = zmsg_recv(sub_read);

			/*
			 * zmsg_recv can be interrupted.
			 */
			if (msg == NULL)
				return -2;
			/*
			 * First frame is the slot mask, is this packet for us?
			 */
			frame = zmsg_pop(msg);
			mask = *zframe_data(frame);
			zframe_destroy(&frame);

			for (i = 0; i < pcap_priv->num_vplanes; i++) {
				pcap_priv_dp = &pcap_priv->pcap_priv_dp[i];
				if (pcap_priv_dp->sub_socket == sub_read)
					break;
			}
			if (mask & pcap_priv_dp->cap_slot)
				break;

			zmsg_destroy(&msg);
		} else if (zpoller_expired(pcap_priv->poller))
			continue;
		else if (zpoller_terminated(pcap_priv->poller))
			return -2;
		else
			return PCAP_ERROR;
	}

	/*
	 * Next frame is the pcap header,
	 * everything else is the packet.
	 */
	frame = zmsg_pop(msg);
	memcpy(&pkth, zframe_data(frame), sizeof(pkth));
	zframe_destroy(&frame);

	buffer = pcap->buffer;
	while (zmsg_size(msg)) {
		frame = zmsg_pop(msg);
		memcpy(buffer, zframe_data(frame), zframe_size(frame));
		buffer += zframe_size(frame);
		zframe_destroy(&frame);
	}
	zmsg_destroy(&msg);
	/*
	 * Filtering takes place at the remote end.
	 */
	callback(user, &pkth, pcap->buffer);
	return 1;
}

static void
vyatta_dataplane_cleanup(pcap_t *pcap)
{
	struct pcap_vyatta_dp *pcap_priv = pcap->priv;
	struct pcap_vyatta_per_dp *pcap_priv_dp;
	char *response;
	zmsg_t *msg;
	int i;

	for (i = 0; i < pcap_priv->num_vplanes; i++) {
		pcap_priv_dp = &pcap_priv->pcap_priv_dp[i];

		msg = zmsg_new();

		if (msg == NULL) {
			snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
				 "zmq filter msg alloc failed\n");
			return;
		}

		zmsg_addstr(msg, "STOP");
		zmsg_addmem(msg, &pcap_priv_dp->cap_slot, sizeof(u_char));

		if (zmsg_send(&msg, pcap_priv_dp->pcapin_socket) != 0)
			zmsg_destroy(&msg);

		msg = zmsg_recv(pcap_priv_dp->pcapin_socket);
		if (msg) {
			response = zmsg_popstr(msg);
			if (strcmp(response, "OK STOP"))
				snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
					 "stop failed %s\n", response);

			free(response);
			zmsg_destroy(&msg);
		}
		zsock_destroy(&pcap_priv_dp->sub_socket);
		zsock_destroy(&pcap_priv_dp->pcapin_socket);
	}
	zpoller_destroy(&pcap_priv->poller);

	if (pcap_priv->uplink)
		free(pcap_priv->uplink_endpoint);

	pcap_cleanup_live_common(pcap);
}

static int
vyatta_dataplane_activate(pcap_t *pcap)
{
	struct pcap_vyatta_dp *pcap_priv = pcap->priv;
	struct pcap_vyatta_per_dp *pcap_priv_dp;
	int vplane_id;
	FILE *vplout;
	char vplresponse[112]; /* slotmask and 2 urls (possibly IPv6) */
	const char *pub_endpoint;
	const char *pcapin_endpoint;
	char cmd[100];
	int vplsh_ret;
	int i;

	pcap_priv->poller = zpoller_new(NULL);
	if (pcap_priv->poller == NULL) {
		snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
			 "zpoller create failed\n");
		return PCAP_ERROR;
	}

	pcap->bufsize = pcap->snapshot;
	pcap->buffer = malloc(pcap->bufsize);
	if (pcap->buffer == NULL) {
		snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
			 "Can't allocate dump buffer: %s",
			 pcap_strerror(errno));
		return PCAP_ERROR;
	}

	zsys_set_ipv6(1);

	for (i = 0; i < pcap_priv->num_vplanes; i++) {
		pcap_priv_dp = &pcap_priv->pcap_priv_dp[i];
		vplane_id = pcap_priv_dp->vplane_id;

		/*
		 * Send capture start command:
		 *   "capture start <intf_name> <is_promisc> <snaplen>"
		 */
		if (vplane_id == 0)
			/* Local vplane */
			sprintf(cmd,
				"/opt/vyatta/bin/vplsh -l "
				"-c \"capture start %s %u %u %u %u\" 2>&1",
				pcap->opt.device, pcap->opt.promisc,
				pcap->snapshot, pcap_priv->swonly,
				pcap_priv->bandwidth);
		else
			sprintf(cmd,
				"/opt/vyatta/bin/vplsh -f%d "
				"-c \"capture start %s %u %u %u %u\" 2>&1",
				vplane_id, pcap->opt.device, pcap->opt.promisc,
				pcap->snapshot, pcap_priv->swonly,
				pcap_priv->bandwidth);

		vplout = popen(cmd, "r");

		if (fgets(vplresponse, sizeof(vplresponse), vplout) == NULL) {
			snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
				 "capture start failed, no response");
			return PCAP_ERROR;
		}

		vplsh_ret = pclose(vplout);

		if (vplsh_ret != 0) {
			snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
				 "capture start failed, %s\n",
				 vplresponse);
			return PCAP_ERROR;
		}

		/*
		 * Expected response:
		 * <slot_mask> <publish endpoint> <request endpoint>
		 */
		const char *regex = "(\\d+)\\s+(\\w+://\\S+)\\s+(\\w+://\\S+)";
		zrex_t *zrex = zrex_new(regex);
		if (!zrex || !zrex_valid(zrex)) {
			snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
				"zrex_new(%s) failed, error: %s\n", regex,
				zrex ? zrex_strerror(zrex) : "zrex alloc err");
			return PCAP_ERROR;
		}

		if (!zrex_matches(zrex, vplresponse) || zrex_hits(zrex) != 4) {
			snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
				"vplsh response %s does not match regex %s\n",
				vplresponse, regex);
			return PCAP_ERROR;
		}

		sscanf(zrex_hit(zrex, 1), "%2hhx", &pcap_priv_dp->cap_slot);
		pub_endpoint = zrex_hit(zrex, 2);
		pcapin_endpoint = zrex_hit(zrex, 3);

		pcap_priv_dp->sub_socket = zsock_new_sub(pub_endpoint, "");
		if (pcap_priv_dp->sub_socket == NULL) {
			snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
				 "zsock_new_sub(%s, \"\") failed: %s\n",
				 pub_endpoint, strerror(errno));
			return PCAP_ERROR;
		}

		if (pcap_priv->uplink)
			pcap_priv->uplink_endpoint = strdup(pub_endpoint);

		if (zpoller_add(pcap_priv->poller,
				pcap_priv_dp->sub_socket) < 0) {
			snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
				 "zpoller add failed\n");
			return PCAP_ERROR;
		}

		pcap_priv_dp->pcapin_socket = zsock_new_req(pcapin_endpoint);
		if (pcap_priv_dp->pcapin_socket == NULL) {
			snprintf(pcap->errbuf, PCAP_ERRBUF_SIZE,
				 "zsock_new_req(%s) failed: %s\n",
				 pcapin_endpoint, strerror(errno));
			return PCAP_ERROR;
		}

		zrex_destroy(&zrex);

	}

	clock_gettime(CLOCK_MONOTONIC_COARSE, &pcap_priv->last_beat);
	pcap->read_op = vyatta_dataplane_read;
	pcap->stats_op = vyatta_dataplane_stats;
	pcap->cleanup_op = vyatta_dataplane_cleanup;
	pcap->setfilter_op = vyatta_dataplane_setfilter;
	pcap->selectable_fd = -1;
	pcap->linktype = DLT_EN10MB;

	return 0;
}

#define MAX_VPLANES 512
static int
find_bridge_vplanes(const char *bridgename, int *ids)
{
	char brif_dirname[PATH_MAX];
	DIR *brif_dir;
	struct dirent *br_dirent;
	int vplane_index = 0;
	int vplane_id;
	int i = 0;

	snprintf(brif_dirname, sizeof(brif_dirname),
		 "/sys/devices/virtual/net/%s/brif", bridgename);

	brif_dir = opendir(brif_dirname);
	if (brif_dir == NULL)
		return 0;

	while ((br_dirent = readdir(brif_dir))) {

		if ((br_dirent->d_name[0] == '.') ||
		    !strncmp("vxl-vbr", br_dirent->d_name, 7))
			continue;

		/*
		 * If any ports on the bridge aren't vplane ports,
		 * just give up and don't try to do a vplane capture.
		 */
		if (sscanf(br_dirent->d_name, "dp%d", &vplane_id) != 1) {
			closedir(brif_dir);
			return 0;
		}

		if (vplane_index)
			for (i = 0; i < vplane_index; i++) {
				if (ids[i] == vplane_id)
					break;
			}

		if (i == vplane_index)
			ids[vplane_index++] = vplane_id;

		if (vplane_index == MAX_VPLANES)
			break;
	}
	closedir(brif_dir);
	return vplane_index;
}

static int
find_bridge_vif_vplanes(const char *brvifname, int *ids)
{
	char if_dirname[PATH_MAX];
	char brifname[PATH_MAX];
	DIR *if_dir;
	struct dirent *if_dirent;
	int vplane_index = 0;

	snprintf(if_dirname, sizeof(if_dirname),
		 "/sys/devices/virtual/net/%s", brvifname);

	if_dir = opendir(if_dirname);
	if (if_dir == NULL)
		return 0;

	brifname[0] = '\0';
	while ((if_dirent = readdir(if_dir))) {
		if (!memcmp(if_dirent->d_name, "lower_",
			    strlen("lower_"))) {
			vplane_index = find_bridge_vplanes(
				if_dirent->d_name + strlen("lower_"),
				ids);
			break;
		}
	}
	closedir(if_dir);
	return vplane_index;
}

static int linkinfo_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type = mnl_attr_get_type(attr);

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, IFLA_INFO_MAX) < 0)
		return MNL_CB_OK;

	if (type == IFLA_INFO_KIND)
		if (mnl_attr_validate(attr, MNL_TYPE_STRING) < 0)
			return MNL_CB_ERROR;

	tb[type] = attr;
	return MNL_CB_OK;
}

static int link_attr(const struct nlattr *attr, void *data)
{
	const struct nlattr **tb = data;
	int type;

	/* skip unsupported attribute in user-space */
	if (mnl_attr_type_valid(attr, IFLA_MAX) < 0)
		return MNL_CB_OK;

	type = mnl_attr_get_type(attr);
	tb[type] = attr;
	return MNL_CB_OK;
}

static int process_netlink_rtnl(const struct nlmsghdr *nlh, void *arg)
{
	struct ifinfomsg *ifi = mnl_nlmsg_get_payload(nlh);
	struct nlattr *tb[IFLA_MAX+1] = { NULL };
	struct nlattr *linkinfo[IFLA_INFO_MAX+1] = { NULL };
	int ret;
	bool *is_ours = arg;

	ret = mnl_attr_parse(nlh, sizeof(*ifi), link_attr, tb);
	if (ret != MNL_CB_OK)
		return MNL_CB_ERROR;

	if (tb[IFLA_LINKINFO]) {
		if (mnl_attr_parse_nested(tb[IFLA_LINKINFO],
					  linkinfo_attr,
					  linkinfo) != MNL_CB_OK)
			return MNL_CB_ERROR;
	} else {
		return MNL_CB_OK;
	}

	if (!linkinfo[IFLA_INFO_KIND])
		return MNL_CB_OK;

	const char *kind = mnl_attr_get_str(linkinfo[IFLA_INFO_KIND]);
	if ((strcmp(kind, "gre") == 0) || (strcmp(kind, "gretap") == 0) ||
	    (strcmp(kind, "vti") == 0) || (strcmp(kind, "vxlan") == 0) ||
	    (strcmp(kind, "ip6gre") == 0))
		*is_ours = true;

	return MNL_CB_OK;
}

static bool
vyatta_dataplane_tunnel(const char *device)
{
	char buf[MNL_SOCKET_BUFFER_SIZE];
	struct nlmsghdr *nlh = mnl_nlmsg_put_header(buf);
	struct ifinfomsg *ifi;
	ssize_t len;
	int ifindex;
	bool is_ours = false;

	ifindex = if_nametoindex(device);
	if (ifindex == 0)
		return false;

	/* Get the netlink info for the given ifindex */
	struct mnl_socket *nl = mnl_socket_open(NETLINK_ROUTE);
	if (!nl)
		return false;

	if (mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
		goto close;

	nlh->nlmsg_type = RTM_GETLINK;
	nlh->nlmsg_flags = NLM_F_REQUEST;
	ifi = mnl_nlmsg_put_extra_header(nlh, sizeof(struct ifinfomsg));
	ifi->ifi_family = AF_UNSPEC;
	ifi->ifi_index = ifindex;

	if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
		goto close;

	len = mnl_socket_recvfrom(nl, buf, sizeof(buf));
	mnl_cb_run(buf, len, 0, 0, process_netlink_rtnl, &is_ours);

 close:
	mnl_socket_close(nl);
	return is_ours;
}

static bool
net_device_is_local(const char *device)
{
	DIR *net_dir;
	struct dirent *net_dirent;

	net_dir = opendir("/sys/class/net");
	if (net_dir == NULL)
		return false;

	while ((net_dirent = readdir(net_dir)))
		if (!strcmp(net_dirent->d_name, device)) {
			closedir(net_dir);
			return true;
		}

	closedir(net_dir);
	return false;
}

static int
dp_tunnel_find_binding(const char *device)
{
	const char mapfile[] = "/var/run/vyatta/dp_bind_map";
	FILE *f;
	struct stat st;
	char *map_buf;
	int read;
	json_object *dp_bind_map = NULL;
	json_object *bind_maps;
	int i,j;
	int bound_dpid = -1;

	/*
	 * Only VDR has a binding map, if it doesn't exist assume
	 * we're on a VR.
	 */
	f = fopen(mapfile, "r");
	if (!f)
		return 0;

	if (stat(mapfile, &st) < 0) {
		fclose(f);
		return -1;
	}

	map_buf = malloc(st.st_size);
	if (!map_buf) {
		fclose(f);
		return -ENOMEM;
	}

	read = fread(map_buf, 1, st.st_size, f);
	fclose(f);
	if (!read)
		goto out;

	dp_bind_map = json_tokener_parse(map_buf);
	if (!dp_bind_map)
		goto out;

	json_object_object_get_ex(dp_bind_map, "bind_maps", &bind_maps);
	if (!bind_maps)
		goto out;

	for (i = 0; i < json_object_array_length(bind_maps); i++) {
		json_object *dp_map = json_object_array_get_idx(bind_maps, i);
		json_object *dp_intfs;

		json_object_object_get_ex(dp_map, "intfs", &dp_intfs);

		if (dp_intfs)
			for (j = 0;
			     j < json_object_array_length(dp_intfs); j++) {
				json_object *intf =
					json_object_array_get_idx(dp_intfs,j);
				if (!strcmp(device,
					    json_object_get_string(intf))) {
					bound_dpid = i;
					goto out;
				}
			}
	}

out:
	json_object_put(dp_bind_map);
	free(map_buf);
	return bound_dpid;
}

static int
device_is_ours(const char *device, int *vplane_ids, bool *is_uplink)
{
	int num_vplanes = 1;

	*is_uplink = false;

	if (!strncmp("dp", device, 2)) {
		/*
		 * Regular dp interface. If the net device isn't local then
		 * we might be on a VDR dp node, so try a capture via
		 * local vplaned.
		 */
		if (!net_device_is_local(device))
			vplane_ids[0] = 0;
		else if (sscanf(device, "dp%d", &vplane_ids[0]) != 1)
			return 0;
	} else if (!strncmp("bp", device, 2)) {
		/*
		 * Backplane dp interface. If the net device isn't local then
		 * we might be on a VDR dp node, so try a capture via
		 * local vplaned.
		 */
		if (!net_device_is_local(device))
			vplane_ids[0] = 0;
		else if (sscanf(device, "bp%d", &vplane_ids[0]) != 1)
			return 0;
	} else if (!strncmp("up", device, 2)) {
		/*
		 * VDR uplink. If the net device is local then we're on the
		 * dp node so capture via local vplaned.
		 * If not, try remote.
		 */
		if (net_device_is_local(device))
			vplane_ids[0] = 0;
		else if (sscanf(device, "up%d", &vplane_ids[0]) != 1)
			return 0;

		*is_uplink = true;
	} else if (!strncmp("br", device, 2) ||
		   !strncmp("sw", device, 2) ||
		   !strncmp("vbr", device, 3)) {
		if (strchr(device, '.'))
			num_vplanes = find_bridge_vif_vplanes(
				device, vplane_ids);
		else
			num_vplanes = find_bridge_vplanes(device, vplane_ids);
	} else if (!strncmp("lttp", device, 4))
		/* Not supported on VDR */
		vplane_ids[0] = 0;
	else if (!strncmp("vfp", device, 3))
		vplane_ids[0] = 0;
	else if (vyatta_dataplane_tunnel(device)) {
		if ((vplane_ids[0] = dp_tunnel_find_binding(device)) < 0)
			return 0;
	} else
		return 0;

	return num_vplanes;
}

bool
device_on_vyatta_dataplane(const char *device)
{
	int vplane_ids[MAX_VPLANES];
	bool is_uplink;

	return device_is_ours(device, vplane_ids, &is_uplink) != 0;
}

static bool
vyatta_getenv_to_int(const char *name, int *value, int vmin, int vmax)
{
	const char *envar;
	char *endp = NULL;
	long val;

	*value = 0;
	envar = getenv(name);
	if (envar == NULL)
		return false;

	val = strtol(envar, &endp, 10);
	if ((endp == NULL) ||
	    (*endp != '\0') ||
	    (val > vmax || val < vmin))
		return false;

	*value = val;
	return true;
}

pcap_t *
vyatta_dataplane_create(const char *device, char *ebuf, int *is_ours)
{
	pcap_t *pcap;
	struct pcap_vyatta_dp *pcap_priv;
	struct pcap_vyatta_per_dp *pcap_priv_dp;
	int vplane_ids[MAX_VPLANES];
	unsigned i, num_vplanes;
	bool is_uplink = false;
	int env_value;

	if (num_vplanes = device_is_ours(device, vplane_ids, &is_uplink))
		*is_ours = 1;
	else {
		*is_ours = 0;
		return NULL;
	}

	pcap = pcap_create_common(ebuf,
				  sizeof(*pcap_priv) +
				  sizeof(*pcap_priv_dp) * num_vplanes);
	if (pcap == NULL)
		return NULL;

	pcap->activate_op = vyatta_dataplane_activate;

	pcap_priv = pcap->priv;
	pcap_priv->num_vplanes = num_vplanes;
	pcap_priv->uplink = is_uplink;

	/*
	 * See vyatta-tshark.pl over in vyatta-op.
	 */
	if (vyatta_getenv_to_int("VYATTA_MONITOR_SWONLY", &env_value,
				 0, INT_MAX))
		pcap_priv->swonly = env_value > 0;

	if (vyatta_getenv_to_int("VYATTA_MONITOR_BANDWIDTH", &env_value,
				 0, INT_MAX))
		pcap_priv->bandwidth = env_value;

	for (i = 0; i < num_vplanes; i++)
		pcap_priv->pcap_priv_dp[i].vplane_id = vplane_ids[i];

	return pcap;
}

int
vyatta_dataplane_findalldevs(pcap_if_t **alldevsp, char *err_str)
{
	/* silent failure - we don't support capturing on all devices */
	return 0;
}
