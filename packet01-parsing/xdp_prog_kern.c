/* SPDX-License-Identifier: GPL-2.0 */
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
/* Defines xdp_stats_map from packet04 */
#include "../common/xdp_stats_kern_user.h"
#include "../common/xdp_stats_kern.h"

#ifndef VLAN_MAX_DEPTH
#define VLAN_MAX_DEPTH 2
#endif

#ifndef VLAN_VID_MASK
#define VLAN_VID_MASK 0x0fff
#endif

struct vlan_hdr {
	__be16	h_vlan_TCI;
	__be16	h_vlan_encapsulated_proto;
};

struct collected_vlans {
	__u16 id[VLAN_MAX_DEPTH];
};

/* Header cursor to keep track of current parsing position */
struct hdr_cursor {
	void *pos;
};

static __always_inline int proto_is_vlan(__u16 h_proto)
{
	return !!(h_proto == bpf_htons(ETH_P_8021Q) ||
			  h_proto == bpf_htons(ETH_P_8021AD));
}

static __always_inline int parse_vlanhdr(struct hdr_cursor *nh,
					void *data_end, __u16 hproto, struct collected_vlans *vlans)
{
	struct vlan_hdr *vlan_or_eth = nh->pos;

	#pragma unroll
	for(int i = 0; i < VLAN_MAX_DEPTH; i++) {
		if(!proto_is_vlan(hproto))
			break;

		if (vlan_or_eth + 1 > data_end)
			break;

		hproto = vlan_or_eth->h_vlan_encapsulated_proto;

		if (vlans) /* collect VLAN ids */
			vlans->id[i] =
				(bpf_ntohs(vlan_or_eth->h_vlan_TCI) & VLAN_VID_MASK);

		vlan_or_eth++;
	}

	nh->pos = vlan_or_eth;
    return hproto;
}

/* Packet parsing helpers.
 *
 * Each helper parses a packet header, including doing bounds checking, and
 * returns the type of its contents if successful, and -1 otherwise.
 *
 * For Ethernet and IP headers, the content type is the type of the payload
 * (h_proto for Ethernet, nexthdr for IPv6), for ICMP it is the ICMP type field.
 * All return values are in host byte order.
 */
static __always_inline int parse_ethhdr(struct hdr_cursor *nh,
					void *data_end,
					struct ethhdr **ethhdr)
{
	struct ethhdr *eth = nh->pos;
	int hdrsize = sizeof(*eth);

	/* Byte-count bounds check; check if current pointer + size of header
	 * is after data_end.
	 */
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*ethhdr = eth;

	return parse_vlanhdr(nh, data_end, eth->h_proto, NULL); /* network-byte-order */
}

static __always_inline int parse_ip6hdr(struct hdr_cursor *nh,
					void *data_end,
					struct ipv6hdr **ip6hdr)
{
	struct ipv6hdr *ipv6 = nh->pos;

	if (ipv6 + 1 > data_end)
		return -1;

	nh->pos = ipv6 + 1;
	*ip6hdr = ipv6;

	return ipv6->nexthdr; /* network-byte-order */
}

static __always_inline int parse_iphdr(struct hdr_cursor *nh,
					void *data_end,
					struct iphdr **iphdr)
{
	struct iphdr *ip = nh->pos;

	if (ip + 1 > data_end)
		return -1;

	int hdrsize = ip->ihl * 4;
	if (nh->pos + hdrsize > data_end)
		return -1;

	nh->pos += hdrsize;
	*iphdr = ip;

	return ip->protocol;
}

static __always_inline int parse_icmp6hdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmp6hdr **icmp6hdr)
{
	struct icmp6hdr *icmp6 = nh->pos;

	if (icmp6 + 1 > data_end)
		return -1;

	nh->pos = icmp6 + 1;
	*icmp6hdr = icmp6;

	return icmp6->icmp6_type; /* network-byte-order */
}

static __always_inline int parse_icmphdr(struct hdr_cursor *nh,
					  void *data_end,
					  struct icmphdr **icmphdr)
{
	struct icmphdr *icmp = nh->pos;

	if (icmp + 1 > data_end)
		return -1;

	nh->pos = icmp + 1;
	*icmphdr = icmp;

	return icmp->type;
}

SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth;
    struct ipv6hdr *ipv6;
    struct icmp6hdr *icmp6;
	struct iphdr *ip;
	struct icmphdr *icmp;

	/* Default action XDP_PASS, imply everything we couldn't parse, or that
	 * we don't want to deal with, we just pass up the stack and let the
	 * kernel deal with it.
	 */
	__u32 action = XDP_PASS; /* Default action */

        /* These keep track of the next header type and iterator pointer */
	struct hdr_cursor nh;
	int nh_type;

	/* Start next header cursor position at data start */
	nh.pos = data;

	/* Packet parsing in steps: Get each header one at a time, aborting if
	 * parsing fails. Each helper function does sanity checking (is the
	 * header type in the packet correct?), and bounds checking.
	 */
	nh_type = parse_ethhdr(&nh, data_end, &eth);
    if (nh_type == bpf_htons(ETH_P_IPV6) )
    {
	    nh_type = parse_ip6hdr(&nh, data_end, &ipv6);
		if (nh_type != IPPROTO_ICMPV6)
			goto out;

		nh_type = parse_icmp6hdr(&nh, data_end, &icmp6);
		if (nh_type != ICMPV6_ECHO_REQUEST)
			goto out;

	    if (bpf_ntohs(icmp6->icmp6_sequence) % 2 == 0)
			action = XDP_DROP;
    }
    else if (nh_type == bpf_htons(ETH_P_IP) )
    {
    	nh_type = parse_iphdr(&nh, data_end, &ip);
		if (nh_type != IPPROTO_ICMP)
			goto out;

		nh_type = parse_icmphdr(&nh, data_end, &icmp);
		if (nh_type != ICMP_ECHO)
			goto out;

		if (bpf_ntohs(icmp->un.echo.sequence) % 2 == 0)
			action = XDP_DROP;
    }
out:
	return xdp_stats_record_action(ctx, action); /* read via xdp_stats */
}

char _license[] SEC("license") = "GPL";
