// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Manually define necessary constants
#ifndef ETH_P_IP
#define ETH_P_IP    0x0800
#endif
#ifndef ETH_P_IPV6
#define ETH_P_IPV6  0x86DD
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#endif
// BPF return codes for TC actions
#ifndef BPF_TC_ACT_OK
#define BPF_TC_ACT_OK 0
#endif
#ifndef BPF_TC_ACT_SHOT
#define BPF_TC_ACT_SHOT 2 // Action to drop the packet
#endif

// --- Configuration Map ---
// Stores the target TCP port at index 0.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u16); // Store target port in host byte order
    __uint(max_entries, 1);
} config_map SEC(".maps");

// --- Job Status Map ---
// Stores the global allow/reject status at index 0.
// 0 = Reject packets, 1 = Allow packets.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u8); // Store job status (0 or 1)
    __uint(max_entries, 1);
} job_status_map SEC(".maps");


// --- Ring Buffer Map Definition ---
// For sending payload prefixes to userspace.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024); // 256 KB ring buffer
} rb SEC(".maps");

// --- Data Structure for Ring Buffer Events ---
#define MAX_IDENTIFIER_LEN 512 // Max prefix size to send
struct sni_event_t {
    char identifier[MAX_IDENTIFIER_LEN];
};

// --- Main TC Program ---
SEC("tc")
int tc_ingress(struct __sk_buff *skb) {
    void *data_end = (void *)(unsigned long)skb->data_end;
    void *data     = (void *)(unsigned long)skb->data;
    struct ethhdr *eth; struct iphdr *iph; struct tcphdr *tcph;
    __u16 h_proto; __u16 dest_port_net;
    u64 l3_hdr_off = 0, l4_hdr_off = 0, payload_off = 0;
    int ret;
    __u32 config_key = 0;
    __u32 status_key = 0;
    __u16 *target_port_ptr;
    __u16 target_port_h;
    __u8 *job_status_ptr;
    __u8 job_status;

    // --- Read Target Port from config_map ---
    target_port_ptr = bpf_map_lookup_elem(&config_map, &config_key);
    if (!target_port_ptr) {
        // Config map not populated by userspace yet? Silently allow.
        return BPF_TC_ACT_OK;
    }
    target_port_h = *target_port_ptr; // Value is already host byte order
    if (target_port_h == 0) {
        // Port not configured - allow packet.
        return BPF_TC_ACT_OK;
    }

    // --- L2/L3/L4 Parsing (Ethernet/IPv4/TCP) ---
    // L2 Parse
    if (data + sizeof(struct ethhdr) > data_end) return BPF_TC_ACT_OK;
    eth = (struct ethhdr *)data; h_proto = eth->h_proto; l3_hdr_off = sizeof(struct ethhdr);
    // L3 Parse (IPv4 only for simplicity)
    if (h_proto == bpf_htons(ETH_P_IP)) {
        iph = data + l3_hdr_off;
        if ((void *)iph + sizeof(struct iphdr) > data_end) return BPF_TC_ACT_OK;
        if (iph->protocol != IPPROTO_TCP) return BPF_TC_ACT_OK;
        if (iph->ihl < 5) return BPF_TC_ACT_OK; // Reject invalid header length
        l4_hdr_off = l3_hdr_off + ((u64)iph->ihl * 4);
        if (data + l4_hdr_off > data_end) return BPF_TC_ACT_OK;
    } else {
        // Allow non-IPv4 packets (like ARP, IPv6 etc.)
        return BPF_TC_ACT_OK;
    }
    // L4 Parse
    if (data + l4_hdr_off + sizeof(struct tcphdr) > data_end) return BPF_TC_ACT_OK;
    tcph = (struct tcphdr *)(data + l4_hdr_off);
    dest_port_net = tcph->dest;

    // --- Filter: Destination Port ---
    if (bpf_ntohs(dest_port_net) != target_port_h) {
         return BPF_TC_ACT_OK; // Not the target port, allow.
    }

    // --- Packet matched target port. Now check global job status. ---

    // --- Check Job Status from job_status_map ---
    job_status_ptr = bpf_map_lookup_elem(&job_status_map, &status_key);
    if (!job_status_ptr) {
        // Status map not yet populated by userspace. Default to REJECT (0) for safety.
        // Userspace MUST initialize this map to 0, then update based on job checks.
        bpf_printk("BPF DBG: Job status map (key %u) lookup failed. Defaulting to REJECT. Port %u\n", status_key, target_port_h);
        return BPF_TC_ACT_SHOT; // Drop packet if status unknown
    }
    job_status = *job_status_ptr;

    // --- Decision Point ---
    if (job_status == 0) {
        // Status is REJECT (0) - Drop the packet.
        bpf_printk("BPF DBG: Job status is REJECT (0). Dropping packet for port %u.\n", target_port_h);
        return BPF_TC_ACT_SHOT;
    }

    // --- Job status is ALLOW (1) ---
    bpf_printk("BPF DBG: Job status is ALLOW (1). Processing packet for port %u.\n", target_port_h);

    // --- Send payload prefix to Ring Buffer ---
    // Calculate payload offset (check TCP header length)
    if (tcph->doff < 5) { return BPF_TC_ACT_OK; } // Invalid TCP header offset
    payload_off = l4_hdr_off + ((u64)tcph->doff * 4);
    // bpf_printk("BPF DBG: Calculated PayloadOff=%llu (TCPDoff=%u)\n", payload_off, tcph->doff);

    // Reserve space in the ring buffer
    struct sni_event_t *event = bpf_ringbuf_reserve(&rb, sizeof(struct sni_event_t), 0);
    if (!event) {
        // Failed reserve, allow packet but don't send event
        return BPF_TC_ACT_OK;
    }

    // Check if payload actually exists and determine length to copy
    long payload_size = (long)(data_end - (data + payload_off));
    if (payload_size <= 0) {
        bpf_ringbuf_discard(event, 0); // No payload, discard event
        return BPF_TC_ACT_OK;
    }

    // Determine length to copy (min of payload size, buffer size - 1 for null terminator)
    int len_to_copy = payload_size < (MAX_IDENTIFIER_LEN - 1) ? payload_size : (MAX_IDENTIFIER_LEN - 1);

    // Zero out buffer first (important!)
    #pragma clang loop unroll(disable)
    for(int i=0; i < MAX_IDENTIFIER_LEN; ++i) { event->identifier[i] = 0; }

    // Use bpf_skb_load_bytes to safely copy payload prefix from skb into event buffer
    ret = bpf_skb_load_bytes(skb, payload_off, &event->identifier[0], len_to_copy);
    if (ret == 0) {
        // event->identifier[len_to_copy] = '\0'; // Already zeroed
        // bpf_printk("BPF DBG: Copied prefix (%d bytes), submitting.\n", len_to_copy);
        bpf_ringbuf_submit(event, 0); // Submit event to userspace
    } else {
        // bpf_printk("BPF DBG: skb_load_bytes failed for prefix (err %d). Discarding event.\n", ret);
        bpf_ringbuf_discard(event, 0); // Discard on error
    }

    // --- Allow packet to proceed up the network stack ---
    return BPF_TC_ACT_OK;
}

// Required license for eBPF programs
char LICENSE[] SEC("license") = "Dual BSD/GPL";