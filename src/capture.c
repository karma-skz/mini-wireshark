/*
 * capture.c - Packet capture implementation for cshark
 * 
 * Handles pcap device setup, signal handling for graceful Ctrl+C,
 * and structured packet decoding (L2/L3/L4) with formatted output.
 */

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include "capture.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/if_arp.h>
#include "icmp.h"
#include "http.h"
#include "stats.h"
#include "session.h"

/* Global state for signal handler and capture management */
static pcap_t* global_handle = NULL;
static int packet_count = 0;
static volatile sig_atomic_t capture_interrupted = 0;
static int global_enable_hexdump = 0;

/*
 * Signal handler for SIGINT (Ctrl+C)
 * Gracefully stops packet capture without killing the program
 */
static void sigint_handler(int signum) {
    (void)signum; /* Suppress unused parameter warning */
    
    capture_interrupted = 1;
    
    if (global_handle) {
        pcap_breakloop(global_handle);
    }
    
    log_printf("\n\n[C-Shark] Capture interrupted by user (Ctrl+C)\n");
}

/*
 * Packet callback function called for each captured packet
 * Performs structured packet decoding (L2/L3/L4) and displays results
 */
static void packet_callback(unsigned char* user_data, 
                          const struct pcap_pkthdr* pkthdr, 
                          const unsigned char* packet) {
    (void)user_data; /* Suppress unused parameter warning */
    
    /* Check if capture was interrupted */
    if (capture_interrupted) {
        return;
    }
    
    packet_count++;
    
    /* Format timestamp */
    char* timestamp = format_timestamp(&pkthdr->ts);
    if (!timestamp) {
        timestamp = malloc(32);
        strcpy(timestamp, "unknown");
    }
    
    /* Create packet summary for storage */
    char summary[256];
    snprintf(summary, sizeof(summary), "Packet #%d | %s | %d bytes", 
             packet_count, timestamp, pkthdr->len);
    
    /* Store packet in session */
    session_add_packet(packet_count, pkthdr, packet, summary);
    
    /* Print packet header with colors */
    color_printf(COLOR_BRIGHT_CYAN, "\n======================================================================\n");
    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "Packet #");
    color_printf(COLOR_BOLD COLOR_BRIGHT_YELLOW, "%d", packet_count);
    color_printf(COLOR_WHITE, " | ");
    color_printf(COLOR_BRIGHT_GREEN, "Time: ");
    color_printf(COLOR_BRIGHT_YELLOW, "%s", timestamp);
    color_printf(COLOR_WHITE, " | ");
    color_printf(COLOR_BRIGHT_MAGENTA, "Length: ");
    color_printf(COLOR_BRIGHT_WHITE, "%d bytes\n", pkthdr->len);
    color_printf(COLOR_BRIGHT_CYAN, "----------------------------------------------------------------------\n");
    
    /* Decode packet layers */
    int eth_len = decode_ethernet(packet, pkthdr->caplen);
    if (eth_len > 0 && eth_len < pkthdr->caplen) {
        /* Get ethernet type for L3 decoding */
        struct ether_header* eth = (struct ether_header*)packet;
        unsigned short ether_type = ntohs(eth->ether_type);
        
        int l3_len = decode_layer3(packet + eth_len, pkthdr->caplen - eth_len, ether_type);
        if (l3_len > 0 && (eth_len + l3_len) < pkthdr->caplen) {
            /* For IP packets, decode L4 */
            if (ether_type == 0x0800) { /* IPv4 */
                struct ip* ip_hdr = (struct ip*)(packet + eth_len);
                decode_layer4(packet + eth_len + l3_len, 
                             pkthdr->caplen - eth_len - l3_len, 
                             ip_hdr->ip_p);
            } else if (ether_type == 0x86DD) { /* IPv6 */
                struct ip6_hdr* ip6_hdr = (struct ip6_hdr*)(packet + eth_len);
                decode_layer4(packet + eth_len + l3_len, 
                             pkthdr->caplen - eth_len - l3_len, 
                             ip6_hdr->ip6_nxt);
            }
        }
    }
    
    /* Optional hexdump of entire packet */
    if (global_enable_hexdump) {
        color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "Hexdump: ");
        print_hex_dump(packet, pkthdr->caplen, pkthdr->caplen);
        log_printf("\n");
    }
    
    color_printf(COLOR_BRIGHT_CYAN, "======================================================================\n");
    
    free(timestamp);
}

/*
 * Set up signal handler for graceful capture interruption
 */
void setup_signal_handler(void) {
    signal(SIGINT, sigint_handler);
}

/*
 * Clean up capture resources
 */
void cleanup_capture(void) {
    if (global_handle) {
        pcap_close(global_handle);
        global_handle = NULL;
    }
    
    /* Reset capture state */
    packet_count = 0;
    capture_interrupted = 0;
}

/*
 * Start packet capture on specified device
 * Opens device, sets up capture, and runs until interrupted
 */
int start_capture(const char* device_name, const char* filter_string, int enable_hexdump) {
    if (!device_name) {
        log_printf("Error: No device name provided\n");
        return -1;
    }
    
    char errbuf[PCAP_ERRBUF_SIZE];
    
    log_printf("[C-Shark] Opening device '%s' for capture...\n", device_name);
    
    /* Open device for live capture
     * Parameters: device, snaplen, promiscuous, timeout_ms, errbuf */
    global_handle = pcap_open_live(device_name, 65536, 1, 1000, errbuf);
    
    if (!global_handle) {
        log_printf("Error opening device '%s': %s\n", device_name, errbuf);
        return -1;
    }
    
    /* Apply BPF filter if provided */
    if (filter_string) {
        struct bpf_program filter_prog;
        if (pcap_compile(global_handle, &filter_prog, filter_string, 0, PCAP_NETMASK_UNKNOWN) == -1) {
            log_printf("Error compiling filter '%s': %s\n", filter_string, pcap_geterr(global_handle));
            pcap_close(global_handle);
            return -1;
        }
        
        if (pcap_setfilter(global_handle, &filter_prog) == -1) {
            log_printf("Error setting filter '%s': %s\n", filter_string, pcap_geterr(global_handle));
            pcap_freecode(&filter_prog);
            pcap_close(global_handle);
            return -1;
        }
        
        pcap_freecode(&filter_prog);
        log_printf("[C-Shark] Filter applied: %s\n", filter_string);
    }
    
    log_printf("[C-Shark] Device opened successfully. Starting capture...\n");
    log_printf("[C-Shark] Press Ctrl+C to stop capture and return to menu.\n\n");
    
    /* Start new packet storage session */
    session_start(device_name, filter_string);
    
    /* Reset state for new capture session */
    packet_count = 0;
    capture_interrupted = 0;
    global_enable_hexdump = enable_hexdump;
    
    /* Set up signal handler */
    setup_signal_handler();
    
    /* Start capture loop
     * Parameters: handle, count (-1 for infinite), callback, user_data */
    int result = pcap_loop(global_handle, -1, packet_callback, NULL);
    
    /* Check why loop ended */
    if (result == -1) {
        log_printf("\nError during packet capture: %s\n", pcap_geterr(global_handle));
        cleanup_capture();
        return -1;
    }
    
    /* Normal termination (breakloop called) */
    log_printf("\n[C-Shark] Capture stopped. Total packets captured: %d\n", packet_count);
    
    /* End the packet storage session */
    session_end();
    
    cleanup_capture();
    return 0;
}

/*
 * Decode and display Layer 2 (Ethernet) header
 */
int decode_ethernet(const unsigned char* packet, int length) {
    if (!packet || length < sizeof(struct ether_header)) {
        printf("L2: Packet too short for Ethernet header\n");
        return -1;
    }
    
    struct ether_header* eth = (struct ether_header*)packet;
    
    char* dst_mac = format_mac_address(eth->ether_dhost);
    char* src_mac = format_mac_address(eth->ether_shost);
    unsigned short ether_type = ntohs(eth->ether_type);
    
    color_printf(COLOR_BOLD COLOR_BRIGHT_GREEN, "[L2 Ethernet] ");
    color_printf(COLOR_WHITE, "Dst: ");
    color_printf(COLOR_BRIGHT_YELLOW, "%s", dst_mac ? dst_mac : "??:??:??:??:??:??");
    color_printf(COLOR_WHITE, " | Src: ");
    color_printf(COLOR_BRIGHT_CYAN, "%s", src_mac ? src_mac : "??:??:??:??:??:??");
    color_printf(COLOR_WHITE, " | Type: ");
    color_printf(COLOR_BRIGHT_MAGENTA, "%s", get_ether_type_name(ether_type));
    color_printf(COLOR_DIM, " (0x%04X)\n", ether_type);
    
    stats_increment("ethernet");
    
    free(dst_mac);
    free(src_mac);
    
    return sizeof(struct ether_header);
}

/*
 * Decode and display Layer 3 headers (IPv4/IPv6/ARP)
 */
int decode_layer3(const unsigned char* packet, int length, unsigned short ether_type) {
    if (!packet || length <= 0) {
        printf("L3: No data available\n");
        return -1;
    }
    
    switch (ether_type) {
        case 0x0800: { /* IPv4 */
            if (length < sizeof(struct ip)) {
                printf("L3: Packet too short for IPv4 header\n");
                return -1;
            }
            
            struct ip* ip_hdr = (struct ip*)packet;
            char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
            
            inet_ntop(AF_INET, &ip_hdr->ip_src, src_ip, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, &ip_hdr->ip_dst, dst_ip, INET_ADDRSTRLEN);
            
            char* flags_str = format_ip_flags(ntohs(ip_hdr->ip_off));
            int header_len = ip_hdr->ip_hl * 4;
            
            log_printf("L3 (IPv4): Src IP: %s | Dst IP: %s | Protocol: %s (%d)\n",
                       src_ip, dst_ip, get_ip_protocol_name(ip_hdr->ip_p), ip_hdr->ip_p);
            log_printf("           TTL: %d | ID: %d | Total Length: %d | Header Length: %d | Flags: %s\n",
                       ip_hdr->ip_ttl, ntohs(ip_hdr->ip_id), ntohs(ip_hdr->ip_len), 
                       header_len, flags_str ? flags_str : "None");
            
            stats_increment("ipv4");
            
            free(flags_str);
            return header_len;
        }
        
        case 0x86DD: { /* IPv6 */
            if (length < sizeof(struct ip6_hdr)) {
                printf("L3: Packet too short for IPv6 header\n");
                return -1;
            }
            
            struct ip6_hdr* ip6_hdr = (struct ip6_hdr*)packet;
            char src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
            
            inet_ntop(AF_INET6, &ip6_hdr->ip6_src, src_ip, INET6_ADDRSTRLEN);
            inet_ntop(AF_INET6, &ip6_hdr->ip6_dst, dst_ip, INET6_ADDRSTRLEN);
            
            unsigned int flow_label = ntohl(ip6_hdr->ip6_flow) & 0xFFFFF;
            unsigned int traffic_class = (ntohl(ip6_hdr->ip6_flow) >> 20) & 0xFF;
            
            log_printf("L3 (IPv6): Src IP: %s | Dst IP: %s\n", src_ip, dst_ip);
            log_printf("           Next Header: %s (%d) | Hop Limit: %d | Traffic Class: %d | Flow Label: %d | Payload Length: %d\n",
                       get_ip_protocol_name(ip6_hdr->ip6_nxt), ip6_hdr->ip6_nxt,
                       ip6_hdr->ip6_hlim, traffic_class, flow_label, ntohs(ip6_hdr->ip6_plen));
            
            stats_increment("ipv6");
            
            return sizeof(struct ip6_hdr);
        }
        
        case 0x0806: { /* ARP */
            if (length < sizeof(struct arphdr)) {
                printf("L3: Packet too short for ARP header\n");
                return -1;
            }
            
            struct arphdr* arp_hdr = (struct arphdr*)packet;
            
            if (length < sizeof(struct arphdr) + 2 * arp_hdr->ar_hln + 2 * arp_hdr->ar_pln) {
                printf("L3: Packet too short for complete ARP data\n");
                return -1;
            }
            
            const unsigned char* arp_data = packet + sizeof(struct arphdr);
            const unsigned char* sender_hw = arp_data;
            const unsigned char* sender_ip = arp_data + arp_hdr->ar_hln;
            const unsigned char* target_hw = arp_data + arp_hdr->ar_hln + arp_hdr->ar_pln;
            const unsigned char* target_ip = arp_data + 2 * arp_hdr->ar_hln + arp_hdr->ar_pln;
            
            char* sender_mac = format_mac_address(sender_hw);
            char* target_mac = format_mac_address(target_hw);
            char sender_ip_str[INET_ADDRSTRLEN], target_ip_str[INET_ADDRSTRLEN];
            
            inet_ntop(AF_INET, sender_ip, sender_ip_str, INET_ADDRSTRLEN);
            inet_ntop(AF_INET, target_ip, target_ip_str, INET_ADDRSTRLEN);
            
            const char* operation = (ntohs(arp_hdr->ar_op) == 1) ? "Request" : 
                                   (ntohs(arp_hdr->ar_op) == 2) ? "Reply" : "Unknown";
            
            log_printf("L3 (ARP): Operation: %s | Sender IP: %s | Target IP: %s\n",
                       operation, sender_ip_str, target_ip_str);
            log_printf("          Sender MAC: %s | Target MAC: %s\n",
                       sender_mac ? sender_mac : "??:??:??:??:??:??",
                       target_mac ? target_mac : "??:??:??:??:??:??");
            
            stats_increment("arp");
            
            free(sender_mac);
            free(target_mac);
            
            return sizeof(struct arphdr) + 2 * arp_hdr->ar_hln + 2 * arp_hdr->ar_pln;
        }
        
        default:
            printf("L3: Unsupported protocol (EtherType: 0x%04X)\n", ether_type);
            return -1;
    }
}

/*
 * Decode and display Layer 4 headers (TCP/UDP)
 */
int decode_layer4(const unsigned char* packet, int length, unsigned char protocol) {
    if (!packet || length <= 0) {
        return -1;
    }
    
    switch (protocol) {
        case 6: { /* TCP */
            if (length < sizeof(struct tcphdr)) {
                printf("L4: Packet too short for TCP header\n");
                return -1;
            }
            
            struct tcphdr* tcp_hdr = (struct tcphdr*)packet;
            unsigned short src_port = ntohs(tcp_hdr->th_sport);
            unsigned short dst_port = ntohs(tcp_hdr->th_dport);
            int header_len = tcp_hdr->th_off * 4;
            
            log_printf("L4 (TCP): Src Port: %d (%s) | Dst Port: %d (%s)\n",
                       src_port, get_port_service(src_port),
                       dst_port, get_port_service(dst_port));
            log_printf("          Seq: %u | Ack: %u | Window: %d | Checksum: 0x%04X | Header Length: %d\n",
                       ntohl(tcp_hdr->th_seq), ntohl(tcp_hdr->th_ack),
                       ntohs(tcp_hdr->th_win), ntohs(tcp_hdr->th_sum), header_len);
            
            /* TCP Flags */
            log_printf("          Flags: ");
            if (tcp_hdr->th_flags & TH_SYN) log_printf("SYN ");
            if (tcp_hdr->th_flags & TH_ACK) log_printf("ACK ");
            if (tcp_hdr->th_flags & TH_FIN) log_printf("FIN ");
            if (tcp_hdr->th_flags & TH_RST) log_printf("RST ");
            if (tcp_hdr->th_flags & TH_PUSH) log_printf("PSH ");
            if (tcp_hdr->th_flags & TH_URG) log_printf("URG ");
            if (tcp_hdr->th_flags == 0) log_printf("None");
            log_printf("\n");
            
            stats_increment("tcp");
            
            /* Check for HTTP payload if there's data after TCP header */
            if (header_len < length) {
                const unsigned char* payload = packet + header_len;
                int payload_len = length - header_len;
                decode_http(payload, payload_len, src_port, dst_port);
            }
            
            return header_len;
        }
        
        case 17: { /* UDP */
            if (length < sizeof(struct udphdr)) {
                printf("L4: Packet too short for UDP header\n");
                return -1;
            }
            
            struct udphdr* udp_hdr = (struct udphdr*)packet;
            unsigned short src_port = ntohs(udp_hdr->uh_sport);
            unsigned short dst_port = ntohs(udp_hdr->uh_dport);
            
            log_printf("L4 (UDP): Src Port: %d (%s) | Dst Port: %d (%s)\n",
                       src_port, get_port_service(src_port),
                       dst_port, get_port_service(dst_port));
            log_printf("          Length: %d | Checksum: 0x%04X\n",
                       ntohs(udp_hdr->uh_ulen), ntohs(udp_hdr->uh_sum));
            
            stats_increment("udp");
            
            return sizeof(struct udphdr);
        }
        
        case 1: { /* ICMP */
            return decode_icmp(packet, length);
        }
        
        case 58: { /* ICMPv6 */
            return decode_icmpv6(packet, length);
        }
        
        default:
            printf("L4: Unsupported or no L4 protocol (%d)\n", protocol);
            return -1;
    }
}