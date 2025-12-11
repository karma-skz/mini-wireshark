/*
 * inspect.c - Detailed packet inspection and analysis implementation
 * 
 * Comprehensive packet analysis with hex dumps, layer breakdowns,
 * and human-readable interpretations of network protocols.
 */

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include "inspect.h"
#include "session.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

/*
 * Helper function to format timestamp for display
 */
static void format_time_display(const struct timeval* tv, char* buffer, size_t size) {
    struct tm* tm_info = localtime(&tv->tv_sec);
    snprintf(buffer, size, "%02d:%02d:%02d.%06ld",
             tm_info->tm_hour, tm_info->tm_min, tm_info->tm_sec, tv->tv_usec);
}

/*
 * Helper function to get basic packet info for summary
 */
static void get_packet_basic_info(const unsigned char* data, unsigned int length,
                                 char* protocol, char* src_info, char* dst_info) {
    strcpy(protocol, "Unknown");
    strcpy(src_info, "N/A");
    strcpy(dst_info, "N/A");
    
    if (length < sizeof(struct ethhdr)) {
        return;
    }
    
    struct ethhdr* eth = (struct ethhdr*)data;
    unsigned short eth_type = ntohs(eth->h_proto);
    
    if (eth_type == ETH_P_IP && length >= sizeof(struct ethhdr) + sizeof(struct iphdr)) {
        struct iphdr* ip = (struct iphdr*)(data + sizeof(struct ethhdr));
        strcpy(protocol, get_ip_protocol_name(ip->protocol));
        
        struct in_addr src, dst;
        src.s_addr = ip->saddr;
        dst.s_addr = ip->daddr;
        strcpy(src_info, inet_ntoa(src));
        strcpy(dst_info, inet_ntoa(dst));
        
    } else if (eth_type == ETH_P_ARP) {
        strcpy(protocol, "ARP");
        strcpy(src_info, "ARP Request/Reply");
        strcpy(dst_info, "");
    } else {
        snprintf(protocol, 32, "EthType:0x%04x", eth_type);
    }
}

/*
 * Display a summary table of all packets in the current session
 */
int inspect_show_packet_summary(void) {
    const packet_session_t* session = session_get_current();
    if (!session || session->count == 0) {
        color_printf(COLOR_BRIGHT_RED, "No packets in current session!\n");
        return 0;
    }
    
    color_printf(COLOR_BRIGHT_CYAN, "\n================================================================================\n");
    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "PACKET SESSION SUMMARY\n");
    color_printf(COLOR_BRIGHT_CYAN, "================================================================================\n");
    color_printf(COLOR_BRIGHT_WHITE, "Interface: %s | Filter: %s\n", 
             session->interface_name ? session->interface_name : "Unknown",
             session->filter_string ? session->filter_string : "None");
    color_printf(COLOR_BRIGHT_WHITE, "Packets: %u | Capacity: %u\n", 
             session->count, session->capacity);
    color_printf(COLOR_BRIGHT_CYAN, "================================================================================\n\n");
    
    color_printf(COLOR_BRIGHT_YELLOW, "%-8s %-15s %-10s %-10s %-20s %-20s\n",
                 "ID", "Timestamp", "Length", "Protocol", "Source", "Destination");
    color_printf(COLOR_BRIGHT_CYAN, "--------------------------------------------------------------------------------\n");
    
    for (unsigned int i = 0; i < session->count; i++) {
        const stored_packet_t* pkt = &session->packets[i];
        char timestamp[32], protocol[32], src_info[64], dst_info[64];
        
        format_time_display(&pkt->timestamp, timestamp, sizeof(timestamp));
        get_packet_basic_info(pkt->data, pkt->caplen, protocol, src_info, dst_info);
        
        color_printf(COLOR_BRIGHT_WHITE, "%-8u %-15s %-10u %-10s %-20s %-20s\n",
                 pkt->id, timestamp, pkt->length, protocol, src_info, dst_info);
    }
    
    color_printf(COLOR_BRIGHT_CYAN, "================================================================================\n\n");
    
    return session->count;
}

/*
 * Display a hex dump of packet data
 */
void inspect_hex_dump(const unsigned char* data, unsigned int length, unsigned int offset) {
    color_printf(COLOR_BRIGHT_CYAN, "\n================================================================================\n");
    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "HEX DUMP\n");
    color_printf(COLOR_BRIGHT_CYAN, "================================================================================\n\n");
    
    color_printf(COLOR_BRIGHT_YELLOW, "Offset    ");
    for (int i = 0; i < 16; i++) {
        color_printf(COLOR_BRIGHT_YELLOW, "%02X ", i);
    }
    color_printf(COLOR_BRIGHT_YELLOW, "  ASCII\n");
    
    color_printf(COLOR_BRIGHT_YELLOW, "--------  ");
    for (int i = 0; i < 16; i++) {
        color_printf(COLOR_BRIGHT_YELLOW, "-- ");
    }
    color_printf(COLOR_BRIGHT_YELLOW, "  ----------------\n");
    
    for (unsigned int i = 0; i < length; i += 16) {
        color_printf(COLOR_BRIGHT_BLUE, "%08X  ", offset + i);
        
        // Print hex bytes
        for (int j = 0; j < 16; j++) {
            if (i + j < length) {
                color_printf(COLOR_BRIGHT_WHITE, "%02X ", data[i + j]);
            } else {
                color_printf(COLOR_BRIGHT_WHITE, "   ");
            }
        }
        
        color_printf(COLOR_BRIGHT_GREEN, "  ");
        
        // Print ASCII representation
        for (int j = 0; j < 16 && i + j < length; j++) {
            unsigned char c = data[i + j];
            if (isprint(c) && c < 127) {
                color_printf(COLOR_BRIGHT_GREEN, "%c", c);
            } else {
                color_printf(COLOR_BRIGHT_RED, ".");
            }
        }
        color_printf(COLOR_RESET, "\n");
    }
    printf("\n");
}

/*
 * Analyze Ethernet header
 */
static void analyze_ethernet_header(const unsigned char* data, unsigned int length) {
    if (length < sizeof(struct ethhdr)) {
        color_printf(COLOR_BRIGHT_RED, "❌ Packet too short for Ethernet header\n");
        return;
    }
    
    struct ethhdr* eth = (struct ethhdr*)data;
    
    color_printf(COLOR_BRIGHT_CYAN, "--------------------------------------------------------------------------------\n");
    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "ETHERNET HEADER (Layer 2)\n");
    color_printf(COLOR_BRIGHT_CYAN, "--------------------------------------------------------------------------------\n");
    
    color_printf(COLOR_BRIGHT_WHITE, "Destination MAC: ");
    color_printf(COLOR_BRIGHT_GREEN, "%02x:%02x:%02x:%02x:%02x:%02x\n",
             eth->h_dest[0], eth->h_dest[1], eth->h_dest[2],
             eth->h_dest[3], eth->h_dest[4], eth->h_dest[5]);
             
    color_printf(COLOR_BRIGHT_WHITE, "Source MAC:      ");
    color_printf(COLOR_BRIGHT_GREEN, "%02x:%02x:%02x:%02x:%02x:%02x\n",
             eth->h_source[0], eth->h_source[1], eth->h_source[2],
             eth->h_source[3], eth->h_source[4], eth->h_source[5]);
             
    unsigned short eth_type = ntohs(eth->h_proto);
    color_printf(COLOR_BRIGHT_WHITE, "EtherType:       ");
    color_printf(COLOR_BRIGHT_YELLOW, "0x%04x", eth_type);
    
    switch (eth_type) {
        case ETH_P_IP:
            color_printf(COLOR_BRIGHT_GREEN, " (IPv4)\n");
            break;
        case ETH_P_IPV6:
            color_printf(COLOR_BRIGHT_GREEN, " (IPv6)\n");
            break;
        case ETH_P_ARP:
            color_printf(COLOR_BRIGHT_GREEN, " (ARP)\n");
            break;
        default:
            color_printf(COLOR_BRIGHT_RED, " (Unknown/Other)\n");
            break;
    }
    
    color_printf(COLOR_BRIGHT_WHITE, "Header Length:   ");
    color_printf(COLOR_BRIGHT_CYAN, "%lu bytes\n\n", sizeof(struct ethhdr));
}

/*
 * Analyze IP header
 */
static void analyze_ip_header(const unsigned char* data, unsigned int length, unsigned int* next_offset) {
    if (length < sizeof(struct ethhdr) + sizeof(struct iphdr)) {
        color_printf(COLOR_BRIGHT_RED, "❌ Packet too short for IP header\n");
        return;
    }
    
    struct iphdr* ip = (struct iphdr*)(data + sizeof(struct ethhdr));
    
    color_printf(COLOR_BRIGHT_CYAN, "--------------------------------------------------------------------------------\n");
    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "IP HEADER (Layer 3)\n");
    color_printf(COLOR_BRIGHT_CYAN, "--------------------------------------------------------------------------------\n");
    
    color_printf(COLOR_BRIGHT_WHITE, "Version:         ");
    color_printf(COLOR_BRIGHT_GREEN, "%u\n", ip->version);
    
    color_printf(COLOR_BRIGHT_WHITE, "Header Length:   ");
    color_printf(COLOR_BRIGHT_GREEN, "%u bytes (%u * 4)\n", ip->ihl * 4, ip->ihl);
    
    color_printf(COLOR_BRIGHT_WHITE, "Type of Service: ");
    color_printf(COLOR_BRIGHT_YELLOW, "0x%02x\n", ip->tos);
    
    color_printf(COLOR_BRIGHT_WHITE, "Total Length:    ");
    color_printf(COLOR_BRIGHT_GREEN, "%u bytes\n", ntohs(ip->tot_len));
    
    color_printf(COLOR_BRIGHT_WHITE, "Identification:  ");
    color_printf(COLOR_BRIGHT_YELLOW, "0x%04x (%u)\n", ntohs(ip->id), ntohs(ip->id));
    
    color_printf(COLOR_BRIGHT_WHITE, "Flags & Frag:    ");
    color_printf(COLOR_BRIGHT_YELLOW, "0x%04x", ntohs(ip->frag_off));
    if (ntohs(ip->frag_off) & IP_DF) color_printf(COLOR_BRIGHT_RED, " [Don't Fragment]");
    if (ntohs(ip->frag_off) & IP_MF) color_printf(COLOR_BRIGHT_RED, " [More Fragments]");
    printf("\n");
    
    color_printf(COLOR_BRIGHT_WHITE, "Time to Live:    ");
    color_printf(COLOR_BRIGHT_GREEN, "%u\n", ip->ttl);
    
    color_printf(COLOR_BRIGHT_WHITE, "Protocol:        ");
    color_printf(COLOR_BRIGHT_YELLOW, "%u", ip->protocol);
    color_printf(COLOR_BRIGHT_GREEN, " (%s)\n", get_ip_protocol_name(ip->protocol));
    
    color_printf(COLOR_BRIGHT_WHITE, "Header Checksum: ");
    color_printf(COLOR_BRIGHT_YELLOW, "0x%04x\n", ntohs(ip->check));
    
    struct in_addr src, dst;
    src.s_addr = ip->saddr;
    dst.s_addr = ip->daddr;
    
    color_printf(COLOR_BRIGHT_WHITE, "Source IP:       ");
    color_printf(COLOR_BRIGHT_GREEN, "%s\n", inet_ntoa(src));
    
    color_printf(COLOR_BRIGHT_WHITE, "Destination IP:  ");
    color_printf(COLOR_BRIGHT_GREEN, "%s\n\n", inet_ntoa(dst));
    
    *next_offset = sizeof(struct ethhdr) + (ip->ihl * 4);
}

/*
 * Analyze TCP header
 */
static void analyze_tcp_header(const unsigned char* data, unsigned int length, unsigned int offset) {
    if (length < offset + sizeof(struct tcphdr)) {
        color_printf(COLOR_BRIGHT_RED, "❌ Packet too short for TCP header\n");
        return;
    }
    
    struct tcphdr* tcp = (struct tcphdr*)(data + offset);
    
    color_printf(COLOR_BRIGHT_CYAN, "--------------------------------------------------------------------------------\n");
    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "TCP HEADER (Layer 4)\n");
    color_printf(COLOR_BRIGHT_CYAN, "--------------------------------------------------------------------------------\n");
    
    color_printf(COLOR_BRIGHT_WHITE, "Source Port:     ");
    color_printf(COLOR_BRIGHT_GREEN, "%u\n", ntohs(tcp->source));
    
    color_printf(COLOR_BRIGHT_WHITE, "Destination Port:");
    color_printf(COLOR_BRIGHT_GREEN, "%u\n", ntohs(tcp->dest));
    
    color_printf(COLOR_BRIGHT_WHITE, "Sequence Number: ");
    color_printf(COLOR_BRIGHT_YELLOW, "0x%08x (%u)\n", ntohl(tcp->seq), ntohl(tcp->seq));
    
    color_printf(COLOR_BRIGHT_WHITE, "Ack Number:      ");
    color_printf(COLOR_BRIGHT_YELLOW, "0x%08x (%u)\n", ntohl(tcp->ack_seq), ntohl(tcp->ack_seq));
    
    color_printf(COLOR_BRIGHT_WHITE, "Header Length:   ");
    color_printf(COLOR_BRIGHT_GREEN, "%u bytes (%u * 4)\n", tcp->doff * 4, tcp->doff);
    
    color_printf(COLOR_BRIGHT_WHITE, "Flags:           ");
    if (tcp->fin) color_printf(COLOR_BRIGHT_RED, "[FIN] ");
    if (tcp->syn) color_printf(COLOR_BRIGHT_GREEN, "[SYN] ");
    if (tcp->rst) color_printf(COLOR_BRIGHT_RED, "[RST] ");
    if (tcp->psh) color_printf(COLOR_BRIGHT_YELLOW, "[PSH] ");
    if (tcp->ack) color_printf(COLOR_BRIGHT_BLUE, "[ACK] ");
    if (tcp->urg) color_printf(COLOR_BRIGHT_MAGENTA, "[URG] ");
    printf("\n");
    
    color_printf(COLOR_BRIGHT_WHITE, "Window Size:     ");
    color_printf(COLOR_BRIGHT_GREEN, "%u\n", ntohs(tcp->window));
    
    color_printf(COLOR_BRIGHT_WHITE, "Checksum:        ");
    color_printf(COLOR_BRIGHT_YELLOW, "0x%04x\n", ntohs(tcp->check));
    
    color_printf(COLOR_BRIGHT_WHITE, "Urgent Pointer:  ");
    color_printf(COLOR_BRIGHT_YELLOW, "%u\n\n", ntohs(tcp->urg_ptr));
}

/*
 * Analyze UDP header
 */
static void analyze_udp_header(const unsigned char* data, unsigned int length, unsigned int offset) {
    if (length < offset + sizeof(struct udphdr)) {
        color_printf(COLOR_BRIGHT_RED, "❌ Packet too short for UDP header\n");
        return;
    }
    
    struct udphdr* udp = (struct udphdr*)(data + offset);
    
    color_printf(COLOR_BRIGHT_CYAN, "--------------------------------------------------------------------------------\n");
    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "UDP HEADER (Layer 4)\n");
    color_printf(COLOR_BRIGHT_CYAN, "--------------------------------------------------------------------------------\n");
    
    color_printf(COLOR_BRIGHT_WHITE, "Source Port:     ");
    color_printf(COLOR_BRIGHT_GREEN, "%u\n", ntohs(udp->source));
    
    color_printf(COLOR_BRIGHT_WHITE, "Destination Port:");
    color_printf(COLOR_BRIGHT_GREEN, "%u\n", ntohs(udp->dest));
    
    color_printf(COLOR_BRIGHT_WHITE, "Length:          ");
    color_printf(COLOR_BRIGHT_GREEN, "%u bytes\n", ntohs(udp->len));
    
    color_printf(COLOR_BRIGHT_WHITE, "Checksum:        ");
    color_printf(COLOR_BRIGHT_YELLOW, "0x%04x\n\n", ntohs(udp->check));
}

/*
 * Display detailed analysis of a specific packet
 */
int inspect_analyze_packet(unsigned int packet_id) {
    const stored_packet_t* pkt = session_get_packet(packet_id);
    if (!pkt) {
        color_printf(COLOR_BRIGHT_RED, "Packet ID %u not found!\n", packet_id);
        return 0;
    }
    
    char timestamp[32];
    format_time_display(&pkt->timestamp, timestamp, sizeof(timestamp));
    
    color_printf(COLOR_BRIGHT_CYAN, "\n================================================================================\n");
    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "DETAILED PACKET ANALYSIS\n");
    color_printf(COLOR_BRIGHT_CYAN, "================================================================================\n");
    color_printf(COLOR_BRIGHT_WHITE, "Packet ID: %u | Timestamp: %s | Length: %u\n", 
             pkt->id, timestamp, pkt->length);
    color_printf(COLOR_BRIGHT_WHITE, "Captured: %u | Original: %u | Truncated: %s\n",
             pkt->caplen, pkt->length, (pkt->caplen < pkt->length) ? "Yes" : "No");
    color_printf(COLOR_BRIGHT_CYAN, "================================================================================\n\n");
    
    // Analyze Ethernet header
    analyze_ethernet_header(pkt->data, pkt->caplen);
    
    // Check for IP layer
    if (pkt->caplen >= sizeof(struct ethhdr)) {
        struct ethhdr* eth = (struct ethhdr*)pkt->data;
        unsigned short eth_type = ntohs(eth->h_proto);
        
        if (eth_type == ETH_P_IP) {
            unsigned int ip_offset = 0;
            analyze_ip_header(pkt->data, pkt->caplen, &ip_offset);
            
            // Check for transport layer
            if (pkt->caplen > ip_offset) {
                struct iphdr* ip = (struct iphdr*)(pkt->data + sizeof(struct ethhdr));
                
                if (ip->protocol == IPPROTO_TCP) {
                    analyze_tcp_header(pkt->data, pkt->caplen, ip_offset);
                } else if (ip->protocol == IPPROTO_UDP) {
                    analyze_udp_header(pkt->data, pkt->caplen, ip_offset);
                }
                
                // Show payload if present
                unsigned int payload_offset = ip_offset;
                if (ip->protocol == IPPROTO_TCP) {
                    struct tcphdr* tcp = (struct tcphdr*)(pkt->data + ip_offset);
                    payload_offset += tcp->doff * 4;
                } else if (ip->protocol == IPPROTO_UDP) {
                    payload_offset += sizeof(struct udphdr);
                }
                
                if (payload_offset < pkt->caplen) {
                    unsigned int payload_len = pkt->caplen - payload_offset;
                    color_printf(COLOR_BRIGHT_CYAN, "--------------------------------------------------------------------------------\n");
                    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "PAYLOAD DATA (%u bytes)\n", payload_len);
                    color_printf(COLOR_BRIGHT_CYAN, "--------------------------------------------------------------------------------\n");
                    
                    // Show first 128 bytes of payload in hex
                    unsigned int show_len = (payload_len > 128) ? 128 : payload_len;
                    for (unsigned int i = 0; i < show_len; i += 16) {
                        color_printf(COLOR_BRIGHT_BLUE, "%04X: ", i);
                        for (int j = 0; j < 16 && i + j < show_len; j++) {
                            color_printf(COLOR_BRIGHT_WHITE, "%02X ", pkt->data[payload_offset + i + j]);
                        }
                        color_printf(COLOR_BRIGHT_GREEN, " ");
                        for (int j = 0; j < 16 && i + j < show_len; j++) {
                            unsigned char c = pkt->data[payload_offset + i + j];
                            color_printf(COLOR_BRIGHT_GREEN, "%c", isprint(c) ? c : '.');
                        }
                        printf("\n");
                    }
                    if (payload_len > 128) {
                        color_printf(COLOR_BRIGHT_YELLOW, "... (%u more bytes)\n", payload_len - 128);
                    }
                    printf("\n");
                }
            }
        }
    }
    
    // Complete hex dump of entire packet
    inspect_hex_dump(pkt->data, pkt->caplen, 0);
    
    return 1;
}

/*
 * Interactive packet inspector interface
 */
int inspect_session_interactive(void) {
    const packet_session_t* session = session_get_current();
    if (!session || session->count == 0) {
        color_printf(COLOR_BRIGHT_RED, "No capture session available!\n");
        color_printf(COLOR_BRIGHT_YELLOW, "Start a packet capture first to inspect packets.\n");
        return 0;
    }
    
    // Show packet summary
    int packet_count = inspect_show_packet_summary();
    if (packet_count == 0) {
        return 0;
    }
    
    // Get user selection
    color_printf(COLOR_BRIGHT_CYAN, "Enter Packet ID to analyze (or 0 to return): ");
    
    char input[32];
    if (!fgets(input, sizeof(input), stdin)) {
        return 0;
    }
    
    unsigned int packet_id = (unsigned int)atoi(input);
    if (packet_id == 0) {
        color_printf(COLOR_BRIGHT_YELLOW, "Returning to main menu...\n\n");
        return 1;
    }
    
    // Analyze the selected packet
    if (!inspect_analyze_packet(packet_id)) {
        color_printf(COLOR_BRIGHT_RED, "Invalid packet ID. Please try again.\n\n");
        return 0;
    }
    
    // Wait for user acknowledgment
    color_printf(COLOR_BRIGHT_CYAN, "\nPress Enter to return to main menu...");
    getchar();
    
    return 1;
}