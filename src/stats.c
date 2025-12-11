/*
 * stats.c - Packet statistics tracking implementation for cshark
 * 
 * Maintains counters for different protocol types and provides
 * summary reporting functionality for packet capture analysis.
 */

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include "stats.h"
#include "utils.h"
#include <stdio.h>
#include <string.h>

/* Global statistics structure */
static packet_stats_t global_stats = {0};

/*
 * Initialize statistics tracking
 */
void stats_init(void) {
    memset(&global_stats, 0, sizeof(packet_stats_t));
}

/*
 * Increment counter for a specific protocol
 */
void stats_increment(const char* protocol) {
    if (!protocol) return;
    
    global_stats.total_packets++;
    
    if (strcmp(protocol, "ethernet") == 0) {
        global_stats.ethernet_packets++;
    } else if (strcmp(protocol, "ipv4") == 0) {
        global_stats.ipv4_packets++;
    } else if (strcmp(protocol, "ipv6") == 0) {
        global_stats.ipv6_packets++;
    } else if (strcmp(protocol, "arp") == 0) {
        global_stats.arp_packets++;
    } else if (strcmp(protocol, "tcp") == 0) {
        global_stats.tcp_packets++;
    } else if (strcmp(protocol, "udp") == 0) {
        global_stats.udp_packets++;
    } else if (strcmp(protocol, "icmp") == 0) {
        global_stats.icmp_packets++;
    } else if (strcmp(protocol, "dns") == 0) {
        global_stats.dns_packets++;
    } else if (strcmp(protocol, "http") == 0) {
        global_stats.http_packets++;
    } else {
        global_stats.other_packets++;
    }
}

/*
 * Get current statistics structure
 */
const packet_stats_t* stats_get(void) {
    return &global_stats;
}

/*
 * Print statistics summary
 */
void stats_print_summary(void) {
    log_printf("\n");
    
    /* Statistics header */
    color_printf(COLOR_BRIGHT_CYAN, "========================================\n");
    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "CAPTURE STATISTICS\n");
    color_printf(COLOR_BRIGHT_CYAN, "========================================\n");
    
    /* Total packets */
    color_printf(COLOR_BOLD COLOR_BRIGHT_YELLOW, "Total packets: ");
    color_printf(COLOR_BRIGHT_WHITE, "%lu\n", global_stats.total_packets);
    
    if (global_stats.total_packets > 0) {
        color_printf(COLOR_BRIGHT_CYAN, "----------------------------------------\n");
    }
    
    /* Protocol breakdown */
    if (global_stats.ethernet_packets > 0) {
        color_printf(COLOR_BRIGHT_GREEN, "  Ethernet: ");
        color_printf(COLOR_WHITE, "%lu\n", global_stats.ethernet_packets);
    }
    if (global_stats.ipv4_packets > 0) {
        color_printf(COLOR_BRIGHT_BLUE, "  IPv4: ");
        color_printf(COLOR_WHITE, "%lu\n", global_stats.ipv4_packets);
    }
    if (global_stats.ipv6_packets > 0) {
        color_printf(COLOR_BRIGHT_BLUE, "  IPv6: ");
        color_printf(COLOR_WHITE, "%lu\n", global_stats.ipv6_packets);
    }
    if (global_stats.arp_packets > 0) {
        color_printf(COLOR_BRIGHT_MAGENTA, "  ARP: ");
        color_printf(COLOR_WHITE, "%lu\n", global_stats.arp_packets);
    }
    if (global_stats.tcp_packets > 0) {
        color_printf(COLOR_BRIGHT_RED, "  TCP: ");
        color_printf(COLOR_WHITE, "%lu\n", global_stats.tcp_packets);
    }
    if (global_stats.udp_packets > 0) {
        color_printf(COLOR_BRIGHT_YELLOW, "  UDP: ");
        color_printf(COLOR_WHITE, "%lu\n", global_stats.udp_packets);
    }
    if (global_stats.icmp_packets > 0) {
        color_printf(COLOR_BRIGHT_WHITE, "  ICMP: ");
        color_printf(COLOR_WHITE, "%lu\n", global_stats.icmp_packets);
    }
    if (global_stats.dns_packets > 0) {
        color_printf(COLOR_BRIGHT_GREEN, "  DNS: ");
        color_printf(COLOR_WHITE, "%lu\n", global_stats.dns_packets);
    }
    if (global_stats.http_packets > 0) {
        color_printf(COLOR_BRIGHT_CYAN, "  HTTP: ");
        color_printf(COLOR_WHITE, "%lu\n", global_stats.http_packets);
    }
    if (global_stats.other_packets > 0) {
        color_printf(COLOR_DIM, "  Other: ");
        color_printf(COLOR_WHITE, "%lu\n", global_stats.other_packets);
    }
    
    color_printf(COLOR_BRIGHT_CYAN, "========================================\n");
}

/*
 * Reset all statistics counters
 */
void stats_reset(void) {
    stats_init();
}