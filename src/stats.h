/*
 * stats.h - Packet statistics tracking for cshark packet sniffer
 * 
 * Contains functions and structures for tracking packet counts
 * by protocol type and displaying summary statistics.
 */

#ifndef STATS_H
#define STATS_H

/*
 * Packet statistics structure
 * Tracks counts for each protocol layer
 */
typedef struct {
    unsigned long total_packets;
    unsigned long ethernet_packets;
    unsigned long ipv4_packets;
    unsigned long ipv6_packets;
    unsigned long arp_packets;
    unsigned long tcp_packets;
    unsigned long udp_packets;
    unsigned long icmp_packets;
    unsigned long dns_packets;
    unsigned long http_packets;
    unsigned long other_packets;
} packet_stats_t;

/*
 * Initialize statistics tracking
 * Resets all counters to zero
 */
void stats_init(void);

/*
 * Increment counter for a specific protocol
 * protocol: string identifier for the protocol
 */
void stats_increment(const char* protocol);

/*
 * Get current statistics structure
 * Returns: pointer to current stats (read-only)
 */
const packet_stats_t* stats_get(void);

/*
 * Print statistics summary
 * Displays formatted statistics output
 */
void stats_print_summary(void);

/*
 * Reset all statistics counters
 */
void stats_reset(void);

#endif /* STATS_H */