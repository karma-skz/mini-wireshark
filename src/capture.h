/*
 * capture.h - Packet capture functionality for cshark
 * 
 * Contains functions for:
 * - Opening pcap devices for capture
 * - Setting up signal handlers for graceful Ctrl+C handling
 * - Packet capture loop with callback
 * - Structured packet decoding (L2/L3/L4)
 */

#ifndef CAPTURE_H
#define CAPTURE_H

#include <pcap.h>

/*
 * Start packet capture on specified device
 * device_name: name of network device to capture on
 * filter_string: BPF filter string (optional, can be NULL)
 * enable_hexdump: 1 to enable hex dump of payload, 0 to disable
 * Returns: 0 on success, -1 on error
 * 
 * This function:
 * - Opens the device with pcap_open_live
 * - Sets up signal handler for Ctrl+C
 * - Applies BPF filter if provided
 * - Starts capture loop until interrupted
 * - Returns to caller when capture stops
 */
int start_capture(const char* device_name, const char* filter_string, int enable_hexdump);

/*
 * Set up signal handler for graceful capture interruption
 * Must be called before starting capture loop
 */
void setup_signal_handler(void);

/*
 * Clean up capture resources
 * Called automatically when capture ends or is interrupted
 */
void cleanup_capture(void);

/*
 * Decode and display Layer 2 (Ethernet) header
 * packet: packet data
 * length: packet length
 * Returns: size of ethernet header, or -1 on error
 */
int decode_ethernet(const unsigned char* packet, int length);

/*
 * Decode and display Layer 3 headers (IPv4/IPv6/ARP)
 * packet: packet data starting at L3 header
 * length: remaining packet length
 * ether_type: ethernet type from L2 header
 * Returns: size of L3 header, or -1 on error
 */
int decode_layer3(const unsigned char* packet, int length, unsigned short ether_type);

/*
 * Decode and display Layer 4 headers (TCP/UDP)
 * packet: packet data starting at L4 header
 * length: remaining packet length
 * protocol: IP protocol number
 * Returns: size of L4 header, or -1 on error
 */
int decode_layer4(const unsigned char* packet, int length, unsigned char protocol);

#endif /* CAPTURE_H */