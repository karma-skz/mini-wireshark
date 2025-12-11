/*
 * icmp.h - ICMP protocol decoding for cshark packet sniffer
 * 
 * Contains functions for decoding ICMP and ICMPv6 headers
 * with human-readable type and code descriptions.
 */

#ifndef ICMP_H
#define ICMP_H

/*
 * Decode and display ICMP header (IPv4)
 * packet: packet data starting at ICMP header
 * length: remaining packet length
 * Returns: size of ICMP header, or -1 on error
 */
int decode_icmp(const unsigned char* packet, int length);

/*
 * Decode and display ICMPv6 header (IPv6)
 * packet: packet data starting at ICMPv6 header
 * length: remaining packet length
 * Returns: size of ICMPv6 header, or -1 on error
 */
int decode_icmpv6(const unsigned char* packet, int length);

/*
 * Get human-readable description of ICMP type and code
 * type: ICMP type field
 * code: ICMP code field
 * Returns: string description of the ICMP message
 */
const char* get_icmp_type_description(unsigned char type, unsigned char code);

/*
 * Get human-readable description of ICMPv6 type and code
 * type: ICMPv6 type field
 * code: ICMPv6 code field
 * Returns: string description of the ICMPv6 message
 */
const char* get_icmpv6_type_description(unsigned char type, unsigned char code);

#endif /* ICMP_H */