/*
 * inspect.h - Detailed packet inspection and analysis for cshark
 * 
 * Provides comprehensive packet analysis including hex dumps,
 * layer-by-layer breakdown, and human-readable interpretation
 * of packet contents for debugging and educational purposes.
 */

#ifndef INSPECT_H
#define INSPECT_H

#include "session.h"

/*
 * Display a summary table of all packets in the current session
 * Shows: Packet ID, Timestamp, Length, Protocol, Source/Dest info
 * Returns: number of packets displayed
 */
int inspect_show_packet_summary(void);

/*
 * Display detailed analysis of a specific packet
 * Includes: Layer-by-layer breakdown, hex dump, human-readable interpretation
 * packet_id: ID of the packet to analyze
 * Returns: 1 if successful, 0 if packet not found
 */
int inspect_analyze_packet(unsigned int packet_id);

/*
 * Display a hex dump of packet data
 * data: raw packet data
 * length: length of data to display
 * offset: starting offset for addressing
 */
void inspect_hex_dump(const unsigned char* data, unsigned int length, unsigned int offset);

/*
 * Interactive packet inspector interface
 * Shows packet list, handles user selection, displays detailed analysis
 * Returns: 1 if session inspected successfully, 0 if no session or error
 */
int inspect_session_interactive(void);

#endif /* INSPECT_H */