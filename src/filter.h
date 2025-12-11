/*
 * filter.h - Packet filtering system for cshark
 * 
 * Contains functions for building BPF filter strings based on
 * user-selected protocols and managing filter operations.
 */

#ifndef FILTER_H
#define FILTER_H

/*
 * Supported filter protocols
 */
typedef enum {
    FILTER_HTTP = 1,
    FILTER_HTTPS,
    FILTER_DNS,
    FILTER_ARP,
    FILTER_TCP,
    FILTER_UDP
} filter_protocol_t;

/*
 * Display interactive protocol filter menu
 * Returns: malloc'd BPF filter string, or NULL if user cancels
 * Caller must free the returned string
 */
char* filter_show_menu(void);

/*
 * Get BPF filter string for a specific protocol
 * protocol: protocol to filter for
 * Returns: static BPF filter string
 */
const char* filter_get_bpf_string(filter_protocol_t protocol);

/*
 * Validate and test a BPF filter string
 * filter: BPF filter string to validate
 * Returns: 1 if valid, 0 if invalid
 */
int filter_validate_bpf(const char* filter);

#endif /* FILTER_H */