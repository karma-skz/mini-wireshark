/*
 * filter.c - Packet filtering system implementation for cshark
 * 
 * Provides interactive protocol selection and BPF filter string
 * generation for common network protocols.
 */

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include "filter.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

/*
 * Display interactive protocol filter menu
 */
char* filter_show_menu(void) {
    log_printf("\n");
    
    /* Filter menu header */
    color_printf(COLOR_BRIGHT_CYAN, "================================================\n");
    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "SELECT PROTOCOL FILTER\n");
    color_printf(COLOR_BRIGHT_CYAN, "================================================\n");
    
    /* Filter options */
    color_printf(COLOR_BRIGHT_YELLOW, "1. ");
    color_printf(COLOR_BRIGHT_WHITE, "HTTP Traffic (port 80)\n");
    
    color_printf(COLOR_BRIGHT_YELLOW, "2. ");
    color_printf(COLOR_BRIGHT_WHITE, "HTTPS Traffic (port 443)\n");
    
    color_printf(COLOR_BRIGHT_YELLOW, "3. ");
    color_printf(COLOR_BRIGHT_WHITE, "DNS Traffic (port 53)\n");
    
    color_printf(COLOR_BRIGHT_YELLOW, "4. ");
    color_printf(COLOR_BRIGHT_WHITE, "ARP Packets\n");
    
    color_printf(COLOR_BRIGHT_YELLOW, "5. ");
    color_printf(COLOR_BRIGHT_WHITE, "TCP Packets\n");
    
    color_printf(COLOR_BRIGHT_YELLOW, "6. ");
    color_printf(COLOR_BRIGHT_WHITE, "UDP Packets\n");
    
    color_printf(COLOR_BRIGHT_YELLOW, "7. ");
    color_printf(COLOR_BRIGHT_WHITE, "HTTP Data Only (no handshakes)\n");
    
    color_printf(COLOR_BRIGHT_YELLOW, "8. ");
    color_printf(COLOR_BRIGHT_RED, "Cancel (No Filter)\n");
    
    color_printf(COLOR_BRIGHT_CYAN, "================================================\n");
    
    char input[64];
    if (!safe_input_read("Enter choice (1-8): ", input, sizeof(input))) {
        return NULL; /* EOF */
    }
    
    int choice = parse_int_range(input, 1, 8);
    
    switch (choice) {
        case 1:
            color_printf(COLOR_BRIGHT_GREEN, "Filter: HTTP traffic (port 80)\n");
            return strdup(filter_get_bpf_string(FILTER_HTTP));
        case 2:
            color_printf(COLOR_BRIGHT_GREEN, "Filter: HTTPS traffic (port 443)\n");
            return strdup(filter_get_bpf_string(FILTER_HTTPS));
        case 3:
            color_printf(COLOR_BRIGHT_GREEN, "Filter: DNS traffic (port 53)\n");
            return strdup(filter_get_bpf_string(FILTER_DNS));
        case 4:
            color_printf(COLOR_BRIGHT_GREEN, "Filter: ARP packets\n");
            return strdup(filter_get_bpf_string(FILTER_ARP));
        case 5:
            color_printf(COLOR_BRIGHT_GREEN, "Filter: TCP packets\n");
            return strdup(filter_get_bpf_string(FILTER_TCP));
        case 6:
            color_printf(COLOR_BRIGHT_GREEN, "Filter: UDP packets\n");
            return strdup(filter_get_bpf_string(FILTER_UDP));
        case 7:
            color_printf(COLOR_BRIGHT_YELLOW, "No filter applied\n");
            return NULL;
        default:
            color_printf(COLOR_BRIGHT_RED, "Invalid choice. No filter applied.\n");
            return NULL;
    }
}

/*
 * Get BPF filter string for a specific protocol
 */
const char* filter_get_bpf_string(filter_protocol_t protocol) {
    switch (protocol) {
        case FILTER_HTTP:
            return "tcp port 80";
        case FILTER_HTTPS:
            return "tcp port 443";
        case FILTER_DNS:
            return "udp port 53 or tcp port 53";
        case FILTER_ARP:
            return "arp";
        case FILTER_TCP:
            return "tcp";
        case FILTER_UDP:
            return "udp";
        default:
            return "";
    }
}

/*
 * Validate and test a BPF filter string
 */
int filter_validate_bpf(const char* filter) {
    if (!filter) {
        return 1; /* NULL filter is valid (no filter) */
    }
    
    pcap_t* handle = pcap_open_dead(DLT_EN10MB, 65536);
    if (!handle) {
        return 0;
    }
    
    struct bpf_program compiled_filter;
    int result = pcap_compile(handle, &compiled_filter, filter, 0, PCAP_NETMASK_UNKNOWN);
    
    if (result == 0) {
        pcap_freecode(&compiled_filter);
    }
    
    pcap_close(handle);
    
    return (result == 0);
}