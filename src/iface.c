/*
 * iface.c - Network interface discovery and selection implementation
 * 
 * Uses libpcap to discover available network interfaces and allows
 * user to select one for packet capture. Handles EOF gracefully.
 */

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include "iface.h"
#include "utils.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

/* Static storage for device list between discover and select calls */
static pcap_if_t* device_list = NULL;

/*
 * Discover and display all available pcap interfaces
 * Uses pcap_findalldevs to get device list and displays numbered options
 */
int discover_interfaces(void) {
    char errbuf[PCAP_ERRBUF_SIZE];
    
    color_printf(COLOR_BRIGHT_BLUE, "Searching for available interfaces... ");
    
    /* Free any previously stored device list */
    if (device_list) {
        pcap_freealldevs(device_list);
        device_list = NULL;
    }
    
    /* Get list of available devices */
    if (pcap_findalldevs(&device_list, errbuf) == -1) {
        color_printf(COLOR_BRIGHT_RED, "Error!\n");
        color_printf(COLOR_RED, "Error finding devices: %s\n", errbuf);
        return -1;
    }
    
    if (device_list == NULL) {
        color_printf(COLOR_BRIGHT_RED, "No devices found!\n");
        return 0;
    }
    
    color_printf(COLOR_BRIGHT_GREEN, "Found!\n\n");
    
    /* Header for interface list */
    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "Available Network Interfaces:\n");
    color_printf(COLOR_BRIGHT_CYAN, "================================================================\n");
    
    /* Display numbered list of devices */
    int count = 0;
    pcap_if_t* dev = device_list;
    
    while (dev) {
        count++;
        color_printf(COLOR_BRIGHT_YELLOW, "%2d. ", count);
        color_printf(COLOR_BRIGHT_WHITE, "%-20s", dev->name);
        
        /* Add description if available */
        if (dev->description && strlen(dev->description) > 0) {
            color_printf(COLOR_WHITE, " - %s", dev->description);
        } else {
            color_printf(COLOR_DIM, " - (No description)");
        }
        
        log_printf("\n");
        dev = dev->next;
    }
    
    color_printf(COLOR_BRIGHT_CYAN, "================================================================\n");
    
    return count;
}

/*
 * Get user selection of interface from numbered list
 * Prompts user and validates input, handles EOF
 */
char* select_interface(int interface_count) {
    if (interface_count <= 0 || !device_list) {
        return NULL;
    }
    
    char input_buffer[64];
    char prompt[128];
    
    snprintf(prompt, sizeof(prompt), 
             "Select an interface to sniff (1-%d): ", interface_count);
    
    /* Get user input */
    if (!safe_input_read(prompt, input_buffer, sizeof(input_buffer))) {
        /* EOF encountered (Ctrl+D) */
        if (device_list) {
            pcap_freealldevs(device_list);
            device_list = NULL;
        }
        return NULL;
    }
    
    /* Parse and validate selection */
    int selection = parse_int_range(input_buffer, 1, interface_count);
    if (selection == -1) {
        printf("Invalid selection. Please enter a number between 1 and %d.\n", 
               interface_count);
        return select_interface(interface_count); /* Recursive retry */
    }
    
    /* Find the selected device in the list */
    pcap_if_t* dev = device_list;
    for (int i = 1; i < selection && dev; i++) {
        dev = dev->next;
    }
    
    if (!dev) {
        printf("Error: Selected device not found.\n");
        return NULL;
    }
    
    /* Make a copy of the device name */
    char* device_name = malloc(strlen(dev->name) + 1);
    if (device_name) {
        strcpy(device_name, dev->name);
    }
    
    /* Free the device list as we no longer need it */
    pcap_freealldevs(device_list);
    device_list = NULL;
    
    return device_name;
}