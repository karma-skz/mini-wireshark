/*
 * iface.h - Network interface discovery and selection for cshark
 * 
 * Contains functions for:
 * - Discovering available pcap devices
 * - Displaying device list to user
 * - Handling user interface selection
 */

#ifndef IFACE_H
#define IFACE_H

/*
 * Discover and display all available pcap interfaces
 * Shows numbered list with device names and descriptions
 * Returns: number of interfaces found, or -1 on error
 */
int discover_interfaces(void);

/*
 * Get user selection of interface from numbered list
 * interface_count: number of available interfaces (from discover_interfaces)
 * Returns: malloc'd string with selected device name, or NULL on error/EOF
 * Caller must free the returned string
 */
char* select_interface(int interface_count);

#endif /* IFACE_H */