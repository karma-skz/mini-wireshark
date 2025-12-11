/*
 * session.h - Packet session storage and management for cshark
 * 
 * Contains functions and structures for storing packets from capture
 * sessions and providing access for later inspection.
 */

#ifndef SESSION_H
#define SESSION_H

#include <pcap.h>
#include <sys/time.h>

/* Maximum number of packets to store per session */
#define MAX_PACKETS 10000

/*
 * Stored packet structure
 * Contains all information needed to reconstruct packet details
 */
typedef struct {
    unsigned int id;                    /* Packet ID */
    struct timeval timestamp;           /* Capture timestamp */
    unsigned int length;                /* Original packet length */
    unsigned int caplen;                /* Captured length */
    unsigned char* data;                /* Packet data (malloc'd) */
    char* summary;                      /* Brief packet summary (malloc'd) */
} stored_packet_t;

/*
 * Session structure
 * Manages the collection of packets from a capture session
 */
typedef struct {
    stored_packet_t* packets;           /* Array of stored packets */
    unsigned int count;                 /* Number of packets stored */
    unsigned int capacity;              /* Maximum capacity (MAX_PACKETS) */
    char* interface_name;               /* Interface used for capture */
    char* filter_string;                /* Filter applied (if any) */
    struct timeval start_time;          /* Session start time */
    struct timeval end_time;            /* Session end time */
} packet_session_t;

/*
 * Initialize session storage system
 * Must be called before using any other session functions
 */
void session_init(void);

/*
 * Start a new capture session
 * Clears any existing session and prepares for new packets
 * interface: name of the interface being captured on
 * filter: filter string applied (NULL if none)
 */
void session_start(const char* interface, const char* filter);

/*
 * Add a packet to the current session
 * packet_id: unique packet identifier
 * pkthdr: pcap packet header structure
 * packet_data: raw packet data
 * summary: brief text summary of packet (will be copied)
 * Returns: 1 if added successfully, 0 if session full
 */
int session_add_packet(unsigned int packet_id, 
                      const struct pcap_pkthdr* pkthdr,
                      const unsigned char* packet_data,
                      const char* summary);

/*
 * End the current capture session
 * Records the end time and finalizes the session
 */
void session_end(void);

/*
 * Get the current session
 * Returns: pointer to current session, or NULL if no session exists
 */
const packet_session_t* session_get_current(void);

/*
 * Get a specific packet from the current session
 * packet_id: ID of the packet to retrieve
 * Returns: pointer to packet, or NULL if not found
 */
const stored_packet_t* session_get_packet(unsigned int packet_id);

/*
 * Clear the current session and free all memory
 * Called automatically when starting a new session
 */
void session_clear(void);

/*
 * Get session statistics
 * Returns: number of packets in current session
 */
unsigned int session_get_packet_count(void);

/*
 * Check if a session exists
 * Returns: 1 if session exists, 0 otherwise
 */
int session_exists(void);

#endif /* SESSION_H */