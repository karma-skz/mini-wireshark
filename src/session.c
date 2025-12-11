/*
 * session.c - Packet session storage implementation for cshark
 * 
 * Manages packet storage for capture sessions with proper memory
 * management and session lifecycle handling.
 */

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include "session.h"
#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Global session storage */
static packet_session_t current_session = {0};
static int session_initialized = 0;

/*
 * Initialize session storage system
 */
void session_init(void) {
    if (session_initialized) {
        session_clear();
    }
    
    memset(&current_session, 0, sizeof(packet_session_t));
    current_session.capacity = MAX_PACKETS;
    session_initialized = 1;
}

/*
 * Start a new capture session
 */
void session_start(const char* interface, const char* filter) {
    if (!session_initialized) {
        session_init();
    }
    
    /* Clear any existing session */
    session_clear();
    
    /* Allocate packet array */
    current_session.packets = calloc(MAX_PACKETS, sizeof(stored_packet_t));
    if (!current_session.packets) {
        color_printf(COLOR_BRIGHT_RED, "Error: Could not allocate memory for packet storage\n");
        return;
    }
    
    /* Set session parameters */
    current_session.count = 0;
    current_session.capacity = MAX_PACKETS;
    
    if (interface) {
        current_session.interface_name = strdup(interface);
    }
    
    if (filter) {
        current_session.filter_string = strdup(filter);
    }
    
    /* Record start time */
    gettimeofday(&current_session.start_time, NULL);
    
    color_printf(COLOR_BRIGHT_GREEN, "📦 Session started - storing up to %d packets\n", MAX_PACKETS);
}

/*
 * Add a packet to the current session
 */
int session_add_packet(unsigned int packet_id, 
                      const struct pcap_pkthdr* pkthdr,
                      const unsigned char* packet_data,
                      const char* summary) {
    
    if (!session_initialized || !current_session.packets) {
        return 0;
    }
    
    if (current_session.count >= current_session.capacity) {
        /* Session is full - could implement circular buffer here */
        return 0;
    }
    
    stored_packet_t* pkt = &current_session.packets[current_session.count];
    
    /* Store packet metadata */
    pkt->id = packet_id;
    pkt->timestamp = pkthdr->ts;
    pkt->length = pkthdr->len;
    pkt->caplen = pkthdr->caplen;
    
    /* Allocate and copy packet data */
    pkt->data = malloc(pkthdr->caplen);
    if (!pkt->data) {
        return 0;
    }
    memcpy(pkt->data, packet_data, pkthdr->caplen);
    
    /* Store summary if provided */
    if (summary) {
        pkt->summary = strdup(summary);
    }
    
    current_session.count++;
    return 1;
}

/*
 * End the current capture session
 */
void session_end(void) {
    if (!session_initialized) {
        return;
    }
    
    /* Record end time */
    gettimeofday(&current_session.end_time, NULL);
    
    color_printf(COLOR_BRIGHT_BLUE, "📦 Session ended - %d packets stored\n", current_session.count);
}

/*
 * Get the current session
 */
const packet_session_t* session_get_current(void) {
    if (!session_initialized || current_session.count == 0) {
        return NULL;
    }
    return &current_session;
}

/*
 * Get a specific packet from the current session
 */
const stored_packet_t* session_get_packet(unsigned int packet_id) {
    if (!session_initialized || !current_session.packets) {
        return NULL;
    }
    
    /* Linear search for packet ID */
    for (unsigned int i = 0; i < current_session.count; i++) {
        if (current_session.packets[i].id == packet_id) {
            return &current_session.packets[i];
        }
    }
    
    return NULL;
}

/*
 * Clear the current session and free all memory
 */
void session_clear(void) {
    if (!session_initialized) {
        return;
    }
    
    /* Free packet data and summaries */
    if (current_session.packets) {
        for (unsigned int i = 0; i < current_session.count; i++) {
            free(current_session.packets[i].data);
            free(current_session.packets[i].summary);
        }
        free(current_session.packets);
    }
    
    /* Free session strings */
    free(current_session.interface_name);
    free(current_session.filter_string);
    
    /* Reset session */
    memset(&current_session, 0, sizeof(packet_session_t));
    current_session.capacity = MAX_PACKETS;
}

/*
 * Get session statistics
 */
unsigned int session_get_packet_count(void) {
    if (!session_initialized) {
        return 0;
    }
    return current_session.count;
}

/*
 * Check if a session exists
 */
int session_exists(void) {
    return session_initialized && current_session.count > 0;
}