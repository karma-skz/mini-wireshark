/*
 * http.c - Basic HTTP protocol parsing implementation for cshark
 * 
 * Provides basic HTTP header detection and parsing for TCP payloads
 * on common HTTP ports. Does not handle reassembly - only parses
 * what's visible in the current packet segment.
 */

#include "http.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "utils.h"
#include "stats.h"

/* Common HTTP ports */
#define HTTP_PORT 80
#define HTTP_ALT_PORT 8080
#define HTTPS_PORT 443

/*
 * Check if TCP ports indicate potential HTTP traffic
 */
int is_http_port(unsigned short src_port, unsigned short dst_port) {
    return (src_port == HTTP_PORT || src_port == HTTP_ALT_PORT || src_port == HTTPS_PORT ||
            dst_port == HTTP_PORT || dst_port == HTTP_ALT_PORT || dst_port == HTTPS_PORT);
}

/*
 * Check if payload starts with HTTP request method
 */
int is_http_request(const unsigned char* payload, int length) {
    if (!payload || length < 4) return 0;
    
    /* Common HTTP methods */
    const char* methods[] = {"GET ", "POST ", "HEAD ", "PUT ", "DELETE ", 
                            "OPTIONS ", "TRACE ", "CONNECT ", "PATCH "};
    int method_count = sizeof(methods) / sizeof(methods[0]);
    
    for (int i = 0; i < method_count; i++) {
        int method_len = strlen(methods[i]);
        if (length >= method_len && 
            strncmp((const char*)payload, methods[i], method_len) == 0) {
            return 1;
        }
    }
    
    return 0;
}

/*
 * Check if payload starts with HTTP response
 */
int is_http_response(const unsigned char* payload, int length) {
    if (!payload || length < 8) return 0;
    
    /* HTTP response starts with "HTTP/1." or "HTTP/2" */
    return (strncmp((const char*)payload, "HTTP/1.", 7) == 0 ||
            strncmp((const char*)payload, "HTTP/2", 6) == 0);
}

/*
 * Find end of line in payload data
 */
static int find_line_end(const unsigned char* payload, int start, int length) {
    for (int i = start; i < length - 1; i++) {
        if (payload[i] == '\r' && payload[i + 1] == '\n') {
            return i;
        }
        if (payload[i] == '\n') {
            return i;
        }
    }
    return -1;
}

/*
 * Print HTTP header line safely (handles non-printable characters)
 */
static void print_http_line(const unsigned char* payload, int start, int end) {
    log_printf("           ");
    for (int i = start; i < end && i < start + 200; i++) { /* Limit line length */
        if (isprint(payload[i]) || payload[i] == ' ' || payload[i] == '\t') {
            log_printf("%c", payload[i]);
        } else if (payload[i] == '\r' || payload[i] == '\n') {
            break;
        } else {
            log_printf(".");
        }
    }
    log_printf("\n");
}

/*
 * Parse and display HTTP headers
 */
int parse_http_headers(const unsigned char* payload, int length, int is_request) {
    int pos = 0;
    int line_count = 0;
    const int max_lines = 10; /* Limit number of header lines to display */
    
    log_printf("L7 (HTTP): %s detected\n", is_request ? "Request" : "Response");
    stats_increment("http");
    
    while (pos < length && line_count < max_lines) {
        int line_end = find_line_end(payload, pos, length);
        
        if (line_end == -1) {
            /* No complete line found */
            break;
        }
        
        /* Check for empty line (end of headers) */
        if (line_end == pos || (line_end == pos + 1 && payload[pos] == '\r')) {
            log_printf("           [End of HTTP headers]\n");
            return line_end + (payload[line_end] == '\r' ? 2 : 1);
        }
        
        /* Print the header line */
        print_http_line(payload, pos, line_end);
        
        /* Move to next line */
        pos = line_end + (payload[line_end] == '\r' ? 2 : 1);
        line_count++;
    }
    
    if (line_count >= max_lines) {
        log_printf("           [... more headers truncated ...]\n");
    }
    
    return pos;
}

/*
 * Detect and parse HTTP headers from TCP payload
 */
int decode_http(const unsigned char* payload, int length, 
                unsigned short src_port, unsigned short dst_port) {
    
    /* Only check packets on HTTP ports */
    if (!is_http_port(src_port, dst_port)) {
        return 0;
    }
    
    /* Must have some minimum payload */
    if (!payload || length < 10) {
        return 0;
    }
    
    /* Check for HTTP request */
    if (is_http_request(payload, length)) {
        return parse_http_headers(payload, length, 1);
    }
    
    /* Check for HTTP response */
    if (is_http_response(payload, length)) {
        return parse_http_headers(payload, length, 0);
    }
    
    /* Not HTTP or not recognizable */
    return 0;
}