/*
 * utils.c - Utility functions implementation for cshark packet sniffer
 * 
 * Provides helper functions for timestamp formatting, hex dumps, 
 * and safe input handling with proper EOF detection.
 */

#include "utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <stdarg.h>
#include <unistd.h>

/*
 * Convert struct timeval to formatted timestamp string
 * Format: "YYYY-MM-DD HH:MM:SS.microseconds"
 */
char* format_timestamp(const struct timeval* tv) {
    if (!tv) return NULL;
    
    char* result = malloc(32);
    if (!result) return NULL;
    
    struct tm* local_time = localtime(&tv->tv_sec);
    if (!local_time) {
        free(result);
        return NULL;
    }
    
    /* Format: YYYY-MM-DD HH:MM:SS.microseconds */
    snprintf(result, 32, "%04d-%02d-%02d %02d:%02d:%02d.%06ld",
             local_time->tm_year + 1900,
             local_time->tm_mon + 1,
             local_time->tm_mday,
             local_time->tm_hour,
             local_time->tm_min,
             local_time->tm_sec,
             tv->tv_usec);
    
    return result;
}

/*
 * Print hex dump of first n bytes of data
 * Prints in format: XX XX XX XX ... (space separated hex bytes)
 */
void print_hex_dump(const unsigned char* data, int len, int max_bytes) {
    if (!data || len <= 0) {
        printf("(no data)");
        return;
    }
    
    int bytes_to_print = (len < max_bytes) ? len : max_bytes;
    
    for (int i = 0; i < bytes_to_print; i++) {
        printf("%02X", data[i]);
        if (i < bytes_to_print - 1) {
            printf(" ");
        }
    }
}

/*
 * Safe input reading that handles EOF properly
 * Returns 1 on successful input, 0 on EOF (Ctrl+D)
 */
int safe_input_read(const char* prompt, char* buffer, int size) {
    if (!prompt || !buffer || size <= 0) return 0;
    
    printf("%s", prompt);
    fflush(stdout);
    
    if (fgets(buffer, size, stdin) == NULL) {
        /* EOF encountered (Ctrl+D) */
        return 0;
    }
    
    /* Remove trailing newline if present */
    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }
    
    return 1;
}

/*
 * Parse integer from string with bounds checking
 * Returns parsed integer or -1 if invalid/out of bounds
 */
int parse_int_range(const char* str, int min, int max) {
    if (!str) return -1;
    
    /* Skip leading whitespace */
    while (*str && isspace(*str)) str++;
    
    if (*str == '\0') return -1;
    
    char* endptr;
    long val = strtol(str, &endptr, 10);
    
    /* Check for conversion errors */
    if (*endptr != '\0') return -1;
    
    /* Check bounds */
    if (val < min || val > max) return -1;
    
    return (int)val;
}

/*
 * Format MAC address as XX:XX:XX:XX:XX:XX string
 */
char* format_mac_address(const unsigned char* mac) {
    if (!mac) return NULL;
    
    char* result = malloc(18); /* XX:XX:XX:XX:XX:XX + null */
    if (!result) return NULL;
    
    snprintf(result, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    
    return result;
}

/*
 * Get protocol name from ethernet type
 */
const char* get_ether_type_name(unsigned short ether_type) {
    switch (ether_type) {
        case 0x0800: return "IPv4";
        case 0x0806: return "ARP";
        case 0x86DD: return "IPv6";
        case 0x8100: return "VLAN";
        case 0x0842: return "Wake-on-LAN";
        default: return "Unknown";
    }
}

/*
 * Get protocol name from IP protocol number
 */
const char* get_ip_protocol_name(unsigned char protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 6: return "TCP";
        case 17: return "UDP";
        case 2: return "IGMP";
        case 41: return "IPv6";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        default: return "Unknown";
    }
}

/*
 * Get service name from port number
 */
const char* get_port_service(unsigned short port) {
    switch (port) {
        case 20: return "ftp-data";
        case 21: return "ftp";
        case 22: return "ssh";
        case 23: return "telnet";
        case 25: return "smtp";
        case 53: return "dns";
        case 67: return "dhcp-server";
        case 68: return "dhcp-client";
        case 80: return "http";
        case 110: return "pop3";
        case 143: return "imap";
        case 443: return "https";
        case 993: return "imaps";
        case 995: return "pop3s";
        default: return "unknown";
    }
}

/*
 * Format IP flags into readable string
 */
char* format_ip_flags(unsigned short flags) {
    char* result = malloc(64);
    if (!result) return NULL;
    
    result[0] = '\0';
    
    if (flags & 0x4000) { /* Don't Fragment */
        strcat(result, "DF ");
    }
    if (flags & 0x2000) { /* More Fragments */
        strcat(result, "MF ");
    }
    if (flags & 0x8000) { /* Reserved bit */
        strcat(result, "RF ");
    }
    
    /* Remove trailing space */
    size_t len = strlen(result);
    if (len > 0 && result[len-1] == ' ') {
        result[len-1] = '\0';
    }
    
    if (result[0] == '\0') {
        strcpy(result, "None");
    }
    
    return result;
}

/* Global log file pointer */
static FILE* log_file = NULL;

/*
 * Set log file for output redirection
 */
int log_set_file(const char* filename) {
    if (log_file && log_file != stdout) {
        fclose(log_file);
    }
    
    if (!filename) {
        log_file = stdout;
        return 1;
    }
    
    log_file = fopen(filename, "a");
    if (!log_file) {
        log_file = stdout;
        return 0;
    }
    
    return 1;
}

/*
 * Close log file and reset to stdout
 */
void log_close(void) {
    if (log_file && log_file != stdout) {
        fclose(log_file);
    }
    log_file = stdout;
}

/*
 * Print to both stdout and log file (if set)
 */
int log_printf(const char* format, ...) {
    va_list args1, args2;
    int result = 0;
    
    /* Print to stdout */
    va_start(args1, format);
    result = vprintf(format, args1);
    va_end(args1);
    fflush(stdout);
    
    /* Also print to log file if it's different from stdout */
    if (log_file && log_file != stdout) {
        va_start(args2, format);
        vfprintf(log_file, format, args2);
        va_end(args2);
        fflush(log_file);
    }
    
    return result;
}

/*
 * Get current log file pointer
 */
FILE* log_get_file(void) {
    return log_file ? log_file : stdout;
}

/* Global color support flag */
static int color_supported = -1; /* -1 = not checked, 0 = no, 1 = yes */

/*
 * Check if terminal supports colors
 */
int terminal_supports_color(void) {
    if (color_supported != -1) {
        return color_supported;
    }
    
    /* Check if stdout is a terminal and TERM is set */
    const char* term = getenv("TERM");
    if (isatty(STDOUT_FILENO) && term && strcmp(term, "dumb") != 0) {
        color_supported = 1;
    } else {
        color_supported = 0;
    }
    
    return color_supported;
}

/*
 * Print colored text (wrapper around log_printf)
 */
int color_printf(const char* color, const char* format, ...) {
    va_list args;
    int result = 0;
    
    /* Only use colors if terminal supports them */
    if (terminal_supports_color()) {
        log_printf("%s", color);
    }
    
    va_start(args, format);
    char buffer[1024];
    vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    
    result = log_printf("%s", buffer);
    
    /* Reset color if terminal supports colors */
    if (terminal_supports_color()) {
        log_printf("%s", COLOR_RESET);
    }
    
    return result;
}

/*
 * Print a decorative border
 */
void print_border(int width, char style) {
    for (int i = 0; i < width; i++) {
        log_printf("%c", style);
    }
    log_printf("\n");
}

/*
 * Print centered text within a width
 */
void print_centered(const char* text, int width) {
    int text_len = strlen(text);
    int padding = (width - text_len) / 2;
    
    for (int i = 0; i < padding; i++) {
        log_printf(" ");
    }
    log_printf("%s", text);
    for (int i = 0; i < (width - text_len - padding); i++) {
        log_printf(" ");
    }
    log_printf("\n");
}

/*
 * Clear terminal screen
 */
void clear_screen(void) {
    if (terminal_supports_color()) {
        log_printf("\033[2J\033[H");
    } else {
        log_printf("\n\n\n"); /* Fallback for non-ANSI terminals */
    }
}

/*
 * Move cursor to specific position
 */
void move_cursor(int row, int col) {
    if (terminal_supports_color()) {
        log_printf("\033[%d;%dH", row, col);
    }
}