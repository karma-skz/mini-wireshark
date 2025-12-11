/*
 * utils.h - Utility functions for cshark packet sniffer
 * 
 * Contains helper functions for:
 * - Formatted timestamp conversion
 * - Hex dump output
 * - Safe input reading with EOF handling
 */

#ifndef UTILS_H
#define UTILS_H

#include <sys/time.h>
#include <stdio.h>

/*
 * Convert struct timeval to formatted timestamp string
 * Returns: malloc'd string with format "YYYY-MM-DD HH:MM:SS.microseconds"
 * Caller must free the returned string
 */
char* format_timestamp(const struct timeval* tv);

/*
 * Print hex dump of first n bytes of data
 * data: pointer to data buffer
 * len: total length of data available
 * max_bytes: maximum number of bytes to print (typically 16)
 */
void print_hex_dump(const unsigned char* data, int len, int max_bytes);

/*
 * Safe input reading that handles EOF properly
 * prompt: string to display as prompt
 * buffer: buffer to store input
 * size: size of buffer
 * Returns: 1 on success, 0 on EOF (Ctrl+D)
 */
int safe_input_read(const char* prompt, char* buffer, int size);

/*
 * Parse integer from string with bounds checking
 * str: input string
 * min: minimum allowed value
 * max: maximum allowed value
 * Returns: parsed integer, or -1 if invalid/out of bounds
 */
int parse_int_range(const char* str, int min, int max);

/*
 * Format MAC address as XX:XX:XX:XX:XX:XX string
 * mac: 6-byte MAC address array
 * Returns: malloc'd formatted string, caller must free
 */
char* format_mac_address(const unsigned char* mac);

/*
 * Get protocol name from ethernet type
 * ether_type: ethernet type value (network byte order)
 * Returns: string description of protocol
 */
const char* get_ether_type_name(unsigned short ether_type);

/*
 * Get protocol name from IP protocol number
 * protocol: IP protocol number
 * Returns: string description of protocol
 */
const char* get_ip_protocol_name(unsigned char protocol);

/*
 * Get service name from port number
 * port: port number
 * Returns: string description of common service, or "Unknown" if not recognized
 */
const char* get_port_service(unsigned short port);

/*
 * Format IP flags into readable string
 * flags: IP header flags field
 * Returns: malloc'd string with flag descriptions, caller must free
 */
char* format_ip_flags(unsigned short flags);

/*
 * Set log file for output redirection
 * filename: path to log file, or NULL for stdout only
 * Returns: 1 on success, 0 on failure
 */
int log_set_file(const char* filename);

/*
 * Close log file and reset to stdout
 */
void log_close(void);

/*
 * Print to both stdout and log file (if set)
 * Works like printf
 */
int log_printf(const char* format, ...);

/*
 * Get current log file pointer (for external use)
 * Returns: FILE* for current log destination
 */
FILE* log_get_file(void);

/* ANSI Color Codes */
#define COLOR_RESET     "\033[0m"
#define COLOR_BOLD      "\033[1m"
#define COLOR_DIM       "\033[2m"
#define COLOR_UNDERLINE "\033[4m"

/* Foreground Colors */
#define COLOR_BLACK     "\033[30m"
#define COLOR_RED       "\033[31m"
#define COLOR_GREEN     "\033[32m"
#define COLOR_YELLOW    "\033[33m"
#define COLOR_BLUE      "\033[34m"
#define COLOR_MAGENTA   "\033[35m"
#define COLOR_CYAN      "\033[36m"
#define COLOR_WHITE     "\033[37m"

/* Bright Colors */
#define COLOR_BRIGHT_RED     "\033[91m"
#define COLOR_BRIGHT_GREEN   "\033[92m"
#define COLOR_BRIGHT_YELLOW  "\033[93m"
#define COLOR_BRIGHT_BLUE    "\033[94m"
#define COLOR_BRIGHT_MAGENTA "\033[95m"
#define COLOR_BRIGHT_CYAN    "\033[96m"
#define COLOR_BRIGHT_WHITE   "\033[97m"

/* Background Colors */
#define BG_BLACK        "\033[40m"
#define BG_RED          "\033[41m"
#define BG_GREEN        "\033[42m"
#define BG_YELLOW       "\033[43m"
#define BG_BLUE         "\033[44m"
#define BG_MAGENTA      "\033[45m"
#define BG_CYAN         "\033[46m"
#define BG_WHITE        "\033[47m"

/*
 * Check if terminal supports colors
 * Returns: 1 if colors supported, 0 otherwise
 */
int terminal_supports_color(void);

/*
 * Print colored text (wrapper around log_printf)
 * color: ANSI color code
 * format: printf-style format string
 */
int color_printf(const char* color, const char* format, ...);

/*
 * Print a decorative border
 * width: width of border
 * style: character to use for border
 */
void print_border(int width, char style);

/*
 * Print centered text within a width
 * text: text to center
 * width: total width
 */
void print_centered(const char* text, int width);

/*
 * Clear terminal screen
 */
void clear_screen(void);

/*
 * Move cursor to specific position
 * row: row number (1-based)
 * col: column number (1-based)
 */
void move_cursor(int row, int col);

#endif /* UTILS_H */