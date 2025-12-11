/*
 * main.c - cshark: Terminal Packet Sniffer
 * 
 * A simple packet sniffer using libpcap for educational purposes.
 * 
 * COMPILE: make
 * RUN: sudo ./cshark
 * 
 * Features (Phase 1):
 * - Network interface discovery and selection
 * - Basic packet capture with timestamp and hex dump
 * - Graceful Ctrl+C handling (returns to menu, doesn't exit)
 * - EOF (Ctrl+D) handling (exits program cleanly)
 * 
 * Requirements:
 * - libpcap development headers (apt install libpcap-dev)
 * - Root privileges for packet capture
 * 
 * Author: C-Shark Development Team
 * Standard: C99
 */

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include "iface.h"
#include "capture.h"
#include "utils.h"
#include "stats.h"
#include "session.h"
#include "filter.h"
#include "inspect.h"

/* Program constants */
#define PROGRAM_NAME "C-Shark"
#define VERSION "1.0 (Final)"

/* Global configuration */
typedef struct {
    char* interface_name;
    char* filter_string;
    char* log_filename;
    int enable_hexdump;
    int interactive_mode;
} config_t;

/* Forward declarations */
static void show_session_inspector(void);

/*
 * Display program banner and version information
 */
static void print_banner(void) {
    log_printf("\n");
    
    /* Top border */
    color_printf(COLOR_BRIGHT_CYAN, "╔");
    for (int i = 0; i < 58; i++) {
        color_printf(COLOR_BRIGHT_CYAN, "═");
    }
    color_printf(COLOR_BRIGHT_CYAN, "╗\n");
    
    /* Title line */
    color_printf(COLOR_BRIGHT_CYAN, "║");
    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "                     C-SHARK                      ");
    color_printf(COLOR_BRIGHT_CYAN, "║\n");
    

    /* Subtitle line */
    color_printf(COLOR_BRIGHT_CYAN, "║");
    color_printf(COLOR_BRIGHT_YELLOW, "            Terminal Packet Sniffer v%s          ", VERSION);
    color_printf(COLOR_BRIGHT_CYAN, "║\n");
    
    /* Author line */
    color_printf(COLOR_BRIGHT_CYAN, "║");
    color_printf(COLOR_DIM COLOR_WHITE, "              Advanced Network Analysis Tool              ");
    color_printf(COLOR_BRIGHT_CYAN, "║\n");
    
    /* Bottom border */
    color_printf(COLOR_BRIGHT_CYAN, "╚");
    for (int i = 0; i < 58; i++) {
        color_printf(COLOR_BRIGHT_CYAN, "═");
    }
    color_printf(COLOR_BRIGHT_CYAN, "╝\n\n");
}

/*
 * Display usage information
 */
static void print_usage(const char* prog_name) {
    print_banner();
    
    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "USAGE\n");
    color_printf(COLOR_BRIGHT_GREEN, "  %s ", prog_name);
    color_printf(COLOR_BRIGHT_YELLOW, "[OPTIONS]\n\n");
    
    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "OPTIONS\n");
    color_printf(COLOR_BRIGHT_CYAN, "  -i ");
    color_printf(COLOR_YELLOW, "INTERFACE   ");
    color_printf(COLOR_WHITE, "Select network interface directly\n");
    
    color_printf(COLOR_BRIGHT_CYAN, "  -f ");
    color_printf(COLOR_YELLOW, "FILTER      ");
    color_printf(COLOR_WHITE, "Apply BPF filter (e.g., \"tcp port 80\")\n");
    
    color_printf(COLOR_BRIGHT_CYAN, "  -x             ");
    color_printf(COLOR_WHITE, "Enable hexdump of packet payload\n");
    
    color_printf(COLOR_BRIGHT_CYAN, "  -o ");
    color_printf(COLOR_YELLOW, "FILE        ");
    color_printf(COLOR_WHITE, "Log output to file\n");
    
    color_printf(COLOR_BRIGHT_CYAN, "  -h             ");
    color_printf(COLOR_WHITE, "Show this help message\n\n");
    
    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "EXAMPLES\n");
    color_printf(COLOR_DIM COLOR_WHITE, "  # Capture HTTP traffic with hexdump and logging\n");
    color_printf(COLOR_BRIGHT_GREEN, "  %s ", prog_name);
    color_printf(COLOR_BRIGHT_YELLOW, "-i eth0 -f \"tcp port 80\" -x -o capture.log\n\n");
    
    color_printf(COLOR_DIM COLOR_WHITE, "  # Monitor all interfaces with hexdump\n");
    color_printf(COLOR_BRIGHT_GREEN, "  %s ", prog_name);
    color_printf(COLOR_BRIGHT_YELLOW, "-i any -x\n\n");
    
    color_printf(COLOR_DIM COLOR_WHITE, "  # Interactive mode (default)\n");
    color_printf(COLOR_BRIGHT_GREEN, "  %s\n\n", prog_name);
}

/*
 * Parse command line arguments
 */
static void parse_arguments(int argc, char* argv[], config_t* config) {
    int opt;
    
    /* Initialize config with defaults */
    config->interface_name = NULL;
    config->filter_string = NULL;
    config->log_filename = NULL;
    config->enable_hexdump = 0;
    config->interactive_mode = 1;
    
    while ((opt = getopt(argc, argv, "i:f:xo:h")) != -1) {
        switch (opt) {
            case 'i':
                config->interface_name = strdup(optarg);
                config->interactive_mode = 0;
                break;
            case 'f':
                config->filter_string = strdup(optarg);
                break;
            case 'x':
                config->enable_hexdump = 1;
                break;
            case 'o':
                config->log_filename = strdup(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                exit(EXIT_SUCCESS);
                break;
            default:
                print_usage(argv[0]);
                exit(EXIT_FAILURE);
        }
    }
}

/*
 * Display main menu after interface selection
 * Returns: 1 if menu should continue, 0 if exit requested
 */
static int show_main_menu(const char* selected_device, const config_t* config) {
    log_printf("\n");
    
    /* Menu header */
    color_printf(COLOR_BRIGHT_CYAN, "================================================\n");
    color_printf(COLOR_BOLD COLOR_BRIGHT_WHITE, "Interface: ");
    color_printf(COLOR_BRIGHT_GREEN, "%s\n", selected_device);
    color_printf(COLOR_BRIGHT_CYAN, "================================================\n");
    
    /* Menu options */
    color_printf(COLOR_BRIGHT_YELLOW, "1. ");
    color_printf(COLOR_BRIGHT_WHITE, "Start Sniffing (All Packets)\n");
    
    color_printf(COLOR_BRIGHT_YELLOW, "2. ");
    color_printf(COLOR_BRIGHT_WHITE, "Start Sniffing (With Filters)\n");
    
    color_printf(COLOR_BRIGHT_YELLOW, "3. ");
    color_printf(COLOR_BRIGHT_WHITE, "Inspect Last Session\n");
    
    color_printf(COLOR_BRIGHT_YELLOW, "4. ");
    color_printf(COLOR_BRIGHT_WHITE, "View Statistics\n");
    
    color_printf(COLOR_BRIGHT_YELLOW, "5. ");
    color_printf(COLOR_BRIGHT_RED, "Exit C-Shark\n");
    
    color_printf(COLOR_BRIGHT_CYAN, "================================================\n");
    
    char input[64];
    if (!safe_input_read("Enter choice (1-5): ", input, sizeof(input))) {
        /* EOF encountered (Ctrl+D) */
        log_printf("\n[%s] Goodbye!\n", PROGRAM_NAME);
        return 0;
    }
    
    int choice = parse_int_range(input, 1, 5);
    
    switch (choice) {
        case 1:
            /* Start packet capture */
            log_printf("\n[%s] Starting packet capture on '%s'...\n", 
                       PROGRAM_NAME, selected_device);
            if (start_capture(selected_device, NULL, config->enable_hexdump) != 0) {
                log_printf("[%s] Capture failed. Returning to main menu.\n", 
                           PROGRAM_NAME);
            }
            return 1; /* Return to menu */
            
        case 2:
            /* Start filtered capture with interactive menu */
            {
                char* filter = filter_show_menu();
                if (filter) {
                    log_printf("\n[%s] Starting filtered capture on '%s'...\n", 
                               PROGRAM_NAME, selected_device);
                    if (start_capture(selected_device, filter, config->enable_hexdump) != 0) {
                        log_printf("[%s] Capture failed. Returning to main menu.\n", 
                                   PROGRAM_NAME);
                    }
                    free(filter);
                } else {
                    log_printf("\n[%s] Filter cancelled. Returning to menu.\n", PROGRAM_NAME);
                }
            }
            return 1;
            
        case 3:
            /* Inspect last session */
            if (!session_exists()) {
                color_printf(COLOR_BRIGHT_RED, "\nNo capture session available!\n");
                color_printf(COLOR_WHITE, "Start a packet capture first to inspect packets.\n");
            } else {
                show_session_inspector();
            }
            return 1;
            
        case 4:
            stats_print_summary();
            return 1;
            
        case 5:
            log_printf("\n[%s] Goodbye!\n", PROGRAM_NAME);
            return 0; /* Exit program */
            
        default:
            log_printf("Invalid choice. Please enter a number between 1 and 5.\n");
            return 1; /* Continue menu loop */
    }
}

/*
 * Show session packet inspector
 */
static void show_session_inspector(void) {
    if (!session_exists()) {
        color_printf(COLOR_BRIGHT_RED, "No capture session available!\n");
        color_printf(COLOR_BRIGHT_YELLOW, "Start a packet capture first to inspect packets.\n");
        return;
    }
    
    /* Use the interactive inspection interface */
    inspect_session_interactive();
}

/*
 * Clean up configuration
 */
static void cleanup_config(config_t* config) {
    free(config->interface_name);
    free(config->filter_string);
    free(config->log_filename);
}

/*
 * Main program entry point
 * Handles interface discovery, selection, and main menu loop
 */
int main(int argc, char* argv[]) {
    config_t config;
    
    /* Parse command line arguments */
    parse_arguments(argc, argv, &config);
    
    /* Initialize logging */
    if (config.log_filename) {
        if (!log_set_file(config.log_filename)) {
            fprintf(stderr, "Warning: Could not open log file '%s', using stdout\n", 
                    config.log_filename);
        } else {
            printf("Logging to file: %s\n", config.log_filename);
        }
    } else {
        log_set_file(NULL); /* stdout only */
    }
    
    /* Initialize statistics and session storage */
    stats_init();
    session_init();
    
    print_banner();
    
    char* selected_device = NULL;
    
    if (config.interactive_mode) {
        /* Interactive mode - show interface selection */
        int interface_count = discover_interfaces();
        
        if (interface_count < 0) {
            log_printf("[%s] Failed to discover network interfaces. Exiting.\n", 
                       PROGRAM_NAME);
            cleanup_config(&config);
            return EXIT_FAILURE;
        }
        
        if (interface_count == 0) {
            log_printf("[%s] No network interfaces available for capture. Exiting.\n", 
                       PROGRAM_NAME);
            cleanup_config(&config);
            return EXIT_FAILURE;
        }
        
        /* Get user interface selection */
        selected_device = select_interface(interface_count);
        
        if (!selected_device) {
            /* EOF or selection error */
            log_printf("\n[%s] No interface selected. Exiting.\n", PROGRAM_NAME);
            cleanup_config(&config);
            return EXIT_SUCCESS;
        }
        
        /* Main menu loop */
        while (1) {
            if (!show_main_menu(selected_device, &config)) {
                /* User chose to exit or EOF encountered */
                break;
            }
        }
    } else {
        /* Command-line mode - start capture directly */
        selected_device = strdup(config.interface_name);
        
        log_printf("[%s] Starting capture on interface '%s'...\n", 
                   PROGRAM_NAME, selected_device);
        
        if (config.filter_string) {
            log_printf("[%s] Using filter: %s\n", PROGRAM_NAME, config.filter_string);
        }
        
        if (config.enable_hexdump) {
            log_printf("[%s] Hexdump enabled\n", PROGRAM_NAME);
        }
        
        /* Start capture */
        start_capture(selected_device, config.filter_string, config.enable_hexdump);
    }
    
    /* Print final statistics */
    stats_print_summary();
    
    /* Clean up and exit */
    free(selected_device);
    cleanup_config(&config);
    session_clear();
    log_close();
    
    log_printf("\n[%s] Program terminated successfully.\n", PROGRAM_NAME);
    return EXIT_SUCCESS;
}