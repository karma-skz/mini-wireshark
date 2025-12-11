/*
 * icmp.c - ICMP protocol decoding implementation for cshark
 * 
 * Handles ICMP and ICMPv6 packet decoding with human-readable
 * type and code descriptions for network diagnostics.
 */

#define _DEFAULT_SOURCE
#define _BSD_SOURCE
#include "icmp.h"
#include <stdio.h>
#include <sys/types.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include "utils.h"
#include "stats.h"
#include <stdio.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

/*
 * Decode and display ICMP header (IPv4)
 */
int decode_icmp(const unsigned char* packet, int length) {
    if (!packet || length < sizeof(struct icmphdr)) {
        printf("L4: Packet too short for ICMP header\n");
        return -1;
    }
    
    struct icmphdr* icmp_hdr = (struct icmphdr*)packet;
    
    log_printf("L4 (ICMP): Type: %d | Code: %d | Checksum: 0x%04X\n",
               icmp_hdr->type, icmp_hdr->code, ntohs(icmp_hdr->checksum));
    log_printf("           Description: %s\n",
               get_icmp_type_description(icmp_hdr->type, icmp_hdr->code));
    
    stats_increment("icmp");
    
    /* Additional fields for specific ICMP types */
    if (icmp_hdr->type == ICMP_ECHO || icmp_hdr->type == ICMP_ECHOREPLY) {
        log_printf("           ID: %d | Sequence: %d\n",
                   ntohs(icmp_hdr->un.echo.id), ntohs(icmp_hdr->un.echo.sequence));
    }
    
    return sizeof(struct icmphdr);
}

/*
 * Decode and display ICMPv6 header (IPv6)
 */
int decode_icmpv6(const unsigned char* packet, int length) {
    if (!packet || length < sizeof(struct icmp6_hdr)) {
        printf("L4: Packet too short for ICMPv6 header\n");
        return -1;
    }
    
    struct icmp6_hdr* icmp6_hdr = (struct icmp6_hdr*)packet;
    
    log_printf("L4 (ICMPv6): Type: %d | Code: %d | Checksum: 0x%04X\n",
               icmp6_hdr->icmp6_type, icmp6_hdr->icmp6_code, 
               ntohs(icmp6_hdr->icmp6_cksum));
    log_printf("             Description: %s\n",
               get_icmpv6_type_description(icmp6_hdr->icmp6_type, icmp6_hdr->icmp6_code));
    
    stats_increment("icmp");
    
    /* Additional fields for specific ICMPv6 types */
    if (icmp6_hdr->icmp6_type == ICMP6_ECHO_REQUEST || 
        icmp6_hdr->icmp6_type == ICMP6_ECHO_REPLY) {
        printf("             ID: %d | Sequence: %d\n",
               ntohs(icmp6_hdr->icmp6_id), ntohs(icmp6_hdr->icmp6_seq));
    }
    
    return sizeof(struct icmp6_hdr);
}

/*
 * Get human-readable description of ICMP type and code
 */
const char* get_icmp_type_description(unsigned char type, unsigned char code) {
    switch (type) {
        case ICMP_ECHOREPLY:
            return "Echo Reply";
            
        case ICMP_DEST_UNREACH:
            switch (code) {
                case ICMP_NET_UNREACH: return "Destination Unreachable - Network Unreachable";
                case ICMP_HOST_UNREACH: return "Destination Unreachable - Host Unreachable";
                case ICMP_PROT_UNREACH: return "Destination Unreachable - Protocol Unreachable";
                case ICMP_PORT_UNREACH: return "Destination Unreachable - Port Unreachable";
                case ICMP_FRAG_NEEDED: return "Destination Unreachable - Fragmentation Required";
                case ICMP_SR_FAILED: return "Destination Unreachable - Source Route Failed";
                default: return "Destination Unreachable - Unknown Code";
            }
            
        case ICMP_SOURCE_QUENCH:
            return "Source Quench";
            
        case ICMP_REDIRECT:
            switch (code) {
                case ICMP_REDIR_NET: return "Redirect - Network";
                case ICMP_REDIR_HOST: return "Redirect - Host";
                case ICMP_REDIR_NETTOS: return "Redirect - Network for TOS";
                case ICMP_REDIR_HOSTTOS: return "Redirect - Host for TOS";
                default: return "Redirect - Unknown Code";
            }
            
        case ICMP_ECHO:
            return "Echo Request (Ping)";
            
        case ICMP_TIME_EXCEEDED:
            switch (code) {
                case ICMP_EXC_TTL: return "Time Exceeded - TTL Exceeded in Transit";
                case ICMP_EXC_FRAGTIME: return "Time Exceeded - Fragment Reassembly Time Exceeded";
                default: return "Time Exceeded - Unknown Code";
            }
            
        case ICMP_PARAMETERPROB:
            return "Parameter Problem";
            
        case ICMP_TIMESTAMP:
            return "Timestamp Request";
            
        case ICMP_TIMESTAMPREPLY:
            return "Timestamp Reply";
            
        case ICMP_INFO_REQUEST:
            return "Information Request";
            
        case ICMP_INFO_REPLY:
            return "Information Reply";
            
        default:
            return "Unknown ICMP Type";
    }
}

/*
 * Get human-readable description of ICMPv6 type and code
 */
const char* get_icmpv6_type_description(unsigned char type, unsigned char code) {
    switch (type) {
        case ICMP6_DST_UNREACH:
            switch (code) {
                case ICMP6_DST_UNREACH_NOROUTE: return "Destination Unreachable - No Route";
                case ICMP6_DST_UNREACH_ADMIN: return "Destination Unreachable - Admin Prohibited";
                case ICMP6_DST_UNREACH_BEYONDSCOPE: return "Destination Unreachable - Beyond Scope";
                case ICMP6_DST_UNREACH_ADDR: return "Destination Unreachable - Address Unreachable";
                case ICMP6_DST_UNREACH_NOPORT: return "Destination Unreachable - Port Unreachable";
                default: return "Destination Unreachable - Unknown Code";
            }
            
        case ICMP6_PACKET_TOO_BIG:
            return "Packet Too Big";
            
        case ICMP6_TIME_EXCEEDED:
            switch (code) {
                case ICMP6_TIME_EXCEED_TRANSIT: return "Time Exceeded - Hop Limit Exceeded";
                case ICMP6_TIME_EXCEED_REASSEMBLY: return "Time Exceeded - Fragment Reassembly Time Exceeded";
                default: return "Time Exceeded - Unknown Code";
            }
            
        case ICMP6_PARAM_PROB:
            switch (code) {
                case ICMP6_PARAMPROB_HEADER: return "Parameter Problem - Erroneous Header";
                case ICMP6_PARAMPROB_NEXTHEADER: return "Parameter Problem - Unrecognized Next Header";
                case ICMP6_PARAMPROB_OPTION: return "Parameter Problem - Unrecognized Option";
                default: return "Parameter Problem - Unknown Code";
            }
            
        case ICMP6_ECHO_REQUEST:
            return "Echo Request (Ping6)";
            
        case ICMP6_ECHO_REPLY:
            return "Echo Reply (Ping6)";
            
        case ND_ROUTER_SOLICIT:
            return "Router Solicitation";
            
        case ND_ROUTER_ADVERT:
            return "Router Advertisement";
            
        case ND_NEIGHBOR_SOLICIT:
            return "Neighbor Solicitation";
            
        case ND_NEIGHBOR_ADVERT:
            return "Neighbor Advertisement";
            
        case ND_REDIRECT:
            return "Redirect";
            
        default:
            return "Unknown ICMPv6 Type";
    }
}