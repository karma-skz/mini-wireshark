/*
 * http.h - Basic HTTP protocol parsing for cshark packet sniffer
 * 
 * Contains functions for detecting and parsing basic HTTP headers
 * from TCP payload data on common HTTP ports.
 */

#ifndef HTTP_H
#define HTTP_H

/*
 * Check if TCP ports indicate potential HTTP traffic
 * src_port: source port number
 * dst_port: destination port number
 * Returns: 1 if ports suggest HTTP traffic, 0 otherwise
 */
int is_http_port(unsigned short src_port, unsigned short dst_port);

/*
 * Detect and parse HTTP headers from TCP payload
 * payload: TCP payload data
 * length: length of payload data
 * src_port: source port (for context)
 * dst_port: destination port (for context)
 * Returns: number of bytes parsed, or 0 if not HTTP
 */
int decode_http(const unsigned char* payload, int length, 
                unsigned short src_port, unsigned short dst_port);

/*
 * Check if payload starts with HTTP request method
 * payload: payload data to check
 * length: length of payload
 * Returns: 1 if HTTP request detected, 0 otherwise
 */
int is_http_request(const unsigned char* payload, int length);

/*
 * Check if payload starts with HTTP response
 * payload: payload data to check
 * length: length of payload
 * Returns: 1 if HTTP response detected, 0 otherwise
 */
int is_http_response(const unsigned char* payload, int length);

/*
 * Parse and display HTTP headers
 * payload: HTTP payload data
 * length: length of payload
 * is_request: 1 if request, 0 if response
 * Returns: number of header bytes parsed
 */
int parse_http_headers(const unsigned char* payload, int length, int is_request);

#endif /* HTTP_H */