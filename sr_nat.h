
#ifndef SR_NAT_TABLE_H
#define SR_NAT_TABLE_H

#include <inttypes.h>
#include <time.h>
#include <pthread.h>
#include "sorted_list.h"
#include <stdio.h>

typedef enum {
	nat_mapping_icmp,
	nat_mapping_tcp,
	nat_mapping_udp,
} sr_nat_mapping_type;

// Used to keep track of "silently dropped" incoming SYN packets.  All ports and
//     IP's are in host order
struct sr_nat_incoming_syn_packet
{
	uint16_t a; // Destination port
	uint32_t B; // Source IP
	uint16_t b; // Source port

	uint8_t* packet;
	unsigned int packet_len;
	char* arrival_interface;
	time_t arrival_time; // Time that the SYN packet arrived
	struct sr_nat_incoming_syn_packet* next;
	struct sr_nat_incoming_syn_packet* prev;
};
typedef struct sr_nat_incoming_syn_packet sr_nat_incoming_syn_packet_t;

enum tcp_state_t
{
	WAITING_SYN,        /* 3 way handshake */
	WAITING_SYN_ACK,
	WAITING_ACK,
	ESTABLISHED,
	FIN_RECEIVED,
};

// A TCP connection structure containing the tuple of {src_ip,src_port,dst_ip,dst_port} as well as the state of
//     the connection.  All ports and IP's are in host order
struct sr_nat_connection {
	uint32_t ip_ext;   // External IP
	uint16_t port_ext; // External port

	// Keeps track of the state of the TCP connection
	enum tcp_state_t tcp_state;

	// The seqno of the outbound(inbound) SYN.  We'll be looking for an inbound(outbound) ack +1 of this
	uint32_t active_seqno;
	uint32_t passive_seqno;

	time_t last_updated; /* use to timeout mappings */

	struct sr_nat_connection *next;
	struct sr_nat_connection *prev;
};

struct sr_nat_mapping {
	sr_nat_mapping_type type;
	uint32_t ip_int; /* internal ip addr */
	uint32_t ip_ext; /* external ip addr */
	uint16_t aux_int; /* internal port or icmp id */
	uint16_t aux_ext; /* external port or icmp id */
	time_t last_updated; /* use to timeout mappings */
	struct sr_nat_connection *conns; /* list of connections. null for ICMP */
	struct sr_nat_mapping *next;
	struct sr_nat_mapping *prev;
};
typedef struct sr_nat_mapping sr_nat_mapping_t;

struct sr_nat {
	// The mappings from (ip_src,port_src) to (port_ext)
	struct sr_nat_mapping *mappings;

	// Used to keep track of available port numbers
	list_entry_t* port_numbers;

	// Timeout values
	time_t icmp_query_timeout;
	time_t tcp_est_timeout;
	time_t tcp_trans_timeout;
	time_t silently_dropped_syn_timeout;
	time_t min_mapping_timeout;

	// "Silently dropped SYN's" timeout list
	sr_nat_incoming_syn_packet_t* silently_dropped_syns;

	// Threading
	pthread_mutex_t lock;
	pthread_mutexattr_t attr;
	pthread_attr_t thread_attr;
	pthread_t thread;
};

// Initialize and destroy the NAT.  All memory that is malloc'd is freed in sr_nat_destroy
int   sr_nat_init(struct sr_nat *nat, uint32_t icmp_query_timeout, uint32_t tcp_est_timeout, uint32_t tcp_trans_timeout);
int   sr_nat_destroy(struct sr_nat *nat);  /* Destroys the nat (free memory) */
void *sr_nat_timeout(void *sr_ptr);  /* Periodic Timout */

// **** MAPPINGS ****

// Look up one of the NAT's mappings based on either external (aux_ext) or internal (ip_int,aux_int) parameters.  This set of
//     functions returns an actual pointer to the mapping - not a copy (so don't free it)
struct sr_nat_mapping *sr_nat_lookup_external_ptr(struct sr_nat *nat,
		uint16_t aux_ext, sr_nat_mapping_type type );
struct sr_nat_mapping *sr_nat_lookup_internal_ptr(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );
struct sr_nat_mapping *sr_nat_lookup_ptr(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, uint16_t aux_ext,
		sr_nat_mapping_type type, uint8_t is_internal);

// Look up one of the NAT's mappings based on either external (aux_ext) or internal (ip_int,aux_int) parameters.  This set of
//     functions returns just a copy to the mapping.  The caller must free the returned mapping if it is not NULL
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
		uint16_t aux_ext, sr_nat_mapping_type type );
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );
struct sr_nat_mapping *sr_nat_lookup(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, uint16_t aux_ext,
		sr_nat_mapping_type type, uint8_t is_internal);

// Insert a new mapping into the nat's mapping table.  The caller must free the returned mapping if it is not NULL
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, uint32_t ip_ext, sr_nat_mapping_type type );

// Lookup and remove a mapping (if it exists) based on either external (aux_ext) or internal (ip_int+aux_int) parameters
void sr_nat_remove_mapping_by_external(struct sr_nat *nat,
		uint16_t aux_ext, sr_nat_mapping_type type );
void sr_nat_remove_mapping_by_internal(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type );
void sr_nat_remove_mapping(struct sr_nat *nat, uint32_t ip_int,
		uint16_t aux_int, uint16_t aux_ext, sr_nat_mapping_type type,
		uint8_t is_internal);

// **** CONNECTIONS ****

// Given an IP packet with a TCP payload, set and remove SYN silently dropped packets from the list to receive ICMP port unreachables
void sr_nat_received_external_initial_syn(struct sr_nat *nat, uint8_t* packet, unsigned int packet_len, char* arrival_interface);
void sr_nat_received_internal_initial_syn(struct sr_nat *nat, uint8_t* packet, unsigned int packet_len, char* arrival_interface);

// Look up one of the NAT's connections given an IP packet that has already be checked for correctness.  This set of
//     functions returns just a copy to the connection.  The caller must free the returned connection if it is not NULL
struct sr_nat_connection* sr_nat_lookup_connection_external(struct sr_nat* nat,
		uint8_t* packet, unsigned int packet_len);
struct sr_nat_connection* sr_nat_lookup_connection_internal(struct sr_nat* nat,
		uint8_t* packet, unsigned int packet_len);
struct sr_nat_connection* sr_nat_lookup_connection(struct sr_nat* nat,
		uint8_t* packet, unsigned int packet_len, uint8_t is_internal);

// Insert a connection into its correct mapping given an IP packet that has already be checked for correctness.  Will
//     first check to see if the correct connection already exists and so won't create duplicates
void sr_nat_insert_connection_external(struct sr_nat* nat, uint8_t* packet, unsigned int packet_len);
void sr_nat_insert_connection_internal(struct sr_nat* nat, uint8_t* packet, unsigned int packet_len);
void sr_nat_insert_connection(struct sr_nat* nat, uint8_t* packet, unsigned int packet_len, uint8_t is_internal);

// Given an IP packet with a TCP payload, its length, and the interface it arrived on, determine which connection of which mapping to update (if any)
void sr_nat_update_connection_state(struct sr_nat* nat, uint8_t* packet, unsigned int packet_len, uint8_t is_internal);

// **** PRINT-OUTS ****

// Prints out all the details of a given connection - indented by the indent_char (*,>,-)
void sr_nat_print_connection(struct sr_nat* nat, struct sr_nat_connection* connection, char indent_char);

// Print all the connections for the given mapping
void sr_nat_print_connections_for_mapping(struct sr_nat* nat, struct sr_nat_mapping* mapping);

// Print all the mappings for the given NAT
void sr_nat_print_mappings(struct sr_nat* nat);

#endif
