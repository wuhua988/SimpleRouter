/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 *
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_nat.h"

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
		do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
				(unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

#define INTERNAL_INTERFACE "eth1"
#define EXTERNAL_INTERFACE "eth2"
#define MIN(X,Y) ((X) < (Y) ? (X) : (Y))

enum icmp_code
{
	// Ping
	ECHO_REQUEST, //(8,0)
	ECHO_REPLY, //(0,0)

	// Errors
	DEST_NETWORK_UNREACHABLE, //(3,0)
	DEST_HOST_UNREACHABLE, //(3,1)
	DEST_PORT_UNREACHABLE, //(3,3)
	TTL_EXPIRED, //(11,0)
};
typedef enum icmp_code icmp_code_t;

struct sr_instance
{
	int  sockfd;   /* socket to server */
	char user[32]; /* user name */
	char host[32]; /* host name */
	char template[30]; /* template name if any */
	unsigned short topo_id;
	struct sockaddr_in sr_addr; /* address to server */
	struct sr_if* if_list; /* list of interfaces */
	struct sr_rt* routing_table; /* routing table */
	struct sr_arpcache cache;   /* ARP cache */
	struct sr_nat nat; // NAT pointer
	uint32_t ip_ext; // External IP of NAT
	uint8_t nat_is_on; // Flag if NAT is turned on
	pthread_attr_t attr;
	FILE* logfile;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance*,uint8_t,uint32_t,uint32_t,uint32_t);
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

// Receiving functions
void sr_handlepacket(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* interface/* lent */);
void sr_receive_ip(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* arrival_interface);
void sr_receive_tcp(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* arrival_interface);
void sr_receive_tcp_nat(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* arrival_interface);
void sr_receive_icmp(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* arrival_interface);
void sr_receive_icmp_nat(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* arrival_interface);
void sr_receive_arp(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* arrival_interface);

// Sending functions
void sr_forward_ip(struct sr_instance* sr, uint8_t* ip_packet, unsigned long len, char* arrival_interface);
void sr_build_and_send_icmp(struct sr_instance* sr, uint32_t src_ip, uint32_t dest_ip, icmp_code_t icmp_code, uint8_t* packet, uint16_t len);
void sr_send_ip(struct sr_instance* sr, uint8_t* ip_packet, unsigned long len);
void sr_build_arp(unsigned char* src_eth, uint32_t src_ip, unsigned char* dst_eth, uint32_t dst_ip, unsigned short op_code, sr_arp_hdr_t* arp_hdr);
int sr_can_send_arp_req(struct sr_instance *sr, struct sr_arpreq* arp_req);
void sr_send_arp(struct sr_instance* sr, uint8_t* arp_packet, unsigned long len);
void sr_send_ethernet(struct sr_instance* sr, uint8_t* ethernet_packet, unsigned long len);

// Helper functions
uint16_t sr_compute_tcp_cksum(uint8_t* packet, unsigned int len);
void sr_concatenate_header_and_payload(uint8_t* header, size_t header_len, uint8_t* payload, size_t payload_len, uint8_t* result);
void sr_find_longest_prefix_match(struct sr_instance* sr, uint32_t dest_ip_addr, uint32_t* next_hop_ip_addr, char* outgoing_interface);
int sr_is_my_interface(struct sr_instance* sr, uint32_t ip_addr);
struct sr_if* sr_get_interface_from_eth_addr(struct sr_instance* sr, unsigned char* eth_addr);
uint8_t sr_is_external(struct sr_instance* sr, char* arrival_interface);
uint8_t sr_is_internal(struct sr_instance* sr, char* arrival_interface);
unsigned int sr_get_ip_hdr_len(sr_ip_hdr_t* ip_hdr);
uint8_t sr_char_array_compare(char* first, char* second);

#endif /* SR_ROUTER_H */
