/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr, uint8_t nat_is_on, uint32_t icmp_query_timeout, uint32_t tcp_est_timeout, uint32_t tcp_trans_timeout)
{
	/* REQUIRES */
	assert(sr);

	// Initialize ARP cache and its threads
	sr_arpcache_init(&(sr->cache));
	pthread_attr_init(&(sr->attr));
	pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
	pthread_t thread;
	pthread_create(&thread,&(sr->attr), sr_arpcache_timeout, sr);

	// Initialize NAT and its threads
	sr->nat_is_on = nat_is_on;
	sr->ip_ext = 0;
	if(nat_is_on)
	{
		sr_nat_init(&(sr->nat), icmp_query_timeout, tcp_est_timeout, tcp_trans_timeout);
		pthread_attr_init(&(sr->nat.thread_attr));
		pthread_attr_setdetachstate(&(sr->nat.thread_attr), PTHREAD_CREATE_JOINABLE);
		pthread_attr_setscope(&(sr->nat.thread_attr), PTHREAD_SCOPE_SYSTEM);
		pthread_attr_setscope(&(sr->nat.thread_attr), PTHREAD_SCOPE_SYSTEM);
		pthread_create(&(sr->nat.thread), &(sr->nat.thread_attr), sr_nat_timeout, sr);
	}

	/* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

// Receiving packets -----

// Receive packet and parse Ethernet fields
void sr_handlepacket(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* interface/* lent */)
{
	/* REQUIRES */
	assert(sr);
	assert(packet);
	assert(interface);

	// Read all fields of the ethernet header
	sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet;

	// Case this is an IP packet, so just pass everything without the ethernet header
	if(ntohs(eth_hdr->ether_type) == ethertype_ip)
		sr_receive_ip(sr,packet+sizeof(sr_ethernet_hdr_t),len-sizeof(sr_ethernet_hdr_t),interface);

	// Case this is an ARP packet, so just pass everything without the ethernet header
	else if(ntohs(eth_hdr->ether_type) == ethertype_arp)
		sr_receive_arp(sr,packet+sizeof(sr_ethernet_hdr_t),len-sizeof(sr_ethernet_hdr_t),interface);
}

// Process a received IP packet.  Check len and cksum fields.  If the IP packet is an ICMP echo or a
//     TCP/UDP packet, then respond accordingly.  If the NAT functionality is turned on, the act accordingly
void sr_receive_ip(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* arrival_interface)
{
	// Extract the IP packet header
	sr_ip_hdr_t* ip_packet_hdr = (sr_ip_hdr_t*)packet;

	// Check the length field
	if(ntohs(ip_packet_hdr->ip_len) == 0 || ntohs(ip_packet_hdr->ip_len) != len)
		return;

	// Check the IP checksum field
	uint16_t sent_cksum = ip_packet_hdr->ip_sum;
	ip_packet_hdr->ip_sum = 0;
	uint16_t computed_cksum = cksum(ip_packet_hdr, sr_get_ip_hdr_len(ip_packet_hdr));
	if(sent_cksum == 0 || computed_cksum != sent_cksum)
		return;
	ip_packet_hdr->ip_sum = sent_cksum;

	// Process this IP packet depending on its type (TCP,ICMP) and whether the NAT
	//     functionality is turned on or not

	// Case this is a TCP packet
	if(ip_packet_hdr->ip_p == ip_protocol_tcp)
	{
		// Extract TCP header
		sr_tcp_hdr_t* tcp_hdr = (sr_tcp_hdr_t*)(packet + sr_get_ip_hdr_len(ip_packet_hdr));

		// Compute checksum of (IP pseudo header, TCP header, and data)
		uint16_t sent_tcp_cksum = tcp_hdr->tcp_cksum;
		tcp_hdr->tcp_cksum = 0;
		uint16_t computed_tcp_cksum = sr_compute_tcp_cksum(packet,len);

		// Case the cksum doesn't match, so just discard
		if(sent_tcp_cksum == 0 || computed_tcp_cksum != sent_tcp_cksum)
			return;

		// Restore the TCP checksum to its original value
		tcp_hdr->tcp_cksum = sent_tcp_cksum;

		// NAT is on
		if(sr->nat_is_on)
			sr_receive_tcp_nat(sr,packet,len,arrival_interface);
		// NAT is off
		else
			sr_receive_tcp(sr,packet,len,arrival_interface);
	}
	// Case this is an ICMP packet
	else if(ip_packet_hdr->ip_p == ip_protocol_icmp)
	{
		// Extract ICMP header
		sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sr_get_ip_hdr_len(ip_packet_hdr));

		// Compute checksum of ICMP payload
		uint16_t sent_icmp_cksum = icmp_hdr->icmp_sum;
		icmp_hdr->icmp_sum = 0;
		uint16_t computed_icmp_cksum = cksum(icmp_hdr, len - sr_get_ip_hdr_len(ip_packet_hdr));

		// Case the cksum doesn't match, so just discard
		if(sent_icmp_cksum == 0 || computed_icmp_cksum != sent_icmp_cksum)
			return;

		// Restore the ICMP checksum to its original value
		icmp_hdr->icmp_sum = sent_icmp_cksum;

		// NAT is on
		if(sr->nat_is_on)
			sr_receive_icmp_nat(sr,packet,len,arrival_interface);
		// NAT is off
		else
			sr_receive_icmp(sr,packet,len,arrival_interface);
	}
	else if(ip_packet_hdr->ip_p == ip_protocol_udp) // UDP
		sr_receive_tcp(sr,packet,len,arrival_interface);
}

// Handle IP packets with TCP payloads whose IP and TCP checksums have already been checked (with NAT off)
void sr_receive_tcp(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* arrival_interface)
{
	// Extract IP header
	sr_ip_hdr_t* ip_packet_hdr = (sr_ip_hdr_t*)packet;

	// Case this packet is sent to this router, so send back an ICMP port unreachable
	if(sr_is_my_interface(sr,ntohl(ip_packet_hdr->ip_dst)))
		sr_build_and_send_icmp(sr,ntohl(sr_get_interface(sr,arrival_interface)->ip),ntohl(ip_packet_hdr->ip_src),DEST_PORT_UNREACHABLE,packet,len);

	// Case the TCP packet is destined for someone else, so forward it
	else
		sr_forward_ip(sr,packet,len,arrival_interface);
}

// Handle IP packets with TCP payloads whose IP and TCP checksums have already been checked (with NAT on)
void sr_receive_tcp_nat(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* arrival_interface)
{
	pthread_mutex_lock(&(sr->nat.lock));

	// Extract IP header
	sr_ip_hdr_t* ip_packet_hdr = (sr_ip_hdr_t*)packet;

	// Extract TCP header
	sr_tcp_hdr_t* tcp_hdr = (sr_tcp_hdr_t*)(packet + sr_get_ip_hdr_len(ip_packet_hdr));

	// Case this packet is internal (outgoing)
	if(sr_is_internal(sr,arrival_interface))
	{
		// First check if this TCP is sent to the NAT, in which case we respond with a port unreachable
		if(sr_is_my_interface(sr,ntohl(ip_packet_hdr->ip_dst)))
			sr_build_and_send_icmp(sr,ntohl(sr_get_interface(sr,arrival_interface)->ip),ntohl(ip_packet_hdr->ip_src),DEST_PORT_UNREACHABLE,packet,len);

		// Case the TCP is outgoing but not destined for the router
		else
		{
			// Find internal mapping
			pthread_mutex_unlock(&(sr->nat.lock));
			sr_nat_mapping_t* mapping = sr_nat_lookup_internal(&sr->nat,ntohl(ip_packet_hdr->ip_src),
					ntohs(tcp_hdr->tcp_src_port),nat_mapping_tcp);
			pthread_mutex_lock(&(sr->nat.lock));

			// If the mapping doesn't exist, and the SYN bit is set, then try to create it
			if(!mapping && tcp_hdr->tcp_ctrl_syn && !tcp_hdr->tcp_ctrl_ack)
			{
				// Figure out external IP, unless we've already found it
				if(!sr->ip_ext)
				{
					struct sr_if* sr_external_interface = sr_get_interface(sr,EXTERNAL_INTERFACE);
					sr->ip_ext = ntohl(sr_external_interface->ip);
				}

				// Insert the mapping based on the internal parameters (ip_src,tcp_src_port)
				pthread_mutex_unlock(&(sr->nat.lock));
				mapping = sr_nat_insert_mapping(&sr->nat,ntohl(ip_packet_hdr->ip_src),
						ntohs(tcp_hdr->tcp_src_port),sr->ip_ext,nat_mapping_tcp);
				pthread_mutex_lock(&(sr->nat.lock));

				// Try to remove any matching INCOMING SYN bit packets in the "silently dropped" list
				pthread_mutex_unlock(&(sr->nat.lock));
				sr_nat_received_internal_initial_syn(&sr->nat,packet,len,arrival_interface);
				pthread_mutex_lock(&(sr->nat.lock));
			}
			// In any case, if a mapping now exists
			if(mapping)
			{
				// Try to update the TCP connection state if a mapping exists
				pthread_mutex_unlock(&(sr->nat.lock));
				sr_nat_update_connection_state(&sr->nat,packet,len,1);
				pthread_mutex_lock(&(sr->nat.lock));

				// Rewrite the IP src and TCP src port fields accordingly
				ip_packet_hdr->ip_src = htonl(mapping->ip_ext);
				tcp_hdr->tcp_src_port = htons(mapping->aux_ext);

				// Recompute the TCP cksum
				tcp_hdr->tcp_cksum = 0;
				tcp_hdr->tcp_cksum = sr_compute_tcp_cksum(packet,len);

				// Forward the TCP packet
				sr_forward_ip(sr,packet,len,arrival_interface);

				free(mapping);
			}
		}
	}
	// Case this packet is INCOMING (coming from the outside)
	else if(sr_is_external(sr,arrival_interface))
	{
		// Find external mapping
		pthread_mutex_unlock(&(sr->nat.lock));
		sr_nat_mapping_t* mapping = sr_nat_lookup_external(&sr->nat,ntohs(tcp_hdr->tcp_dst_port),nat_mapping_tcp);
		pthread_mutex_lock(&(sr->nat.lock));

		// Case a mapping does not yet exist
		if(!mapping)
		{
			// Case this is an initial SYN attempt, which we will buffer and if it's not corroborated by an internal
			//     host within 6 seconds, we'll respond with a port unreachable
			if(tcp_hdr->tcp_ctrl_syn && !tcp_hdr->tcp_ctrl_ack)
			{
				// Add on to the "silently dropped" SYN's if there's not already an entry for it
				pthread_mutex_unlock(&(sr->nat.lock));
				sr_nat_received_external_initial_syn(&sr->nat,packet,len,arrival_interface);
				pthread_mutex_lock(&(sr->nat.lock));
			}
			// Case this packet isn't an initial SYN, so we automatically know to respond with a port unreachable
			else
				sr_build_and_send_icmp(sr,ntohl(sr_get_interface(sr,arrival_interface)->ip),ntohl(ip_packet_hdr->ip_src),DEST_PORT_UNREACHABLE,packet,len);
		}
		// Case a mapping exists, so translate and forward
		else
		{
			// Try to update the TCP connection state if a mapping exists
			pthread_mutex_unlock(&(sr->nat.lock));
			sr_nat_update_connection_state(&sr->nat,packet,len,0);
			pthread_mutex_lock(&(sr->nat.lock));

			// Rewrite the IP dst and TCP dst port fields accordingly
			ip_packet_hdr->ip_dst = htonl(mapping->ip_int);
			tcp_hdr->tcp_dst_port = htons(mapping->aux_int);

			// Recompute the TCP cksum
			tcp_hdr->tcp_cksum = 0;
			tcp_hdr->tcp_cksum = sr_compute_tcp_cksum(packet,len);

			// Forward the TCP packet
			sr_forward_ip(sr,packet,len,arrival_interface);

			free(mapping);
		}
	}
	pthread_mutex_unlock(&(sr->nat.lock));
}

// Handle IP packets with ICMP payloads whose IP and ICMP checksums have already been checked (with NAT off)
void sr_receive_icmp(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* arrival_interface)
{
	// Extract IP header
	sr_ip_hdr_t* ip_packet_hdr = (sr_ip_hdr_t*)packet;

	// Case this packet is sent to this router
	if(sr_is_my_interface(sr,ntohl(ip_packet_hdr->ip_dst)) == 1)
	{
		// Extract ICMP header
		sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sr_get_ip_hdr_len(ip_packet_hdr));

		// Case it's an ICMP echo request, so
		if(icmp_hdr->icmp_type == 8)
		{
			// Send an echo reply back to the source of the IP packet.  The data to be
			//     sent is the data attached to the end of the echo request packet
			sr_build_and_send_icmp(sr,ntohl(ip_packet_hdr->ip_dst),ntohl(ip_packet_hdr->ip_src),ECHO_REPLY,
					packet+sr_get_ip_hdr_len(ip_packet_hdr)+sizeof(sr_icmp_hdr_t),len-sr_get_ip_hdr_len(ip_packet_hdr)-sizeof(sr_icmp_hdr_t));
		}

		// If it's any other type of ICMP packet sent to the router (reply, time exceeded, port unreachable, etc.),
		//     just ignore it
		else{}
	}
	// Case the ICMP packet is destined for someone else, so forward the ICMP packet
	else
		sr_forward_ip(sr,packet,len,arrival_interface);
}

// Handle IP packets with ICMP payloads whose IP and ICMP checksums have already been checked (with NAT on)
void sr_receive_icmp_nat(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* arrival_interface)
{
	pthread_mutex_lock(&(sr->nat.lock));

	// Extract IP header
	sr_ip_hdr_t* ip_packet_hdr = (sr_ip_hdr_t*)packet;

	// Extract ICMP header
	sr_icmp_hdr_t* icmp_hdr = (sr_icmp_hdr_t*)(packet + sr_get_ip_hdr_len(ip_packet_hdr));

	// Case this packet is internal (outgoing)
	if(sr_is_internal(sr,arrival_interface))
	{
		// First check if this ICMP is sent to the NAT, in which case we respond with an echo reply
		if(sr_is_my_interface(sr,ntohl(ip_packet_hdr->ip_dst)))
		{
			// Case this is an echo request, so reply to it
			if(icmp_hdr->icmp_type == 8)
				sr_build_and_send_icmp(sr,ntohl(ip_packet_hdr->ip_dst),ntohl(ip_packet_hdr->ip_src),ECHO_REPLY,
						packet+sr_get_ip_hdr_len(ip_packet_hdr)+sizeof(sr_icmp_hdr_t),len-sr_get_ip_hdr_len(ip_packet_hdr)-sizeof(sr_icmp_hdr_t));

			// If it's any other type of ICMP packet sent to the router (reply, time exceeded, port unreachable, etc.),
			//     just ignore it
			else{}
		}
		// Case this is not sent to the NAT, so create a mapping for it then forward
		else
		{
			// Case it's an echo request
			if(icmp_hdr->icmp_type == 8)
			{
				// Extract ICMP echo header
				sr_icmp_echo_hdr_t* icmp_echo_hdr = (sr_icmp_echo_hdr_t*)(packet + sr_get_ip_hdr_len(ip_packet_hdr));

				// Figure out external IP, unless we've already found it
				if(!sr->ip_ext)
				{
					struct sr_if* sr_external_interface = sr_get_interface(sr,EXTERNAL_INTERFACE);
					sr->ip_ext = ntohl(sr_external_interface->ip);
				}

				// Insert an internal mapping based on the (ip_serc,icmp_id)
				pthread_mutex_unlock(&(sr->nat.lock));
				sr_nat_mapping_t* mapping = sr_nat_insert_mapping(&sr->nat,ntohl(ip_packet_hdr->ip_src),
						ntohs(icmp_echo_hdr->icmp_id),sr->ip_ext,nat_mapping_icmp);
				pthread_mutex_lock(&(sr->nat.lock));

				// Now if a mapping exists
				if(mapping)
				{
					// Rewrite the IP src and ICMP ID fields accordingly
					ip_packet_hdr->ip_src = htonl(mapping->ip_ext);
					icmp_echo_hdr->icmp_id = htons(mapping->aux_ext);

					// Recompute the ICMP header cksum
					icmp_hdr->icmp_sum = 0;
					icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sr_get_ip_hdr_len(ip_packet_hdr));

					// Forward the ICMP echo request
					sr_forward_ip(sr,packet,len,arrival_interface);

					free(mapping);
				}
			}
		}
	}
	// Case this packet is external (incoming)
	else if(sr_is_external(sr,arrival_interface))
	{
		// Case it's an echo request and sent to the NAT itself, so reply to it
		if(sr_is_my_interface(sr,ntohl(ip_packet_hdr->ip_dst)) && icmp_hdr->icmp_type == 8)
			sr_build_and_send_icmp(sr,ntohl(ip_packet_hdr->ip_dst),ntohl(ip_packet_hdr->ip_src),ECHO_REPLY,
					packet+sr_get_ip_hdr_len(ip_packet_hdr)+sizeof(sr_icmp_hdr_t),len-sr_get_ip_hdr_len(ip_packet_hdr)-sizeof(sr_icmp_hdr_t));

		// Case it's an echo reply and not meant for the NAT itself
		else if(icmp_hdr->icmp_type == 0)
		{
			// Extract ICMP echo header
			sr_icmp_echo_hdr_t* icmp_echo_hdr = (sr_icmp_echo_hdr_t*)(packet + sr_get_ip_hdr_len(ip_packet_hdr));

			// Find external mapping by (icmp_id)
			pthread_mutex_unlock(&(sr->nat.lock));
			sr_nat_mapping_t* mapping = sr_nat_lookup_external(&sr->nat,ntohs(icmp_echo_hdr->icmp_id),nat_mapping_icmp);
			pthread_mutex_lock(&(sr->nat.lock));

			// If a mapping exists, translate it
			if(mapping)
			{
				// Rewrite the IP dst and ICMP ID fields accordingly
				ip_packet_hdr->ip_dst = htonl(mapping->ip_int);
				icmp_echo_hdr->icmp_id = htons(mapping->aux_int);

				// Recompute the ICMP header cksum
				icmp_hdr->icmp_sum = 0;
				icmp_hdr->icmp_sum = cksum(icmp_hdr, len - sr_get_ip_hdr_len(ip_packet_hdr));

				// Forward the ICMP echo reply
				sr_forward_ip(sr,packet,len,arrival_interface);

				// Tear down the mapping because ICMP are one-time mappings
				pthread_mutex_unlock(&(sr->nat.lock));
				sr_nat_remove_mapping_by_external(&sr->nat,mapping->aux_ext,nat_mapping_icmp);
				pthread_mutex_lock(&(sr->nat.lock));

				free(mapping);
			}
		}
	}
	pthread_mutex_unlock(&(sr->nat.lock));
}

// Process a received ARP packet.  Check if it's either a request or a reply.  If it's a request, send back an ARP reply if
//     the request is for me.  If it's a reply sent to me OR a request sent to me or anyone, update my cache and send out
//     any packets pending this information
void sr_receive_arp(struct sr_instance* sr, uint8_t * packet/* lent */, unsigned int len, char* arrival_interface)
{
	// Extract ARP header
	sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)packet;

	// Check if this ARP is meant for one of this router's IP addresses
	size_t sent_to_me = sr_is_my_interface(sr,ntohl(arp_hdr->ar_tip));

	// Case this is an ARP request or it's an ARP reply sent to me, so cache the sender's information
	if(ntohs(arp_hdr->ar_op) == arp_op_request || (sent_to_me == 1 && ntohs(arp_hdr->ar_op) == arp_op_reply))
	{
		// Attempt to insert the (IP,mac) pairing in the ARP cache
		struct sr_arpreq* arp_req = sr_arpcache_insert(&sr->cache, arp_hdr->ar_sha, arp_hdr->ar_sip);

		// Case we need to handle and remove the sr_arpreq that was waiting on this ARP entry
		if(arp_req)
		{
			// Send all packets, in order, that were waiting in this ARP req
			struct sr_packet* packet = arp_req->packets;
			while(packet)
			{
				// For each ethernet packet in the linked list, try to send it again now that we have the ARP info
				//     the packet needed
				sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)packet->buf;

				// Copy in the destination ethernet address
				for(int i = 0; i < ETHER_ADDR_LEN; i++)
					eth_hdr->ether_dhost[i] = arp_hdr->ar_sha[i];

				// Send out the ethernet packet now that it's complete
				sr_send_ethernet(sr,packet->buf, packet->len);

				// Go to the next packet
				packet = packet->next;
			}

			// Now that all packets have been sent, remove all reference to this ARP req from the req list
			sr_arpreq_destroy(&sr->cache, arp_req);
		}
	}

	// Case this an ARP request that is sent to me, so I have to reply to it
	if(sent_to_me == 1 && ntohs(arp_hdr->ar_op) == arp_op_request)
	{
		// Swap the source and destination IP addresses
		uint32_t ar_sip_temp = arp_hdr->ar_sip;
		arp_hdr->ar_sip = arp_hdr->ar_tip;
		arp_hdr->ar_tip = ar_sip_temp;

		// Set the destination ethernet address
		for(int i = 0; i < ETHER_ADDR_LEN; i++)
			arp_hdr->ar_tha[i] = arp_hdr->ar_sha[i];

		// Extract the arrival interface so that we can use that as the source ethernet address
		struct sr_if* sr_arrival_interface = sr_get_interface(sr,arrival_interface);
		if(!sr_arrival_interface)
			return;

		// Set the source ethernet address
		for(int i = 0; i < ETHER_ADDR_LEN; i++)
			arp_hdr->ar_sha[i] = sr_arrival_interface->addr[i];

		// Set the ARP type to reply
		arp_hdr->ar_op = htons(arp_op_reply);

		// Send an ARP reply right back out on the interface this was received on
		sr_send_arp(sr, packet, len);
	}
}

// Sending packets -----

// Decrements TTL (and generates error message if it's expired), recomputes cksum and then
//     sends the IP packet
void sr_forward_ip(struct sr_instance* sr, uint8_t* ip_packet, unsigned long len, char* arrival_interface)
{
	// Extract the IP packet header
	sr_ip_hdr_t* ip_packet_hdr = (sr_ip_hdr_t*)ip_packet;

	// Decrement TTL by 1 and case it's now zero
	if(--ip_packet_hdr->ip_ttl <= 0)
	{
		// Restore the checksum and TTL fields to their original values before putting them back into the payload
		//     of the ICMP
		ip_packet_hdr->ip_ttl++;
		ip_packet_hdr->ip_sum = cksum(ip_packet_hdr, sr_get_ip_hdr_len(ip_packet_hdr));

		// Send an ICMP time_exceeded back to the source of the IP packet.  The data to
		//     be passed in is the IP header and up to the first 8 bytes of the IP payload
		sr_build_and_send_icmp(sr,ntohl(sr_get_interface(sr,arrival_interface)->ip),ntohl(ip_packet_hdr->ip_src),TTL_EXPIRED,ip_packet,len);
	}
	// Case the TTL did not expire, so send this IP packet out
	else
	{
		// Recompute the cksum now that the TTL has been decremented
		ip_packet_hdr->ip_sum = 0;
		ip_packet_hdr->ip_sum = cksum(ip_packet_hdr, sr_get_ip_hdr_len(ip_packet_hdr));

		// Attempt to forward it on to the destination
		sr_send_ip(sr,ip_packet,len);
	}
}

// Construct an ICMP packet given the src_ip (host order), dst_ip (host order), icmp_type, and the data+length to be attached
//     to the end of the ICMP header.  The packet is the total IP packet and its len is its total length
void sr_build_and_send_icmp(struct sr_instance* sr, uint32_t src_ip, uint32_t dest_ip, icmp_code_t icmp_code, uint8_t* packet, uint16_t len)
{
	// Extract IP packet header
	sr_ip_hdr_t* ip_packet_hdr = (sr_ip_hdr_t*)packet;

	// Assures the uniqueness of this IP packet.  Will be incremented every time we enter this function
	static uint16_t ip_id = 0;

	// Add buffer padding of four 0 bytes (UNLESS THIS IS A PING REQUEST/REPLY) between the ICMP header and the inner IP header
	int pad_bytes_len, max_bytes_from_packet;
	if(icmp_code == ECHO_REQUEST || icmp_code == ECHO_REPLY)
	{
		// The number of zeros to pad with
		pad_bytes_len = 0;

		// The data to be passed in is the IP header and up to the first 8 bytes of the IP payload
		max_bytes_from_packet = 1e6;
	}
	else
	{
		// The number of zeros to pad with
		pad_bytes_len = 4;

		// The data to be passed in is the IP header and up to the first 8 bytes of the IP payload
		max_bytes_from_packet = 8;
	}

	// The payload data to append to the ICMP
	uint8_t* data = packet;
	uint16_t data_len = sr_get_ip_hdr_len(ip_packet_hdr)+MIN(max_bytes_from_packet,len-sr_get_ip_hdr_len(ip_packet_hdr));

	// Build new IP header for this ICMP
	sr_ip_hdr_t ip_hdr;
	ip_hdr.ip_hl = 5;
	ip_hdr.ip_v = 4;
	ip_hdr.ip_tos = 0;
	ip_hdr.ip_len = htons(sr_get_ip_hdr_len(&ip_hdr)+sizeof(sr_icmp_hdr_t)+pad_bytes_len+data_len);
	ip_hdr.ip_id = htons(ip_id++);  // Unique ID of this IP packet
	ip_hdr.ip_off = htons(0);
	ip_hdr.ip_ttl = INIT_TTL;       // TTL = 255 hops
	ip_hdr.ip_p = ip_protocol_icmp;
	ip_hdr.ip_dst = htonl(dest_ip);
	ip_hdr.ip_src = htonl(src_ip);

	// Compute IP checksum just over the header bytes
	ip_hdr.ip_sum = 0;
	ip_hdr.ip_sum = cksum(&ip_hdr, sr_get_ip_hdr_len(&ip_hdr));

	// Allocate memory for the entire (IP+ICMP+ICMP_data) packet
	uint8_t* concat_packet = malloc(sr_get_ip_hdr_len(&ip_hdr)+sizeof(sr_icmp_hdr_t)+data_len+pad_bytes_len);

	// Copy the IP header
	uint8_t* copy_pointer = (uint8_t*)&ip_hdr;
	for(int i = 0; i < sr_get_ip_hdr_len(&ip_hdr); i++)
		*(concat_packet+i) = *(copy_pointer+i);

	// Build the ICMP packet which has the header and the data
	uint8_t type, code;
	switch(icmp_code)
	{
	case ECHO_REQUEST:
		type = 8;
		code = 0;
		break;
	case ECHO_REPLY:
		type = 0;
		code = 0;
		break;
	case DEST_NETWORK_UNREACHABLE:
		type = 3;
		code = 0;
		break;
	case DEST_HOST_UNREACHABLE:
		type = 3;
		code = 1;
		break;
	case DEST_PORT_UNREACHABLE:
		type = 3;
		code = 3;
		break;
	case TTL_EXPIRED:
		type = 11;
		code = 0;
		break;
	}
	sr_icmp_hdr_t icmp_hdr;
	icmp_hdr.icmp_type = type;
	icmp_hdr.icmp_code = code;
	icmp_hdr.icmp_sum = 0;

	// Copy the ICMP header
	copy_pointer = (uint8_t*)&icmp_hdr;
	for(int i = 0; i < sizeof(sr_icmp_hdr_t); i++)
		*(concat_packet+sr_get_ip_hdr_len(&ip_hdr)+i) = *(copy_pointer+i);

	// Add buffer padding of four 0 bytes between the ICMP header and the ICMP payload
	for(int i = 0; i < pad_bytes_len; i++)
		*(concat_packet+sr_get_ip_hdr_len(&ip_hdr)+sizeof(sr_icmp_hdr_t)+i) = 0;

	// Copy the ICMP payload
	for(int i = 0; i < data_len; i++)
		*(concat_packet+sr_get_ip_hdr_len(&ip_hdr)+sizeof(sr_icmp_hdr_t)+pad_bytes_len+i) = *(data+i);

	// Compute the ICMP cksum over the ICMP header and the ICMP data and store it back in the concat_packet
	sr_icmp_hdr_t* icmp_hdr_ptr = (sr_icmp_hdr_t*)(concat_packet+sr_get_ip_hdr_len(&ip_hdr));
	icmp_hdr_ptr->icmp_sum = cksum(concat_packet+sr_get_ip_hdr_len(&ip_hdr), sizeof(sr_icmp_hdr_t)+pad_bytes_len+data_len);

	// Send the constructed packet with ICMP header and ICMP data surrounded by an IP header
	sr_send_ip(sr, concat_packet, sr_get_ip_hdr_len(&ip_hdr)+sizeof(sr_icmp_hdr_t)+pad_bytes_len+data_len);

	// Free the temporary packet
	free(concat_packet);
}

#define INTERFACE_NAME_SIZE 20
// Use longest prefix matching (LPM) to send the given ip_packet, which has all its IP header and data.  If an ARP entry doesn't
//     exist for the desired outgoing interface, this packet is added to a queue and an ARP request is created and sent.
//     Caller must free the passed in IP packet afterwards.
void sr_send_ip(struct sr_instance* sr, uint8_t* ip_packet, unsigned long len)
{
	if(!ip_packet)
		return;

	// Extract the IP header
	sr_ip_hdr_t* ip_packet_hdr = (sr_ip_hdr_t*)ip_packet;

	// Check the longest prefix match in routing table to determine which interface to send this out on
	uint32_t* next_hop_ip_addr_ptr = malloc(sizeof(uint32_t)); // in host order
	char* outgoing_interface_ptr = malloc(INTERFACE_NAME_SIZE); // our own interface we're sending the packet out on
	sr_find_longest_prefix_match(sr, ntohl(ip_packet_hdr->ip_dst), next_hop_ip_addr_ptr, outgoing_interface_ptr);

	// Extract the heap values into stack variables so we don't have to worry about forgetting to free them upon
	//     early exit
	uint32_t next_hop_ip_addr = *next_hop_ip_addr_ptr;
	free(next_hop_ip_addr_ptr);
	char outgoing_interface[INTERFACE_NAME_SIZE];
	int i;
	for(i = 0; i < INTERFACE_NAME_SIZE; i++)
	{
		if((outgoing_interface_ptr+i)==0 || *(outgoing_interface_ptr+i)==0)
			break;
		outgoing_interface[i] = *(outgoing_interface_ptr+i);
	}
	outgoing_interface[i] = 0;
	free(outgoing_interface_ptr);

	// Get the sr_if interface variable corresponding to the char* outgoing_interface
	struct sr_if* sr_outgoing_interface = sr_get_interface(sr,outgoing_interface);

	// Case no interface exists with this char*
	if(!sr_outgoing_interface || next_hop_ip_addr == 0)
	{
		sr_build_and_send_icmp(sr,ntohl(sr->if_list->ip),ntohl(ip_packet_hdr->ip_src),DEST_NETWORK_UNREACHABLE,ip_packet,len);
		return;
	}

	// Start building the ethernet header to this IP packet
	sr_ethernet_hdr_t eth_hdr;
	eth_hdr.ether_type = htons(ethertype_ip);

	// Fill in the source ethernet addr
	for(int i = 0; i < ETHER_ADDR_LEN; i++)
		eth_hdr.ether_shost[i] = sr_outgoing_interface->addr[i];

	// Put the header and payload together to build the (ethernet_hdr+IP_hdr+IP_payload) packet
	uint8_t* concat_packet = malloc(sizeof(sr_ethernet_hdr_t)+len);
	sr_concatenate_header_and_payload((uint8_t*)&eth_hdr, sizeof(sr_ethernet_hdr_t), (uint8_t*)ip_packet, len, concat_packet);

	// Check the ARP cache for the next hop MAC address.  IP lookup is in network order
	struct sr_arpentry* entry = sr_arpcache_lookup(&sr->cache, htonl(next_hop_ip_addr));

	// Case an ARP entry exists in the cache
	if(entry)
	{
		// So fill in the destination ethernet address (by pointing back to the ethernet header)
		sr_ethernet_hdr_t* eth_hdr_ptr = (sr_ethernet_hdr_t*)concat_packet;
		for(int i = 0; i < ETHER_ADDR_LEN; i++)
			eth_hdr_ptr->ether_dhost[i] = entry->mac[i];

		// Send ethernet packet
		sr_send_ethernet(sr, concat_packet, len+sizeof(sr_ethernet_hdr_t));

		// Cleanup the entry from sr_arpcache_lookup()
		free(entry);
	}
	// Case an ARP entry doesn't exist in the cache
	else
	{
		// Add this packet to the queue of the IP ARP request.  IP address is in network byte order
		uint8_t* data = concat_packet;
		uint16_t data_len = len+sizeof(sr_ethernet_hdr_t);
		struct sr_arpreq* arp_req = sr_arpcache_queuereq(&sr->cache, htonl(next_hop_ip_addr), data, data_len, outgoing_interface);

		// Case we can send this ARP req again, so call sr_send_arp()
		if(sr_can_send_arp_req(sr, arp_req))
		{
			// A broadcast ethernet address
			unsigned char broadcast_addr[ETHER_ADDR_LEN];
			for(int i = 0; i < ETHER_ADDR_LEN; i++)
				broadcast_addr[i] = 0xff;

			// Build an ARP request header to send.  src_ip = this router's outgoing interface's IP, dst_ip = the next hop's IP
			//     src_eth = this router's outgoing interface's ethernet, dst_eth = broadcast address
			sr_arp_hdr_t* arp_hdr = malloc(sizeof(sr_arp_hdr_t));
			sr_build_arp(sr_outgoing_interface->addr, ntohl(sr_outgoing_interface->ip), broadcast_addr, next_hop_ip_addr, arp_op_request, arp_hdr);

			// Send the ARP request
			sr_send_arp(sr, (uint8_t*)arp_hdr, sizeof(sr_arp_hdr_t));

			// Free the malloc'd ARP header once it's been sent
			free(arp_hdr);
		}
	}
	// Free the (ethernet_hdr+IP_hdr+IP_payload) packet whether we sent it right away or put it in an arp_req
	free(concat_packet);
}

// Builds an ARP header given the passed in information in the malloc'd (but blank) arp_hdr bucket variable.
//     Caller passes in a blank arp_hdr, which they must free after this function returns.  src_ip, dst_ip are in host order
void sr_build_arp(unsigned char* src_eth, uint32_t src_ip, unsigned char* dst_eth, uint32_t dst_ip, unsigned short op_code, sr_arp_hdr_t* arp_hdr)
{
	if(!arp_hdr)
		return;

	// Set the source and destination ethernet fields of the ARP request based on the passed in ethernet arguments
	for(int i = 0; i < ETHER_ADDR_LEN; i++)
	{
		arp_hdr->ar_sha[i] = src_eth[i];
		arp_hdr->ar_tha[i] = dst_eth[i];
	}

	// Build the other ARP header fields
	arp_hdr->ar_hrd = htons(arp_hrd_ethernet); // hardware format = ethernet
	arp_hdr->ar_pro = htons(ethertype_ip);     // protocol = IP
	arp_hdr->ar_hln = ETHER_ADDR_LEN;          // length of hardware address in bytes
	arp_hdr->ar_pln = sizeof(uint32_t); 	   // length of IP address in bytes
	arp_hdr->ar_op = htons(op_code);           // operation code (request or reply)
	arp_hdr->ar_sip = htonl(src_ip); 		   // IP address of the interface we're sending over
	arp_hdr->ar_tip = htonl(dst_ip);           // IP address we'd like a response from
}

#define MAX_ARP_SEND_TIMES 5
// Determines by the number of times this arp_req has been sent and how long it's been since it was last sent whether
//     it can be sent again.  If it can, update the count and the most recent sent time.
//     If not, send an ICMP host unreachable and call arpreq_destroy().  The caller still has to call sr_send_arp()
//     to actually send the ARP packet.  Returns 1 if the packet is eligible to be sent again, 0 otherwise.
int sr_can_send_arp_req(struct sr_instance *sr, struct sr_arpreq* arp_req)
{
	// Case no arp_req was passed in, so don't let them send the ARP request
	if(!arp_req)
		return 0;

	// Get the current time
	time_t curr_time = time(NULL);

	// Case it has been long enough since we last sent this ARP request, so do something with this arp_req
	if(difftime(curr_time, arp_req->sent) <= 1.0)
		return 0;

	// Case we've sent more than 5 times, so send an ICMP host unreachable and destroy this arp_req
	if(arp_req->times_sent >= MAX_ARP_SEND_TIMES)
	{
		// Send the ICMP host unreachable back to the SENDER of each of the packets in the linked list
		//     as long as that sender isn't one of this router's interfaces
		struct sr_packet* packet = arp_req->packets;
		while(packet)
		{
			// Extract the IP header and beyond out of the ethernet packet
			sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)(packet->buf + sizeof(sr_ethernet_hdr_t));
			uint32_t dst_ip = ntohl(ip_hdr->ip_src);

			// As long as this router didn't create the message, send host unreachable ICMP packet
			if(!sr_is_my_interface(sr, dst_ip))
			{
				// Send an ICMP host unreachable.  The data to be passed in is the IP header and up to the first
				//     8 bytes of the IP payload
				sr_build_and_send_icmp(sr,ntohl(sr->if_list->ip),dst_ip,DEST_HOST_UNREACHABLE,packet->buf+sizeof(sr_ethernet_hdr_t),packet->len);
			}

			// Consider the next packet in the linked list
			packet = packet->next;
		}

		// Remove the ARP request from memory
		sr_arpreq_destroy(&sr->cache,arp_req);
		return 0;
	}

	// Case this ARP request has passed all the checks so we can try (re)sending it.  Also, update the number
	//     of times it's been sent and the last send time
	arp_req->times_sent++;
	arp_req->sent = curr_time;
	return 1;
}

// Given an ARP packet with a fully-built ARP header, will determine and attach the ethernet header and send it out
void sr_send_arp(struct sr_instance* sr, uint8_t* arp_packet, unsigned long len)
{
	// Extract the ARP header
	sr_arp_hdr_t* arp_hdr = (sr_arp_hdr_t*)arp_packet;

	// Build the ethernet header
	sr_ethernet_hdr_t eth_hdr;
	eth_hdr.ether_type = htons(ethertype_arp);

	// Set the ethernet source and destination fields from the ARP's similar information
	for(int i = 0; i < ETHER_ADDR_LEN; i++)
	{
		eth_hdr.ether_shost[i] = arp_hdr->ar_sha[i];
		eth_hdr.ether_dhost[i] = arp_hdr->ar_tha[i];
	}

	// Put the header and payload together to build the packet
	uint8_t* concat_packet = malloc(sizeof(sr_ethernet_hdr_t)+len);
	sr_concatenate_header_and_payload((uint8_t*)&eth_hdr, sizeof(sr_ethernet_hdr_t), (uint8_t*)arp_packet, len, concat_packet);

	// Pass in the (ethernet+ARP) payload and its length to send the ethernet packet out over
	sr_send_ethernet(sr, (uint8_t*)concat_packet, sizeof(sr_ethernet_hdr_t)+sizeof(sr_arp_hdr_t));

	// Free the malloc'd packet
	free(concat_packet);
}

// Given an ethernet packet with a fully-built ethernet header, will determine which interface to send this over and send it
void sr_send_ethernet(struct sr_instance* sr, uint8_t* ethernet_packet, unsigned long len)
{
	// Extract the ethernet header
	sr_ethernet_hdr_t* eth_hdr = (sr_ethernet_hdr_t*)ethernet_packet;

	// Determine the router's outbound interface to use based on the ethernet address
	struct sr_if* sr_sending_interface = sr_get_interface_from_eth_addr(sr, eth_hdr->ether_shost);
	if(!sr_sending_interface)
		return;

	// Send the packet over the ethernet link
	sr_send_packet(sr, ethernet_packet, len, sr_sending_interface->name);
}

// Given a IP packet, this function computes and returns the TCP cksum over the IP pseudo header,
//     TCP header, and TCP payload.  The result is already in network order
uint16_t sr_compute_tcp_cksum(uint8_t* packet, unsigned int len)
{
	// Extract IP header
	sr_ip_hdr_t* ip_hdr = (sr_ip_hdr_t*)packet;

	// Extract TCP header
	sr_tcp_hdr_t* tcp_hdr = (sr_tcp_hdr_t*)(packet+sr_get_ip_hdr_len(ip_hdr));

	// Make sure to set the TCP cksum to zero before computing
	tcp_hdr->tcp_cksum = 0;

	// Create the IP pseudo header out of some select fields from the IP header passed in
	sr_ip_pseudo_hdr_t ip_pseudo_hdr;
	ip_pseudo_hdr.ip_src = ip_hdr->ip_src;
	ip_pseudo_hdr.ip_dst = ip_hdr->ip_dst;
	ip_pseudo_hdr.ip_reserved = 0;
	ip_pseudo_hdr.ip_protocol = ip_hdr->ip_p;
	ip_pseudo_hdr.ip_tcp_len = htons(len-sr_get_ip_hdr_len(ip_hdr));

	// Concatenate the IP pseudo header with the TCP header and its payload
	uint8_t* concat_ip_pseudo_hdr_with_tcp_hdr_and_payload = malloc(sizeof(sr_ip_pseudo_hdr_t)+len-sr_get_ip_hdr_len(ip_hdr));
	sr_concatenate_header_and_payload((uint8_t*)&ip_pseudo_hdr,sizeof(sr_ip_pseudo_hdr_t),packet+sr_get_ip_hdr_len(ip_hdr),
			len-sr_get_ip_hdr_len(ip_hdr),concat_ip_pseudo_hdr_with_tcp_hdr_and_payload);

	// Compute the cksum over this concatenated result
	uint16_t computed_cksum = cksum(concat_ip_pseudo_hdr_with_tcp_hdr_and_payload, sizeof(sr_ip_pseudo_hdr_t)+len-sr_get_ip_hdr_len(ip_hdr));

	// Free the memory used in computing the cksum, now that we have the result
	free(concat_ip_pseudo_hdr_with_tcp_hdr_and_payload);

	// Store the result in the appropriate TCP header field and return the value
	tcp_hdr->tcp_cksum = computed_cksum;
	return computed_cksum;
}

// Concatenate the header with the payload and store the result in "result".  This function expects result
//     to be malloc'd ahead of time and this function won't free any memory
void sr_concatenate_header_and_payload(uint8_t* header, size_t header_len, uint8_t* payload, size_t payload_len, uint8_t* result)
{
	// Case there was a malloc failure
	if(!header || !payload || !result)
		return;

	// Copy the header
	for(int i = 0; i < header_len; i++)
		*(result+i) = *(header+i);

	// Copy the payload
	for(int i = 0; i < payload_len; i++)
		*(result+header_len+i) = *(payload+i);
}

// Longest prefix matching --------

// Simply reverses the order of the 32 bits in the incoming integer
uint32_t reverse_bits_of_uint32(uint32_t number)
{
	number = (((number & 0xaaaaaaaa) >> 1) | ((number & 0x55555555) << 1));
	number = (((number & 0xcccccccc) >> 2) | ((number & 0x33333333) << 2));
	number = (((number & 0xf0f0f0f0) >> 4) | ((number & 0x0f0f0f0f) << 4));
	number = (((number & 0xff00ff00) >> 8) | ((number & 0x00ff00ff) << 8));
	return((number >> 16) | (number << 16));
}

// Tallies up the number of consecutive ones, counting from the left, until a zero is reached.
//     Used for determining the subnet mask's length
int count_number_of_ones_from_left(uint32_t number)
{
	// It's easier to count from right to left, so first flip the number
	uint32_t reversed_number = reverse_bits_of_uint32(number);

	// Iteratively count up the number of consecutive ones from right to left
	int num_ones = 0;
	for(int i = 0; i < sizeof(uint32_t)*8; i++)
	{
		if(((reversed_number >> i) & 1) == 1)
			num_ones++;
		else
			break;
	}
	return num_ones;
}

// Determines which local interface and next hop IP the packet corresponding to this dest_ip_addr should be sent over.
//     dest_ip_addr and next_hop_addr are host order.  next_hop_ip_addr = IP address of the other link,
//     outgoing_interface = name of this router's link.  If no matches and not even a default gateway are found,
//     *next_hop_ip_addr=*outgoing_interface=0
void sr_find_longest_prefix_match(struct sr_instance* sr, uint32_t dest_ip_addr, uint32_t* next_hop_ip_addr, char* outgoing_interface)
{
	if(!next_hop_ip_addr || !outgoing_interface)
		return;

	*next_hop_ip_addr = 0;
	*outgoing_interface = 0;

	struct sr_rt* routing_table = sr->routing_table;
	int most_bits_matches = -1;

	// Cycle through all entries in the routing table
	while(routing_table)
	{
		// The number of bits we care about, counting from the left
		uint32_t mask = ntohl((uint32_t)routing_table->mask.s_addr);

		// Find the number of consecutive ones from the left in the subnet mask
		//     Set to zero for the default gateway case
		int care_bits = count_number_of_ones_from_left(mask);

		// Try to match as many bits as possible, except for the default gateway case
		uint32_t routing_addr = ntohl((uint32_t)routing_table->dest.s_addr);
		int num_bits_matched = 0;
		int left_most_bit = sizeof(uint32_t)*8;
		for(int i = left_most_bit; i > left_most_bit-care_bits; i--)
		{
			uint32_t routing_addr_bit_i = (routing_addr >> (i-1)) & 1;
			uint32_t dest_ip_addr_bit_i = (dest_ip_addr >> (i-1)) & 1;
			if(routing_addr_bit_i == dest_ip_addr_bit_i)
				num_bits_matched++;
			else
				break;
		}
		// Case this matches the most number of bits yet (and it's actually a match)
		if((num_bits_matched == care_bits) && num_bits_matched > most_bits_matches)
		{
			// Update the most number of bits matched
			most_bits_matches = num_bits_matched;

			// Copy the IP address
			*next_hop_ip_addr = ntohl((uint32_t)routing_table->gw.s_addr);

			// Copy the interface name
			int i;
			for(i = 0; i < INTERFACE_NAME_SIZE; i++)
			{
				if((routing_table->interface+i)==0 || *(routing_table->interface+i)==0)
					break;
				outgoing_interface[i] = *(routing_table->interface+i);
			}
			outgoing_interface[i] = 0;
		}
		routing_table = routing_table->next;
	}
}

// Loops through all interfaces in this sr and checks to see if any one's IP address matches ip_addr.  ip_addr is in
//     host order
int sr_is_my_interface(struct sr_instance* sr, uint32_t ip_addr)
{
	// Convert the desired IP address into network order
	uint32_t ip_addr_network = htonl(ip_addr);

	// Loop through all interfaces on this router
	struct sr_if* list_head = sr->if_list;
	while(list_head)
	{
		// Case we have a match (in network order)
		if(ip_addr_network == list_head->ip)
			return 1;

		// Go to the next interface entry
		list_head = list_head->next;
	}
	return 0;
}

// Does a reverse lookup using the ethernet address to return the desired sr_if* of the router.  Returns NULL pointer
//     if no match found
struct sr_if* sr_get_interface_from_eth_addr(struct sr_instance* sr, unsigned char* eth_addr)
{
	// Loop through all IP's in the list
	struct sr_if* sr_interface = sr->if_list;
	while(sr_interface)
	{
		// Check if this is the matching interface by all ethernet address bytes matching
		size_t match = 1;
		for(int i = 0; i < ETHER_ADDR_LEN && match; i++)
		{
			if(sr_interface->addr[i] != eth_addr[i])
				match = 0;
		}

		// Case we just found a match
		if(match)
			return sr_interface;

		// Otherwise, move to the next interface
		sr_interface = sr_interface->next;
	}
	return 0;
}

// Checks if this packet is external (inbound) based on its arrival_interface
uint8_t sr_is_external(struct sr_instance* sr, char* arrival_interface)
{
	return sr_char_array_compare(arrival_interface,EXTERNAL_INTERFACE);
}

// Checks if this packet is internal (outbound) based on its arrival_interface
uint8_t sr_is_internal(struct sr_instance* sr, char* arrival_interface)
{
	return sr_char_array_compare(arrival_interface,INTERNAL_INTERFACE);
}

// Returns the length field of the IP header in bytes (since it is variable and depends on
//     the value stored in the ip_hl field).  We should never just use sizeof(sr_ip_hdr_t)
unsigned int sr_get_ip_hdr_len(sr_ip_hdr_t* ip_hdr)
{
	return ip_hdr->ip_hl*4;
}

// Given two null-terminated char arrays, determines if they are exactly equal
uint8_t sr_char_array_compare(char* first, char* second)
{
	int i = 0;
	while(first[i] && second[i] && i < sr_IFACE_NAMELEN)
	{
		if(first[i] != second[i])
			return 0;
		i++;
	}
	// Case we're at the end of one char array but not at the end of the other, so they
	//     can't be equivalent.  Or we may have gone through more characters than
	//     are allowed in an interface name
	if((!first[i] && second[i]) || (first[i] && !second[i]) || i==sr_IFACE_NAMELEN)
		return 0;

	return 1;
}
