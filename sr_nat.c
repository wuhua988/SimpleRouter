
#include <signal.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h> // for malloc and free
#include <string.h> // for memcpy
#include "sr_nat.h"
#include "sr_router.h"
#include "sr_utils.h"

int sr_nat_init(struct sr_nat *nat, uint32_t icmp_query_timeout, uint32_t tcp_est_timeout, uint32_t tcp_trans_timeout)
{
	assert(nat);

	/* Acquire mutex lock */
	pthread_mutexattr_init(&(nat->attr));
	pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
	int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

	/* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

	// Initalize timeouts, in seconds
	nat->mappings = NULL;
	nat->silently_dropped_syns = NULL;
	nat->icmp_query_timeout = icmp_query_timeout;
	nat->tcp_est_timeout = tcp_est_timeout;
	nat->tcp_trans_timeout = tcp_trans_timeout;
	nat->silently_dropped_syn_timeout = 6;
	nat->min_mapping_timeout = 1;

	// Initialize sorted, growing double-linked list of ports
	uint16_t min_port_number = 1024;
	uint16_t max_port_number = 65535;
	set_min_value_and_max_value(min_port_number,max_port_number);
	nat->port_numbers = malloc(sizeof(list_entry_t));
	nat->port_numbers->value = min_port_number;
	nat->port_numbers->prev = 0;
	nat->port_numbers->next = 0;

	return success;
}

int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

	pthread_mutex_lock(&(nat->lock));

	// Free the port number memory
	list_entry_t* port_number = nat->port_numbers;
	list_entry_t* next_port_number = 0;
	while(port_number)
	{
		// Store the next in the list so that we can safely free this one
		next_port_number = port_number->next;
		next_port_number->prev = 0;
		free(port_number);

		// Shift to the next in the list
		port_number = next_port_number;
	}

	// Free the "silently dropped" SYN memory
	sr_nat_incoming_syn_packet_t* silently_dropped_syn = nat->silently_dropped_syns;
	sr_nat_incoming_syn_packet_t* next_silently_dropped_syn = 0;
	while(silently_dropped_syn)
	{
		// Store the next in the list so that we can safely free this one
		next_silently_dropped_syn = silently_dropped_syn->next;
		next_silently_dropped_syn->prev = 0;

		// Free the data packet and the overall struct
		free(silently_dropped_syn->packet);
		free(silently_dropped_syn);

		// Shift to the next in the list
		silently_dropped_syn = next_silently_dropped_syn;
	}

	// Free the mapping memory
	sr_nat_mapping_t* mapping = nat->mappings;
	sr_nat_mapping_t* next_mapping = 0;
	while(mapping)
	{
		// Store the next in the list so that we can safely free this one
		next_mapping = mapping->next;
		next_mapping->prev = 0;

		struct sr_nat_connection* conn = mapping->conns;
		struct sr_nat_connection* next_conn = 0;
		while(conn)
		{
			// Store the next in the list so that we can safely free this one
			next_conn = conn->next;
			next_conn->prev = 0;
			free(conn);

			// Shift to the next in the list
			conn = next_conn;
		}
		free(mapping);

		// Shift to the next in the list
		mapping = next_mapping;
	}

	pthread_kill(nat->thread, SIGKILL);
	return pthread_mutex_destroy(&(nat->lock)) &&
			pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *sr_ptr) {  /* Periodic Timout handling */
	struct sr_instance* sr = sr_ptr;
	struct sr_nat* nat = &(sr->nat);

	while (1) {
		sleep(1.0);
		pthread_mutex_lock(&(nat->lock));

		// Get the current time
		time_t curr_time = time(NULL);

		// UPDATE SILENTLY DROPPED INCOMING SYN LIST
		// Loop through all entries in the "silently dropped" incoming SYN's list.  If any have
		//     expired (are older than 6 seconds), then send an ICMP (3,3) back to their sender
		sr_nat_incoming_syn_packet_t* silently_dropped_syn = nat->silently_dropped_syns;
		while(silently_dropped_syn)
		{
			// Case this silently dropped SYN has been in this list too long
			if(difftime(curr_time,silently_dropped_syn->arrival_time) >= nat->silently_dropped_syn_timeout)
			{
				// Extract the IP packet header
				sr_ip_hdr_t* ip_packet_hdr = (sr_ip_hdr_t*)silently_dropped_syn->packet;

				// Send an ICMP port unreachable with the IP header + 8 bytes of the payload to go into the ICMP packet.
				//     The data to be passed in is the IP header and up to the first 8 bytes of the IP payload
				sr_build_and_send_icmp(sr,ntohl(sr_get_interface(sr,silently_dropped_syn->arrival_interface)->ip),
						ntohl(ip_packet_hdr->ip_src),DEST_PORT_UNREACHABLE,silently_dropped_syn->packet,silently_dropped_syn->packet_len);

				// Remove this entry from the list and free it
				sr_nat_incoming_syn_packet_t* next_ptr = silently_dropped_syn->next;
				if(silently_dropped_syn->prev)
					silently_dropped_syn->prev->next = silently_dropped_syn->next;
				if(silently_dropped_syn->next)
					silently_dropped_syn->next->prev = silently_dropped_syn->prev;

				// Repoint the head of the list
				if(silently_dropped_syn == nat->silently_dropped_syns)
					nat->silently_dropped_syns = silently_dropped_syn->next;

				// Free the memory
				free(silently_dropped_syn->packet);
				free(silently_dropped_syn->arrival_interface);
				free(silently_dropped_syn);

				// Move to the next entry in the list of silently dropped SYN's
				silently_dropped_syn = next_ptr;
			}
			// Move to the next entry in the list of silently dropped SYN's
			else
				silently_dropped_syn = silently_dropped_syn->next;
		}

		// UPDATE MAPPING ENTRIES
		struct sr_nat_mapping* mapping = nat->mappings;
		while(mapping)
		{
			// Check to see if any connections are overdue and need to be torn down
			struct sr_nat_connection* connection = mapping->conns;
			while(connection)
			{
				// Case this connection is in one of the transitory states
				uint8_t in_trans_state = connection->tcp_state==WAITING_SYN ||
						connection->tcp_state==WAITING_SYN_ACK ||
						connection->tcp_state==WAITING_ACK ||
						connection->tcp_state==FIN_RECEIVED;

				// Case this connection is in transitory or established state and has expired
				if((in_trans_state && difftime(curr_time,connection->last_updated) >= nat->tcp_trans_timeout) ||
						(connection->tcp_state==ESTABLISHED && difftime(curr_time,connection->last_updated) >= nat->tcp_est_timeout))
				{
					// Save a pointer to the next entry, because we'll be freeing this one soon
					struct sr_nat_connection* next_conn = connection->next;

					// Set the links around this entry
					if(connection->prev)
						connection->prev->next = connection->next;
					if(connection->next)
						connection->next->prev = connection->prev;
					if(mapping->conns == connection)
						mapping->conns = connection->next;

					// Free the entry and move to the next one
					free(connection);
					connection = next_conn;
				}
				// Case this connection should be left alone, so move to the next in the list
				else
					connection = connection->next;
			}

			// Case this is an ICMP mapping and past the query timeout limit
			if(mapping->type==nat_mapping_icmp && difftime(curr_time,mapping->last_updated) >= nat->icmp_query_timeout)
			{
				pthread_mutex_unlock(&(nat->lock));
				sr_nat_remove_mapping_by_external(nat,mapping->aux_ext,nat_mapping_icmp);
				pthread_mutex_lock(&(nat->lock));
			}

			// Case this is a TCP mapping and the mapping has no more connections (and it's at least 1 second old)
			else if(mapping->type==nat_mapping_tcp && !mapping->conns &&
					difftime(curr_time,mapping->last_updated) >= nat->min_mapping_timeout)
			{
				// So tear it down
				pthread_mutex_unlock(&(nat->lock));
				sr_nat_remove_mapping_by_external(nat,mapping->aux_ext,nat_mapping_tcp);
				pthread_mutex_lock(&(nat->lock));
			}

			mapping = mapping->next;
		}
		pthread_mutex_unlock(&(nat->lock));
	}
	return NULL;
}

// **** MAPPINGS ****

// Look up one of the NAT's mappings based on either external (aux_ext) or internal (ip_int,aux_int) parameters.  This set of
//     functions returns an actual pointer to the mapping - not a copy (so don't free it)
struct sr_nat_mapping *sr_nat_lookup_external_ptr(struct sr_nat *nat,
		uint16_t aux_ext, sr_nat_mapping_type type )
{
	return sr_nat_lookup_ptr(nat,0,0,aux_ext,type,0);
}
struct sr_nat_mapping *sr_nat_lookup_internal_ptr(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type )
{
	return sr_nat_lookup_ptr(nat,ip_int,aux_int,0,type,1);
}
struct sr_nat_mapping *sr_nat_lookup_ptr(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, uint16_t aux_ext,
		sr_nat_mapping_type type, uint8_t is_internal)
{
	pthread_mutex_lock(&(nat->lock));

	// Lookup mapping
	struct sr_nat_mapping* mapping = nat->mappings;
	while(mapping)
	{
		// Case the parameters match for an internal or external lookup
		if((is_internal && mapping->type==type && mapping->aux_int==aux_int && mapping->ip_int==ip_int) ||
				(!is_internal && mapping->type==type && mapping->aux_ext==aux_ext))
			break;
		mapping = mapping->next;
	}

	pthread_mutex_unlock(&(nat->lock));
	return mapping;
}

// Look up one of the NAT's mappings based on either external (aux_ext) or internal (ip_int,aux_int) parameters.  This set of
//     functions returns just a copy to the mapping.  The caller must free the returned mapping if it is not NULL
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
		uint16_t aux_ext, sr_nat_mapping_type type )
{
	return sr_nat_lookup(nat,0,0,aux_ext,type,0);
}
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type )
{
	return sr_nat_lookup(nat,ip_int,aux_int,0,type,1);
}
struct sr_nat_mapping *sr_nat_lookup(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, uint16_t aux_ext,
		sr_nat_mapping_type type, uint8_t is_internal)
{
	// Delegate the lookup to the previously-written sr_nat_lookup_ptr() function
	struct sr_nat_mapping* mapping = sr_nat_lookup_ptr(nat,ip_int,aux_int,aux_ext,type,is_internal);
	struct sr_nat_mapping* copy = NULL;

	// Make a copy of the mapping returned
	if(mapping)
	{
		copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
		memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
	}
	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

// Insert a new mapping into the nat's mapping table.  The caller must free the returned mapping if it is not NULL
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, uint32_t ip_ext, sr_nat_mapping_type type )
{
	pthread_mutex_lock(&(nat->lock));

	// Case we already have this mapping, so just return it
	pthread_mutex_unlock(&(nat->lock));
	struct sr_nat_mapping *mapping = sr_nat_lookup_internal(nat,ip_int,aux_int,type);
	pthread_mutex_lock(&(nat->lock));
	if(mapping)
	{
		pthread_mutex_unlock(&(nat->lock));
		return mapping;
	}

	/* handle insert here, create a mapping, and then return a copy of it */
	mapping = malloc(sizeof(struct sr_nat_mapping));
	mapping->type = type;
	mapping->ip_int = ip_int;
	mapping->aux_int = aux_int;
	mapping->ip_ext = ip_ext;
	mapping->conns = NULL;
	mapping->last_updated = time(NULL);
	mapping->prev = 0;

	// Get port out of linked list head
	list_entry_t* front_entry = front(&nat->port_numbers);
	mapping->aux_ext = (uint16_t)(front_entry->value);

	// Take this port number out of the available list of port numbers
	pop_front(&nat->port_numbers);
	free(front_entry);

	// Add this mapping into the beginning of the linked list
	mapping->next = nat->mappings;
	// Case there's already something in the list, so make its prev point to the new entry
	if(nat->mappings)
		nat->mappings->prev = mapping;
	nat->mappings = mapping;

	/* Must return a copy b/c another thread could jump in and modify
         table after we return. */
	struct sr_nat_mapping* copy = 0;
	if(mapping)
	{
		copy = (struct sr_nat_mapping *) malloc(sizeof(struct sr_nat_mapping));
		memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
	}

	pthread_mutex_unlock(&(nat->lock));
	return copy;
}

// Lookup and remove a mapping (if it exists) based on either external (aux_ext) or internal (ip_int+aux_int) parameters
void sr_nat_remove_mapping_by_external(struct sr_nat *nat,
		uint16_t aux_ext, sr_nat_mapping_type type )
{
	// Call the generic remove mapping code but signal that the entry is to
	//     be removed by its external parameters
	sr_nat_remove_mapping(nat,0,0,aux_ext,type,0);
}
void sr_nat_remove_mapping_by_internal(struct sr_nat *nat,
		uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type )
{
	// Call the generic remove mapping code but signal that the entry is to
	//     be removed by its internal parameters
	sr_nat_remove_mapping(nat,ip_int,aux_int,0,type,1);
}
void sr_nat_remove_mapping(struct sr_nat *nat, uint32_t ip_int,
		uint16_t aux_int, uint16_t aux_ext, sr_nat_mapping_type type,
		uint8_t is_internal)
{
	pthread_mutex_lock(&(nat->lock));

	// Loop through all mappings
	struct sr_nat_mapping* mapping = nat->mappings;
	while(mapping)
	{
		// Case the parameters match for an internal or external removal
		if((is_internal && mapping->type==type && mapping->aux_int==aux_int && mapping->ip_int==ip_int) ||
				(!is_internal && mapping->type==type && mapping->aux_ext==aux_ext))
		{
			// Reconnect the connections of the entry to its neighbors
			if(mapping->prev)
				mapping->prev->next = mapping->next;
			if(mapping->next)
				mapping->next->prev = mapping->prev;

			// Case we're removing the head, so repoint the head pointer to the next in line
			if(mapping == nat->mappings)
				nat->mappings = mapping->next;

			// Put the port from this entry back into the list
			list_entry_t* port_number = malloc(sizeof(list_entry_t));
			port_number->value = mapping->aux_ext;
			push(&nat->port_numbers,port_number);

			// Free the memory and exit
			free(mapping);
			mapping = NULL;

			break;
		}
		mapping = mapping->next;
	}
	pthread_mutex_unlock(&(nat->lock));
}

// **** CONNECTIONS ****

// Given an IP packet with a TCP payload, set SYN silently dropped packets from the list to receive ICMP port unreachables
void sr_nat_received_external_initial_syn(struct sr_nat *nat, uint8_t* packet, unsigned int packet_len, char* arrival_interface)
{
	pthread_mutex_lock(&(nat->lock));

	// Extract the IP and TCP headers
	sr_ip_hdr_t* ip_packet_hdr = (sr_ip_hdr_t*)packet;
	sr_tcp_hdr_t* tcp_hdr = (sr_tcp_hdr_t*)(packet+sr_get_ip_hdr_len(ip_packet_hdr));

	// Extract the source IP, source port, and destination port
	uint16_t a = ntohs(tcp_hdr->tcp_dst_port); // Destination port (host order)
	uint32_t B = ntohl(ip_packet_hdr->ip_src); // Source IP (host order)
	uint16_t b = ntohs(tcp_hdr->tcp_src_port); // Source port (host order)

	sr_nat_incoming_syn_packet_t* silently_dropped_syn = nat->silently_dropped_syns;

	// First check to see if an entry for (a,B,b) already exists
	while(silently_dropped_syn)
	{
		// Case we have a match
		if(silently_dropped_syn->a==a && silently_dropped_syn->B==B && silently_dropped_syn->b==b)
		{
			pthread_mutex_unlock(&(nat->lock));
			return;
		}
		// Look at the next entry in the list
		silently_dropped_syn = silently_dropped_syn->next;
	}
	// Case we didn't find an entry already in the list, so create a new one at the head
	silently_dropped_syn = malloc(sizeof(sr_nat_incoming_syn_packet_t));
	silently_dropped_syn->a = a;
	silently_dropped_syn->B = B;
	silently_dropped_syn->b = b;
	silently_dropped_syn->prev = 0;
	silently_dropped_syn->arrival_time = time(NULL);

	silently_dropped_syn->arrival_interface = malloc(sr_IFACE_NAMELEN);
	int i = 0;
	while(arrival_interface[i] && i < sr_IFACE_NAMELEN)
	{
		silently_dropped_syn->arrival_interface[i] = arrival_interface[i];
		i++;
	}
	silently_dropped_syn->arrival_interface[i] = 0;

	// Deep copy the packet data into the struct just in case the caller frees it before we get to use it
	silently_dropped_syn->packet = malloc(packet_len);
	for(i=0; i<packet_len; i++)
		*(silently_dropped_syn->packet+i) = *(packet+i);
	silently_dropped_syn->packet_len = packet_len;

	// Insert the new entry into the head of the list
	silently_dropped_syn->next = nat->silently_dropped_syns;

	// Case there's already something in the list, so make its prev point to the new entry
	if(nat->silently_dropped_syns)
		nat->silently_dropped_syns->prev = silently_dropped_syn;
	nat->silently_dropped_syns = silently_dropped_syn;

	pthread_mutex_unlock(&(nat->lock));
}

// Given an IP packet with a TCP payload, remove SYN silently dropped packets from the list to receive ICMP port unreachables
void sr_nat_received_internal_initial_syn(struct sr_nat *nat, uint8_t* packet, unsigned int packet_len, char* arrival_interface)
{
	pthread_mutex_lock(&(nat->lock));

	// Extract the source IP, source port, and destination port
	sr_ip_hdr_t* ip_packet_hdr = (sr_ip_hdr_t*)packet;
	sr_tcp_hdr_t* tcp_hdr = (sr_tcp_hdr_t*)(packet+sr_get_ip_hdr_len(ip_packet_hdr));
	uint16_t a = ntohs(tcp_hdr->tcp_src_port); // Source port (host order)
	uint32_t B = ntohl(ip_packet_hdr->ip_dst); // Destination IP (host order)
	uint16_t b = ntohs(tcp_hdr->tcp_dst_port); // Destination port (host order)

	// Loop through the list of "silently dropped" SYN packets and remove the entry
	//     corresponding to the tuple {a,B,b}
	sr_nat_incoming_syn_packet_t* silently_dropped_syn = nat->silently_dropped_syns;
	while(silently_dropped_syn)
	{
		// Case this is the entry we want to remove
		if(silently_dropped_syn->B==B && silently_dropped_syn->a==a && silently_dropped_syn->b==b)
		{
			// Remove this entry from the list and free it
			if(silently_dropped_syn->prev)
				silently_dropped_syn->prev->next = silently_dropped_syn->next;
			if(silently_dropped_syn->next)
				silently_dropped_syn->next->prev = silently_dropped_syn->prev;

			// Repoint the head of the list
			if(silently_dropped_syn == nat->silently_dropped_syns)
				nat->silently_dropped_syns = silently_dropped_syn->next;

			// Free the memory
			free(silently_dropped_syn->packet);
			free(silently_dropped_syn->arrival_interface);
			free(silently_dropped_syn);

			// Stop searching now that we found the entry
			break;
		}
		silently_dropped_syn = silently_dropped_syn->next;
	}
	pthread_mutex_unlock(&(nat->lock));
}

// Look up one of the NAT's connections given an IP packet that has already be checked for correctness.  This set of
//     functions returns just a copy to the connection.  The caller must free the returned connection if it is not NULL
struct sr_nat_connection* sr_nat_lookup_connection_external(struct sr_nat* nat, uint8_t* packet, unsigned int packet_len)
{
	return sr_nat_lookup_connection(nat,packet,packet_len,0);
}
struct sr_nat_connection* sr_nat_lookup_connection_internal(struct sr_nat* nat, uint8_t* packet, unsigned int packet_len)
{
	return sr_nat_lookup_connection(nat,packet,packet_len,1);
}
struct sr_nat_connection* sr_nat_lookup_connection(struct sr_nat* nat, uint8_t* packet, unsigned int packet_len, uint8_t is_internal)
{
	pthread_mutex_lock(&(nat->lock));

	// Extract the IP and TCP headers
	sr_ip_hdr_t* ip_packet_hdr = (sr_ip_hdr_t*)packet;
	sr_tcp_hdr_t* tcp_hdr = (sr_tcp_hdr_t*)(packet+sr_get_ip_hdr_len(ip_packet_hdr));

	// Look up the mapping
	struct sr_nat_mapping* mapping;
	pthread_mutex_unlock(&(nat->lock));
	if(is_internal)
		mapping = sr_nat_lookup_internal(nat,ntohl(ip_packet_hdr->ip_src),ntohs(tcp_hdr->tcp_src_port),nat_mapping_tcp);
	else
		mapping = sr_nat_lookup_external(nat,ntohs(tcp_hdr->tcp_dst_port),nat_mapping_tcp);
	pthread_mutex_lock(&(nat->lock));

	struct sr_nat_connection* connection = NULL;

	// Case we found a mapping for this packet, so that's a good start
	if(mapping)
	{
		connection = mapping->conns;
		while(connection)
		{
			// Case the paremeters match for an internal or external lookup of connection
			if((is_internal && connection->ip_ext==ntohl(ip_packet_hdr->ip_dst) && connection->port_ext==ntohs(tcp_hdr->tcp_dst_port)) ||
					(!is_internal && connection->ip_ext==ntohl(ip_packet_hdr->ip_src) && connection->port_ext==ntohs(tcp_hdr->tcp_src_port)))
				break;
			connection = connection->next;
		}
		free(mapping);
	}

	pthread_mutex_unlock(&(nat->lock));
	return connection;
}

// Insert a connection into its correct mapping given an IP packet that has already be checked for correctness.  Will
//     first check to see if the correct connection already exists and so won't create duplicates
void sr_nat_insert_connection_external(struct sr_nat* nat, uint8_t* packet, unsigned int packet_len)
{
	sr_nat_insert_connection(nat,packet,packet_len,0);
}
void sr_nat_insert_connection_internal(struct sr_nat* nat, uint8_t* packet, unsigned int packet_len)
{
	sr_nat_insert_connection(nat,packet,packet_len,1);
}
void sr_nat_insert_connection(struct sr_nat* nat, uint8_t* packet, unsigned int packet_len, uint8_t is_internal)
{
	pthread_mutex_lock(&(nat->lock));

	// Extract the IP and TCP headers
	sr_ip_hdr_t* ip_packet_hdr = (sr_ip_hdr_t*)packet;
	sr_tcp_hdr_t* tcp_hdr = (sr_tcp_hdr_t*)(packet+sr_get_ip_hdr_len(ip_packet_hdr));

	// Look up the mapping in case it already exists
	pthread_mutex_unlock(&(nat->lock));
	struct sr_nat_connection* connection = NULL;
	// Case this is outbound
	if(is_internal)
		connection = sr_nat_lookup_connection_internal(nat,packet,packet_len);
	// Case this is inbound
	else
		connection = sr_nat_lookup_connection_external(nat,packet,packet_len);
	pthread_mutex_lock(&(nat->lock));

	// Case this connection already exists
	if(connection)
	{
		pthread_mutex_unlock(&(nat->lock));
		return;
	}

	// Get the mapping (but not just a copy because we need to change the actual values)
	struct sr_nat_mapping* mapping = NULL;
	if(is_internal)
		mapping = sr_nat_lookup_internal_ptr(nat,ntohl(ip_packet_hdr->ip_src),ntohs(tcp_hdr->tcp_src_port),nat_mapping_tcp);
	else
		mapping = sr_nat_lookup_external_ptr(nat,ntohs(tcp_hdr->tcp_dst_port),nat_mapping_tcp);

	// Case we found a mapping we can add this connection to
	if(mapping)
	{
		// Set the variables defining a connection based on whether this packet is internal or external
		uint32_t ip_ext;
		uint16_t port_ext;
		// Case this is outbound
		if(is_internal)
		{
			ip_ext = ntohl(ip_packet_hdr->ip_dst);
			port_ext = ntohs(tcp_hdr->tcp_dst_port);
		}
		// Case this is inbound
		else
		{
			ip_ext = ntohl(ip_packet_hdr->ip_src);
			port_ext = ntohs(tcp_hdr->tcp_src_port);
		}

		// Create a new connection and set that it's in the beginning transitory phase
		connection = malloc(sizeof(struct sr_nat_connection));
		connection->ip_ext = ip_ext;
		connection->port_ext = port_ext;
		connection->active_seqno = ntohl(tcp_hdr->tcp_seqno);
		connection->passive_seqno = 0;
		connection->tcp_state = WAITING_SYN_ACK;
		connection->prev = NULL;
		connection->last_updated = time(NULL);

		// Set this connection to the head of the list
		connection->next = mapping->conns;
		if(mapping->conns)
			mapping->conns->prev = connection;
		mapping->conns = connection;
	}
	pthread_mutex_unlock(&(nat->lock));
}

// Given an IP packet with a TCP payload, its length, and the interface it arrived on, determine which connection of which mapping to update (if any)
void sr_nat_update_connection_state(struct sr_nat* nat, uint8_t* packet, unsigned int packet_len, uint8_t is_internal)
{
	pthread_mutex_lock(&(nat->lock));

	// Extract the IP and TCP headers
	sr_ip_hdr_t* ip_packet_hdr = (sr_ip_hdr_t*)packet;
	sr_tcp_hdr_t* tcp_hdr = (sr_tcp_hdr_t*)(packet+sr_get_ip_hdr_len(ip_packet_hdr));

	struct sr_nat_connection* connection = NULL;

	// Case the SYN bit is set and the ACK bit is not set, so the internal wishes to create a connection
	if(tcp_hdr->tcp_ctrl_syn && !tcp_hdr->tcp_ctrl_ack)
	{
		pthread_mutex_unlock(&(nat->lock));
		if(is_internal)
			sr_nat_insert_connection_internal(nat,packet,packet_len);
		else
			sr_nat_insert_connection_external(nat,packet,packet_len);
		pthread_mutex_lock(&(nat->lock));
	}
	// Case this is anything other than an original SYN
	else
	{
		// Attempt to look up the connection using internal parameters
		pthread_mutex_unlock(&(nat->lock));
		if(is_internal)
			connection = sr_nat_lookup_connection_internal(nat,packet,packet_len);
		else
			connection = sr_nat_lookup_connection_external(nat,packet,packet_len);
		pthread_mutex_lock(&(nat->lock));
		if(connection)
		{
			// SYN ACK in response to SYN
			if(tcp_hdr->tcp_ctrl_syn && tcp_hdr->tcp_ctrl_ack &&
					ntohl(tcp_hdr->tcp_ackno)==connection->active_seqno+1 &&
					connection->tcp_state==WAITING_SYN_ACK)
			{
				connection->passive_seqno = ntohl(tcp_hdr->tcp_seqno);
				connection->tcp_state = WAITING_ACK;
			}
			// ACK in response to SYN ACK
			else if(tcp_hdr->tcp_ctrl_ack && ntohl(tcp_hdr->tcp_ackno)==connection->passive_seqno+1 &&
					connection->tcp_state==WAITING_ACK)
				connection->tcp_state = ESTABLISHED;

			// FIN bit
			if(tcp_hdr->tcp_ctrl_fin && connection->tcp_state!=FIN_RECEIVED)
				connection->tcp_state = FIN_RECEIVED;
		}
	}
	// If we acquired a connection during any of this, set the update time
	if(connection)
		connection->last_updated = time(NULL);

	pthread_mutex_unlock(&(nat->lock));
}

// **** PRINT-OUTS ****

// Prints out all the details of a given connection - indented by the indent_char (*,>,-)
void sr_nat_print_connection(struct sr_nat* nat, struct sr_nat_connection* connection, char indent_char)
{
	pthread_mutex_lock(&(nat->lock));

	// Print the connection's details
	printf("\t%cip_ext=",indent_char);
	unsigned char octet_int[4] = {0,0,0,0};
	int i;
	for(i=0; i<4; i++)
	{
		octet_int[i] = ( connection->ip_ext >> (i*8) ) & 0xFF;
	}
	printf("%d.%d.%d.%d\n",octet_int[3],octet_int[2],octet_int[1],octet_int[0]);
	printf("\t%cport_ext=%i\n",indent_char,connection->port_ext);

	printf("\t%ctcp_state=",indent_char);
	if(connection->tcp_state==WAITING_SYN)
		printf("WAITING_SYN\n");
	else if(connection->tcp_state==WAITING_SYN_ACK)
		printf("WAITING_SYN_ACK\n");
	else if(connection->tcp_state==WAITING_ACK)
		printf("WAITING_ACK\n");
	else if(connection->tcp_state==ESTABLISHED)
		printf("ESTABLISHED\n");
	else if(connection->tcp_state==FIN_RECEIVED)
		printf("FIN_RECEIVED\n");

	printf("\t%cactive_seqno=%lu\n",indent_char,(long unsigned int)connection->active_seqno);
	printf("\t%cpassive_seqno=%lu\n",indent_char,(long unsigned int)connection->passive_seqno);

	printf("\t%clast_updated=%lu\n",indent_char,(long unsigned int)connection->last_updated);
	pthread_mutex_unlock(&(nat->lock));
}

// Print all the connections for the given mapping
void sr_nat_print_connections_for_mapping(struct sr_nat* nat, struct sr_nat_mapping* mapping)
{
	pthread_mutex_lock(&(nat->lock));
	char indent_chars[] = {'*','-','>','o'};
	int i = 0;
	struct sr_nat_connection* connection = mapping->conns;
	while(connection)
	{
		// Print each connection
		pthread_mutex_unlock(&(nat->lock));
		sr_nat_print_connection(nat,connection,indent_chars[i%4]);
		pthread_mutex_lock(&(nat->lock));

		connection = connection->next;
		i++;
	}
	pthread_mutex_unlock(&(nat->lock));
}

// Print all the mappings for the given NAT
void sr_nat_print_mappings(struct sr_nat* nat)
{
	pthread_mutex_lock(&(nat->lock));
	printf("*************\n");
	printf("Mappings at %lu\n", time(NULL));
	printf("------------\n");
	struct sr_nat_mapping* mapping = nat->mappings;
	while(mapping)
	{
		// Internal
		printf("ip_int=");
		unsigned char octet_int[4] = {0,0,0,0};
		int i;
		for(i=0; i<4; i++)
		{
			octet_int[i] = ( mapping->ip_int >> (i*8) ) & 0xFF;
		}
		printf("%d.%d.%d.%d\n",octet_int[3],octet_int[2],octet_int[1],octet_int[0]);
		printf("aux_int=%i\n",mapping->aux_int);

		// External
		printf("ip_ext=");
		unsigned char octet_ext[4] = {0,0,0,0};
		for(i=0; i<4; i++)
		{
			octet_ext[i] = ( mapping->ip_ext >> (i*8) ) & 0xFF;
		}
		printf("%d.%d.%d.%d\n",octet_ext[3],octet_ext[2],octet_ext[1],octet_ext[0]);
		printf("aux_ext=%i\n",mapping->aux_ext);

		// Time
		printf("last_updated=%lu\n",mapping->last_updated);

		// Connections
		sr_nat_print_connections_for_mapping(nat,mapping);
		mapping = mapping->next;
		printf("\n");
	}
	printf("*************\n\n");
	pthread_mutex_unlock(&(nat->lock));
}
