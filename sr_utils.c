#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "sr_protocol.h"
#include "sr_utils.h"


uint16_t cksum (const void *_data, int len) {
	const uint8_t *data = _data;
	uint32_t sum;

	for (sum = 0;len >= 2; data += 2, len -= 2)
		sum += data[0] << 8 | data[1];
	if (len > 0)
		sum += data[0] << 8;
	while (sum > 0xffff)
		sum = (sum >> 16) + (sum & 0xffff);
	sum = htons (~sum);
	return sum ? sum : 0xffff;
}


uint16_t ethertype(uint8_t *buf) {
	sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
	return ntohs(ehdr->ether_type);
}

uint8_t ip_protocol(uint8_t *buf) {
	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
	return iphdr->ip_p;
}


/* Prints out formatted Ethernet address, e.g. 00:11:22:33:44:55 */
void print_addr_eth(uint8_t *addr) {
	int pos = 0;
	uint8_t cur;
	for (; pos < ETHER_ADDR_LEN; pos++) {
		cur = addr[pos];
		if (pos > 0)
			fprintf(stderr, ":");
		fprintf(stderr, "%02X", cur);
	}
	fprintf(stderr, "\n");
}

/* Prints out IP address as a string from in_addr */
void print_addr_ip(struct in_addr address) {
	char buf[INET_ADDRSTRLEN];
	if (inet_ntop(AF_INET, &address, buf, 100) == NULL)
		fprintf(stderr,"inet_ntop error on address conversion\n");
	else
		fprintf(stderr, "%s\n", buf);
}

/* Prints out IP address from integer value */
void print_addr_ip_int(uint32_t ip) {
	uint32_t curOctet = ip >> 24;
	fprintf(stderr, "%d.", curOctet);
	curOctet = (ip << 8) >> 24;
	fprintf(stderr, "%d.", curOctet);
	curOctet = (ip << 16) >> 24;
	fprintf(stderr, "%d.", curOctet);
	curOctet = (ip << 24) >> 24;
	fprintf(stderr, "%d\n", curOctet);
}


/* Prints out fields in Ethernet header. */
void print_hdr_eth(uint8_t *buf) {
	sr_ethernet_hdr_t *ehdr = (sr_ethernet_hdr_t *)buf;
	fprintf(stderr, "ETHERNET header:\n");
	fprintf(stderr, "\tdestination: ");
	print_addr_eth(ehdr->ether_dhost);
	fprintf(stderr, "\tsource: ");
	print_addr_eth(ehdr->ether_shost);
	fprintf(stderr, "\ttype: %d\n", ntohs(ehdr->ether_type));
}

/* Prints out fields in IP header. */
void print_hdr_ip(uint8_t *buf) {
	sr_ip_hdr_t *iphdr = (sr_ip_hdr_t *)(buf);
	fprintf(stderr, "IP header:\n");
	fprintf(stderr, "\tversion: %d\n", iphdr->ip_v);
	fprintf(stderr, "\theader length: %d\n", iphdr->ip_hl);
	fprintf(stderr, "\ttype of service: %d\n", iphdr->ip_tos);
	fprintf(stderr, "\tlength: %d\n", ntohs(iphdr->ip_len));
	fprintf(stderr, "\tid: %d\n", ntohs(iphdr->ip_id));

	if (ntohs(iphdr->ip_off) & IP_DF)
		fprintf(stderr, "\tfragment flag: DF\n");
	else if (ntohs(iphdr->ip_off) & IP_MF)
		fprintf(stderr, "\tfragment flag: MF\n");
	else if (ntohs(iphdr->ip_off) & IP_RF)
		fprintf(stderr, "\tfragment flag: R\n");

	fprintf(stderr, "\tfragment offset: %d\n", ntohs(iphdr->ip_off) & IP_OFFMASK);
	fprintf(stderr, "\tTTL: %d\n", iphdr->ip_ttl);
	fprintf(stderr, "\tprotocol: %d\n", iphdr->ip_p);

	/*Keep checksum in NBO*/
	fprintf(stderr, "\tchecksum: %d\n", iphdr->ip_sum);

	fprintf(stderr, "\tsource: ");
	print_addr_ip_int(ntohl(iphdr->ip_src));

	fprintf(stderr, "\tdestination: ");
	print_addr_ip_int(ntohl(iphdr->ip_dst));
}

/* Prints out ICMP header fields */
void print_hdr_icmp(uint8_t *buf) {
	sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf);
	fprintf(stderr, "ICMP header:\n");
	fprintf(stderr, "\ttype: %d\n", icmp_hdr->icmp_type);
	fprintf(stderr, "\tcode: %d\n", icmp_hdr->icmp_code);
	/* Keep checksum in NBO */
	fprintf(stderr, "\tchecksum: %d\n", icmp_hdr->icmp_sum);
}

/* Prints out TCP header fields */
void print_hdr_tcp(uint8_t *buf) {
	sr_tcp_hdr_t *tcp_hdr = (sr_tcp_hdr_t *)(buf);
	fprintf(stderr, "TCP header:\n");
	fprintf(stderr, "\tsrc_port: %d\n", ntohs(tcp_hdr->tcp_src_port));
	fprintf(stderr, "\tdst_port: %d\n", ntohs(tcp_hdr->tcp_dst_port));
	fprintf(stderr, "\tseqno: %ld\n", (long int)ntohl(tcp_hdr->tcp_seqno));
	fprintf(stderr, "\tackno: %ld\n", (long int)ntohl(tcp_hdr->tcp_ackno));
	fprintf(stderr, "\theader_len: %d\n", tcp_hdr->tcp_data_off*4);
	if(tcp_hdr->tcp_ctrl_urgent)
		fprintf(stderr, "\tURGENT bit\n");
	if(tcp_hdr->tcp_ctrl_ack)
		fprintf(stderr, "\tACK bit\n");
	if(tcp_hdr->tcp_ctrl_push)
		fprintf(stderr, "\tPUSH bit\n");
	if(tcp_hdr->tcp_ctrl_reset)
		fprintf(stderr, "\tRESET bit\n");
	if(tcp_hdr->tcp_ctrl_syn)
		fprintf(stderr, "\tSYN bit\n");
	if(tcp_hdr->tcp_ctrl_fin)
		fprintf(stderr, "\tFIN bit\n");
	fprintf(stderr, "\ttcp_window: %d\n", ntohs(tcp_hdr->tcp_window));
	fprintf(stderr, "\ttcp_cksumo: %d\n", tcp_hdr->tcp_cksum); // Leave in network byte order
}

/* Prints out fields in ARP header */
void print_hdr_arp(uint8_t *buf) {
	sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(buf);
	fprintf(stderr, "ARP header\n");
	fprintf(stderr, "\thardware type: %d\n", ntohs(arp_hdr->ar_hrd));
	fprintf(stderr, "\tprotocol type: %d\n", ntohs(arp_hdr->ar_pro));
	fprintf(stderr, "\thardware address length: %d\n", arp_hdr->ar_hln);
	fprintf(stderr, "\tprotocol address length: %d\n", arp_hdr->ar_pln);
	fprintf(stderr, "\topcode: %d\n", ntohs(arp_hdr->ar_op));

	fprintf(stderr, "\tsender hardware address: ");
	print_addr_eth(arp_hdr->ar_sha);
	fprintf(stderr, "\tsender ip address: ");
	print_addr_ip_int(ntohl(arp_hdr->ar_sip));

	fprintf(stderr, "\ttarget hardware address: ");
	print_addr_eth(arp_hdr->ar_tha);
	fprintf(stderr, "\ttarget ip address: ");
	print_addr_ip_int(ntohl(arp_hdr->ar_tip));
}

/* Prints out all possible headers, starting from Ethernet */
void print_hdrs(uint8_t *buf, uint32_t length) {

	/* Ethernet */
	int minlength = sizeof(sr_ethernet_hdr_t);
	if (length < minlength) {
		fprintf(stderr, "Failed to print ETHERNET header, insufficient length\n");
		return;
	}

	uint16_t ethtype = ethertype(buf);
	print_hdr_eth(buf);

	if (ethtype == ethertype_ip) { /* IP */
		minlength += sizeof(sr_ip_hdr_t);
		if (length < minlength) {
			fprintf(stderr, "Failed to print IP header, insufficient length\n");
			return;
		}

		print_hdr_ip(buf + sizeof(sr_ethernet_hdr_t));
		uint8_t ip_proto = ip_protocol(buf + sizeof(sr_ethernet_hdr_t));

		if (ip_proto == ip_protocol_icmp) { /* ICMP */
			minlength += sizeof(sr_icmp_hdr_t);
			if (length < minlength)
				fprintf(stderr, "Failed to print ICMP header, insufficient length\n");
			else
			{
				print_hdr_icmp(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

				// Print the ICMP data
				printf("Data:\n");
				for(int i = 0; i < length-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t)-sizeof(sr_icmp_hdr_t); i++)
				{
					uint8_t val = *(buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_icmp_hdr_t)+i);
					if(val>0xF)
						printf("0x%X ",val);
					else if(val == 0)
						printf("0x00 ");
					else
						printf("0x0%X ",val);

					if((i+1)%14 == 0)
						printf("\n");
				}
				printf("\n");
			}
		}
		// Case it's TCP
		else if(ip_proto == ip_protocol_tcp)
		{
			print_hdr_tcp(buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t));
			// Print the TCP data
			printf("Data:\n");
			for(int i = 0; i < length-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t)-sizeof(sr_tcp_hdr_t); i++)
			{
				uint8_t val = *(buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+sizeof(sr_tcp_hdr_t)+i);
				if(val>0xF)
					printf("0x%X ",val);
				else if(val == 0)
					printf("0x00 ");
				else
					printf("0x0%X ",val);

				if((i+1)%14 == 0)
					printf("\n");
			}
			printf("\n");
		}
		// Case it's UDP
		else
		{
			// Print the TCP/UDP data
			printf("Data:\n");
			for(int i = 0; i < length-sizeof(sr_ethernet_hdr_t)-sizeof(sr_ip_hdr_t); i++)
			{
				uint8_t val = *(buf+sizeof(sr_ethernet_hdr_t)+sizeof(sr_ip_hdr_t)+i);
				if(val>0xF)
					printf("0x%X ",val);
				else if(val == 0)
					printf("0x00 ");
				else
					printf("0x0%X ",val);

				if((i+1)%14 == 0)
					printf("\n");
			}
			printf("\n");
		}

		// Print all the hex bytes
		printf("\nBytes:\n");
		for(int i = 0; i < length; i++)
		{
			uint8_t val = *(buf+i);
			if(val>0xF)
				printf("0x%X ",val);
			else if(val == 0)
				printf("0x00 ");
			else
				printf("0x0%X ",val);

			if((i+1)%14 == 0)
				printf("\n");
		}
		printf("\n");
	}
	else if (ethtype == ethertype_arp) { /* ARP */
		minlength += sizeof(sr_arp_hdr_t);
		if (length < minlength)
			fprintf(stderr, "Failed to print ARP header, insufficient length\n");
		else
			print_hdr_arp(buf + sizeof(sr_ethernet_hdr_t));
	}
	else {
		fprintf(stderr, "Unrecognized Ethernet Type: %d\n", ethtype);
	}
}

