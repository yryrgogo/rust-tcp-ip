#ifndef CURO_APP_H
#define CURO_ARP_H

#include <iostream>

#define ARP_HTYPE_ETHERNET 0x0001

#define ARP_OPERATION_CODE_REQUEST 0x0001
#define ARP_OPERATION_CODE_REPLY 0x0002

#define ARP_ETHERNET_PACKET_LEN 46

#define ARP_TABLE_SIZE 256

struct arp_ip_to_ethernet
{
	uint16_t htype; // Hardware type
	uint16_t ptype; // Protocol type
	uint8_t hlen;		// Hardware address length
	uint8_t plen;		// Protocol address length
	uint16_t op;		// Operation code
	uint8_t sha[6]; // Sender hardware address
	uint32_t spa;		// Sender protocol address;
	uint8_t tha[6]; // Target hardware address
	uint32_t tpa;		// Target protocol address
} __attribute__((packed));

struct net_device;

struct arp_table_entry
{
	uint8_t mac_addr[6];
	uint32_t ip_addr;
	net_device *dev;
	arp_table_entry *next;
};

#endif // CURO_ARP_H
