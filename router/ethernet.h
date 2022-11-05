#include <cstdio>
#include "net.h"

/**
 * 無視するネットワークインターフェースたち
 * 中には、MAC アドレスを持たないものなど、
 * このプログラムで使うとエラーを引き起こすものもある
 */
#define IGNORE_INTERFACES                    \
	{                                          \
		"lo", "bond0", "dummy0", "tunl0", "sit0" \
	}

#define ETHER_TYPE_IP 0x0800
#define ETHER_TYPE_ARP 0x0806
#define ETHER_TYPE_IPV6 0x86dd

#define ETHERNET_HEADER_SIZE 14
#define ETHERNET_ADDRESS_LEN 6
#define MAC_ADDRESS_SIZE 6

const uint8_t ETHERNET_ADDRESS_BROADCAST[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

struct ethernet_header
{
	uint8_t dest_addr[MAC_ADDRESS_SIZE];
	uint8_t src_addr[MAC_ADDRESS_SIZE];
	uint16_t type;
} __attribute__((packed));

void ethernet_input(net_device *dev, uint8_t *buffer, ssize_t len);
