#include <cstdint>
#include <fcntl.h>
#include <ifaddrs.h>
#include <iostream>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netpacket/packet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <termios.h>
#include <unistd.h>
#include "config.h"
#include "ethernet.h"
#include "ip.h"
#include "log.h"
#include "napt.h"
#include "net.h"
#include "utils.h"

bool is_ignore_interface(const char *ifname)
{
	char ignore_interfaces[][IF_NAMESIZE] = IGNORE_INTERFACES;
	for (int i = 0; i < sizeof(ignore_interfaces) / IF_NAMESIZE; i++)
	{
		if (strcmp(ignore_interfaces[i], ifname) == 0)
		{
			return true;
		}
	}
	return false;
}

/**
 * find net_device by name
 * @param name name of net_device
 * @return net_device
 */
net_device *get_net_device_by_name(const char *name)
{
	net_device *dev;
	for (dev = net_dev_list; dev; dev = dev->next)
	{
		if (strcmp(dev->name, name) == 0)
		{
			return dev;
		}
	}
	return nullptr;
}

/**
 * set ip config to net device
 */
void configure_ip()
{

	configure_ip_address(
			get_net_device_by_name("router1-br0"),
			IP_ADDRESS(192, 168, 1, 1),
			IP_ADDRESS(255, 255, 255, 0));

	configure_ip_address(
			get_net_device_by_name("router1-router2"),
			IP_ADDRESS(192, 168, 0, 1),
			IP_ADDRESS(255, 255, 255, 0));

	configure_ip_net_route(
			IP_ADDRESS(192, 168, 2, 0), 24, IP_ADDRESS(192, 168, 0, 2));

	configure_ip_napt(
			get_net_device_by_name("router1-br0"), get_net_device_by_name("router1-router2"));
}

int net_device_transmit(struct net_device *dev, uint8_t *buffer, size_t len);
int net_device_poll(net_device *dev);

struct net_device_data
{
	int fd;
};

int main()
{
	struct ifreq ifr
	{
	};
	struct ifaddrs *addrs;

	// get Network Interface info
	getifaddrs(&addrs);
	for (ifaddrs *tmp = addrs; tmp; tmp = tmp->ifa_next)
	{
		if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET)
		{
			// ioctl でコントロールするインターフェースを設定
			memset(&ifr, 0, sizeof(ifr));
			strcpy(ifr.ifr_name, tmp->ifa_name);
			// 無視するインターフェースか確認
			if (is_ignore_interface(tmp->ifa_name))
			{
				printf("Skipped to enable interface %s\n", tmp->ifa_name);
				continue;
			}

			// open socket
			int sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
			if (sock == -1)
			{
				LOG_ERROR("socket open failed: %s\n", strerror(errno));
				exit(EXIT_FAILURE);
			}
			// get interface index
			if (ioctl(sock, SIOCGIFINDEX, &ifr) == -1)
			{
				LOG_ERROR("ioctl SIOCGIFINDEX failed: %s\n", strerror(errno));
				close(sock);
				exit(EXIT_FAILURE);
			}

			// bind interface to socket
			sockaddr_ll addr{};
			memset(&addr, 0x00, sizeof(addr));
			addr.sll_family = AF_PACKET;
			addr.sll_protocol = htons(ETH_P_ALL);
			addr.sll_ifindex = ifr.ifr_ifindex;
			if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) == -1)
			{
				LOG_ERROR("bind failed: %s\n", strerror(errno));
				close(sock);
				exit(EXIT_FAILURE);
			}

			// get interface MAC address
			if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0)
			{
				LOG_ERROR("ioctl SIOCGIFHWADDR failed: %s\n", strerror(errno));
				close(sock);
				continue;
			}

			// create net_device struct
			// allocate memory for net_device & net_device_data
			net_device *dev;
			dev = (net_device *)calloc(1, sizeof(net_device) + sizeof(net_device_data));

			// set transmit function
			dev->ops.transmit = net_device_transmit;
			// set poll function
			dev->ops.poll = net_device_poll;

			// set interface name to net_device
			strcpy(dev->name, tmp->ifa_name);
			// set MAC address to net_device
			memcpy(dev->mac_addr, &ifr.ifr_hwaddr.sa_data[0], 6);
			((net_device_data *)dev->data)->fd = sock;

			printf("Created device %s socket %d\n", dev->name, sock);

			// add net_device to net_dev_list
			dev->next = net_dev_list;
			net_dev_list = dev;

			// set non blocking
			// get File descriptor flag
			int val = fcntl(sock, F_GETFL, 0);
			// set non blocking bit
			fcntl(sock, F_SETFL, val | O_NONBLOCK);
		}
	}

	freeifaddrs(addrs);
	if (net_dev_list == nullptr)
	{
		LOG_ERROR("No interface is enabled\n");
		exit(EXIT_FAILURE);
	}

	ip_fib = (binary_trie_node<ip_route_entry> *)calloc(1, sizeof(binary_trie_node<ip_route_entry>));

	configure_ip();

	// 入力時にバッファリングせず、すぐに入力を受け取るための設定
	termios attr{};
	tcgetattr(0, &attr);
	attr.c_lflag &= ~ICANON;
	attr.c_cc[VTIME] = 0;
	attr.c_cc[VMIN] = 1;
	tcsetattr(0, TCSANOW, &attr);
	fcntl(0, F_SETFL, O_NONBLOCK); // 標準入力にノンブロッキングの設定

	while (true)
	{
		int input = getchar(); // 入力を受け取る
		if (input != -1)
		{
			// 入力があったら
			printf("\n");
			if (input == 'a')
			{
				// dump_arp_table_entry();
			}
			else if (input == 'n')
			{
				// dump_nat_tables();
			}
			else if (input == 'q')
			{
				break;
			}
		}

		// poll communication from device
		for (net_device *dev = net_dev_list; dev; dev = dev->next)
		{
			dev->ops.poll(dev);
		}
	}

	printf("Goodbye!\n");
	return 0;
}

/**
 * Transmission process for net devices
 * @param dev device used for transmission
 * @param buffer buffer to be transmitted
 * @param len length of buffer
 */
int net_device_transmit(struct net_device *dev, uint8_t *buffer, size_t len)
{
	// transmit data via socket
	send(((net_device_data *)dev->data)->fd, buffer, len, 0);
	return 0;
}

/**
 * Receiving process for net devices
 * @param dev device attempting to receive
 */
int net_device_poll(net_device *dev)
{
	uint8_t recv_buffer[1550];
	// receive from socket
	ssize_t n = recv(
			((net_device_data *)
					 dev->data)
					->fd,
			recv_buffer, sizeof(recv_buffer), 0);

	if (n == -1)
	{
		if (errno == EAGAIN)
		{
			// no data
			return 0;
		}
		else
		{
			return -1;
		}
	}

	printf("Received %lu bytes from %s: ", n, dev->name);
	for (int i = 0; i < n; ++i)
	{
		printf("%02x", recv_buffer[i]);
	}
	printf("\n");

	// send received data to ethernet layer
	ethernet_input(dev, recv_buffer, n);

	return 0;
}
