#include "ip.h"
#include "log.h"
#include "net.h"
#include "utils.h"

/**
 * receive process for IP packet
 * @param input_dev
 * @param buffer
 * @param len
 */
void ip_input(net_device *input_dev, uint8_t *buffer, ssize_t len)
{
	// IP Address のついていないインターフェースからの受信は無視
	if (input_dev->ip_dev == nullptr or input_dev->ip_dev->address == 0)
	{
		return;
	}

	// IP ヘッダ長より短かったらドロップ
	if (len < sizeof(ip_header))
	{
		LOG_IP("Received IP Packet too short from %s\n", input_dev->name);
		return;
	}

	// 送られてきたバッファをキャストして扱う
	auto *ip_packet = reinterpret_cast<ip_header *>(buffer);

	LOG_IP("Received IP packet type %d from %s to %s\n", ip_packet->protocol, ip_ntoa(ip_packet->src_addr), ip_ntoa(ip_packet->dest_addr));

	if (ip_packet->version != 4)
	{
		LOG_IP("Incorrect IP version\n");
		return;
	}

	// IP ヘッダオプションがついていたらドロップ
	if (ip_packet->header_len != (sizeof(ip_header) >> 2))
	{
		LOG_IP("IP header option is not supported\n");
		return;
	}

	if (ip_packet->dest_addr == IP_ADDRESS_LIMITED_BROADCAST)
	{
		// ブロードキャストの場合も自分宛の通信として処理
		return ip_input_to_ours(input_dev, ip_packet, len);
	}

	// 宛先 IP アドレスをルータが持っているか調べる
	for (net_device *dev = net_dev_list; dev; dev = dev->next)
	{
		if (dev->ip_dev != nullptr and dev->ip_dev->address != IP_ADDRESS(0, 0, 0, 0))
			// 宛先 IP アドレスがルータの持っている IP アドレスか、ディレクティッドブロードキャストか調べる
			if (dev->ip_dev->address == ntohl(ip_packet->dest_addr) or dev->ip_dev->broadcast == ntohl(ip_packet->dest_addr))
			{
				// 自分宛の通信として処理
				return ip_input_to_ours(dev, ip_packet, len);
			}
	}
}

/**
 * 自分宛の IP パケットを処理する
 * @param input_dev
 * @param ip_packet
 * @param len
 */
void ip_input_to_ours(net_device *input_dev, ip_header *ip_packet, size_t len)
{
	// 上位プロトコルの処理に移行
	switch (ip_packet->protocol)
	{
	case IP_PROTOCOL_NUM_ICMP:
		LOG_IP("ICMP received!\n");
		return;
	case IP_PROTOCOL_NUM_UDP:
		return;
	case IP_PROTOCOL_NUM_TCP:
		return;
	default:
		LOG_IP("Unhandled ip protocol %04x", ip_packet->protocol);
		return;
	}
}
