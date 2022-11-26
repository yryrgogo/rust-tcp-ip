#include "config.h"

#include "binary_trie.h"
#include "log.h"
#include "ip.h"
#include "napt.h"
#include "net.h"
#include "utils.h"
#include <cstdlib>
#include <cstdint>
#include <malloc.h>

/**
 * set Ip address for net device
 */
void configure_ip_address(net_device *dev, uint32_t address, uint32_t netmask)
{
	if (dev == nullptr)
	{
		LOG_ERROR("Configure net dev not found\n");
		exit(EXIT_FAILURE);
	}

	dev->ip_dev = (ip_device *)calloc(1, sizeof(ip_device));
	dev->ip_dev->address = address;
	dev->ip_dev->netmask = netmask;
	dev->ip_dev->broadcast = (address & netmask) | (~netmask);

	printf("Set ip address to %s\n", dev->name);

	// IP Address を設定すると同時に直接接続ルートを設定する
	ip_route_entry *entry;
	entry = (ip_route_entry *)calloc(1, sizeof(ip_route_entry));
	entry->type = connected;
	entry->dev = dev;

	int len = 0; // サブネット・マスクとプレフィックス長の変換
	for (; len < 32; ++len)
	{
		// 1 が途切れたら break
		if (!(netmask >> (31 - len) & 0b01))
		{
			break;
		}
	}

	// 直接接続ネットワークの経路を設定
	// address & netmask のネットワークには、entry にセットされた net_device が接続されている、という内容
	binary_trie_add(ip_fib, address & netmask, len, entry);

	printf("Set directly connected route %s/%d via %s\n", ip_htoa(address & netmask), len, dev->name);
}

/**
 * デバイスに経路を設定
 * @param prefix
 * @param prefix_len
 * @param next_hop
 */
void configure_ip_net_route(uint32_t prefix, uint32_t prefix_len, uint32_t next_hop)
{
	// プレフィックス長とネット・マスクの変換
	uint32_t mask = 0xffffffff;
	mask <<= (32 - prefix_len);

	// 経路エントリの生成
	ip_route_entry *entry;
	entry = (ip_route_entry *)(calloc(1, sizeof(ip_route_entry)));
	entry->type = network;
	entry->next_hop = next_hop;

	// 経路の登録
	binary_trie_add(ip_fib, prefix & mask, prefix_len, entry);
}

/**
 * デバイスに NAPT を設定
 * @param inside NAPT の内側のデバイス
 * @param outside NAPT の外側のデバイス
 */
void configure_ip_napt(net_device *inside, net_device *outside)
{
	if (inside == nullptr or outside == nullptr or inside->ip_dev == nullptr or outside->ip_dev == nullptr)
	{
		LOG_ERROR("Failed to configure NAT %s => %s\n", inside->name, outside->name);
		exit(EXIT_FAILURE);
	}

	inside->ip_dev->nat_dev = (nat_device *)calloc(1, sizeof(nat_device));
	inside->ip_dev->nat_dev->entries = (nat_entries *)calloc(1, sizeof(nat_entries));
	inside->ip_dev->nat_dev->outside_addr = outside->ip_dev->address;
}
