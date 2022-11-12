#include "arp.h"
#include "ethernet.h"
#include "ip.h"
#include "log.h"
#include "my_buf.h"
#include "utils.h"
#include <cstring>

/**
 * ARP Table
 * グローバル変数にテーブルを保持
 */
arp_table_entry arp_table[ARP_TABLE_SIZE];

/**
 * ARP テーブルにエントリの追加と更新
 * @param dev
 * @param mac_addr
 * @param ip_addr
 */
void add_arp_table_entry(net_device *dev, uint8_t *mac_addr, uint32_t ip_addr)
{
	// 候補となるインデックスは、Hash テーブルの IP アドレスのハッシュ
	const uint32_t index = ip_addr % ARP_TABLE_SIZE;
	arp_table_entry *candidate = &arp_table[index];

	if (candidate->ip_addr == 0 or candidate->ip_addr == ip_addr)
	{
		memcpy(candidate->mac_addr, mac_addr, 6);
		candidate->ip_addr = ip_addr;
		candidate->dev = dev;
		return;
	}

	while (candidate->next != nullptr)
	{
		candidate = candidate->next;

		if (candidate->ip_addr == ip_addr)
		{
			memcpy(candidate->mac_addr, mac_addr, 6);
			candidate->ip_addr = ip_addr;
			candidate->dev = dev;
			return;
		}
	}

	// 連結リストの末尾に新しくエントリを作成
	candidate->next = (arp_table_entry *)calloc(1, sizeof(arp_table_entry));
	memcpy(candidate->next->mac_addr, mac_addr, 6);
	candidate->next->ip_addr = ip_addr;
	candidate->next->dev = dev;
}

/**
 * ARP Request の送信
 * @param dev
 * @param search_ip
 */
void send_arp_request(net_device *dev, uint32_t ip_addr)
{
	LOG_ARP("Sending arp request via %s for %s\n", dev->name, ip_htoa(ip_addr));

	auto *arp_mybuf = my_buf::create(ARP_ETHERNET_PACKET_LEN);
	auto *arp_msg = reinterpret_cast<arp_ip_to_ethernet *>(arp_mybuf->buffer);
	arp_msg->htype = htons(ARP_HTYPE_ETHERNET);
	arp_msg->ptype = htons(ETHER_TYPE_IP);
	arp_msg->hlen = ETHERNET_ADDRESS_LEN;
	arp_msg->plen = IP_ADDRESS_LEN;
	arp_msg->op = htons(ARP_OPERATION_CODE_REQUEST);
	memcpy(arp_msg->sha, dev->mac_addr, 6);
	arp_msg->spa = htonl(dev->ip_dev->address);
	arp_msg->tpa = htonl(ip_addr);

	// イーサネットで送信
	ethernet_encapsulate_output(dev, ETHERNET_ADDRESS_BROADCAST, arp_mybuf, ETHER_TYPE_ARP);
}

void arp_request_arrives(net_device *dev, arp_ip_to_ethernet *request);
void arp_reply_arrives(net_device *dev, arp_ip_to_ethernet *reply);

/**
 * ARP パケットの受信処理
 * @param input_dev
 * @param buffer
 * @param len
 */
void arp_input(net_device *input_dev, uint8_t *buffer, ssize_t len)
{
	// ARP パケットの想定より短かったら
	if (len < sizeof(arp_ip_to_ethernet))
	{
		LOG_ARP("Too short arp packet\n");
		return;
	}

	auto *arp_msg = reinterpret_cast<arp_ip_to_ethernet *>(buffer);

	uint16_t op = ntohs(arp_msg->op);

	switch (ntohs(arp_msg->ptype))
	{
	case ETHER_TYPE_IP:
		if (arp_msg->hlen != ETHERNET_ADDRESS_LEN)
		{
			LOG_ARP("Illegal hardware address length\n");
			return;
		}

		if (arp_msg->plen != IP_ADDRESS_LEN)
		{
			LOG_ARP("Illegal protocol address length\n");
			return;
		}

		// Operation Code によって分岐
		if (op == ARP_OPERATION_CODE_REQUEST)
		{
			// ARP Request の受信
			arp_request_arrives(input_dev, arp_msg);
			return;
		}
		else if (op == ARP_OPERATION_CODE_REPLY)
		{
			// ARP Reply の受信
			arp_reply_arrives(input_dev, arp_msg);
			return;
		}
		break;
	}
}

/**
 * ARP Request Packet の受信処理
 * @param dev
 * @param request
 */
void arp_request_arrives(net_device *dev, arp_ip_to_ethernet *request)
{
	// IP Address が設定されているデバイスからの受信だったら
	if (dev->ip_dev != nullptr and dev->ip_dev->address != IP_ADDRESS(0, 0, 0, 0))
	{
		// 要求されているアドレスが自分のものだったら
		if (dev->ip_dev->address == ntohl(request->tpa))
		{
			LOG_ARP("Sending arp reply via %s\n", ip_ntoa(request->tpa));

			auto *reply_mybuf = my_buf::create(ARP_ETHERNET_PACKET_LEN);

			auto reply_msg = reinterpret_cast<arp_ip_to_ethernet *>(reply_mybuf->buffer);
			reply_msg->htype = htons(ARP_HTYPE_ETHERNET);
			reply_msg->ptype = htons(ETHER_TYPE_IP);
			reply_msg->hlen = ETHERNET_ADDRESS_LEN; // MAC アドレスの長さ
			reply_msg->plen = IP_ADDRESS_LEN;				// IP Address の長さ
			reply_msg->op = htons(ARP_OPERATION_CODE_REPLY);

			// 返答の情報を書き込む
			memcpy(reply_msg->sha, dev->mac_addr, ETHERNET_ADDRESS_LEN);
			reply_msg->spa = htonl(dev->ip_dev->address);
			memcpy(reply_msg->tha, request->sha, ETHERNET_ADDRESS_LEN);
			reply_msg->tpa = request->spa;

			// イーサネットで送信
			ethernet_encapsulate_output(dev, request->sha, reply_mybuf, ETHER_TYPE_ARP);
			// ARP Request からもエントリを生成
			add_arp_table_entry(dev, request->sha, ntohl(request->spa));
			return;
		}
	}
}

/**
 * Arp Reply Packet の受信処理
 * @param dev
 * @param reply
 */
void arp_reply_arrives(net_device *dev, arp_ip_to_ethernet *reply)
{
	// IP Address が設定されているデバイスからの受信だったら
	if (dev->ip_dev != nullptr and dev->ip_dev->address != IP_ADDRESS(0, 0, 0, 0))
	{
		LOG_ARP("Adred arp table entry by arp reply (%s => %s)\n", ip_ntoa(reply->spa), mac_addr_toa(reply->sha));
	}
	// ARP Table エントリの追加
	add_arp_table_entry(dev, reply->sha, ntohl(reply->spa));
}
