#include "ethernet.h"
#include "log.h"
#include "net.h"
#include "utils.h"
#include <arpa/inet.h>
#include <cstddef>
#include <malloc.h>
#include <string.h>
#include <unistd.h>

/**
 * receive process for ethernet
 * @param dev device that received
 * @param buffer byte sequence of the data received
 * @param len length of the data received
 */
void ethernet_input(net_device *dev, uint8_t *buffer, ssize_t len)
{
	// 送られてきた通信をイーサネットのフレームとして解釈する
	auto *header = reinterpret_cast<ethernet_header *>(buffer);
	// イーサタイプを抜き出し、ホストバイトオーダーに変換
	uint16_t ether_type = ntohs(header->type);

	// 自分の MAC アドレス宛か、ブロードキャストの通信かを確認する
	if (memcmp(header->dest_addr, dev->mac_addr, 6) != 0 and memcmp(header->dest_addr, ETHERNET_ADDRESS_BROADCAST, 6) != 0)
	{
		return;
	}

	LOG_ETHERNET("Received ethernet frame type %04x from %s to %s\n", ether_type, mac_addr_toa(header->src_addr), mac_addr_toa(header->dest_addr));

	// イーサタイプの値から上位プロトコルを特定する
	switch (ether_type)
	{
	case ETHER_TYPE_ARP:
		// Ethernet ヘッダを外して ARP 処理へ
		return arp_input(
				dev,
				buffer + ETHERNET_HEADER_SIZE,
				len - ETHERNET_HEADER_SIZE);
	case ETHER_TYPE_IP:
		// Ethernet ヘッダを外して IP 処理へ
		return ip_input(
				dev,
				buffer + ETHERNET_HEADER_SIZE,
				len - ETHERNET_HEADER_SIZE);
	default:
		LOG_ETHERNET("Received unhandled ether type %04x\n", ether_type);
		return;
	}
}

/**
 * イーサネットにカプセル化して送信
 * @param dev device to send
 * @param dest_addr destination Mac Address
 * @param payload_mybuf beginning of data to be encapsulated
 * @param ether_type ether type
 */
void ethernet_encapsulate_output(
		net_device *dev, const uint8_t *dest_addr, my_buf *payload_mybuf, uint16_t ether_type)
{
	LOG_ETHERNET("Sending ethernet frame type %04x from %s to %s\n", ether_type, mac_addr_toa(dev->mac_addr), mac_addr_toa(dest_addr));

	// Ethernet ヘッダ長分のバッファを確保
	my_buf *header_mybuf = my_buf::create(ETHERNET_HEADER_SIZE);
	auto *header = reinterpret_cast<ethernet_header *>(header_mybuf->buffer);

	// イーサネット・ヘッダの設定
	// 送信元アドレスには、デバイスの MAC アドレスを設定する
	memcpy(header->src_addr, dev->mac_addr, 6);
	memcpy(header->dest_addr, dest_addr, 6);
	header->type = htons(ether_type);
	// 上位プロトコルから受け取ったバッファにヘッダをつける
	payload_mybuf->add_header(header_mybuf);

	uint8_t send_buffer[1550];
	// 全長を計算しながらメモリにバッファを展開する
	size_t total_len = 0;
	my_buf *current = header_mybuf;
	while (current != nullptr)
	{
		if (total_len + current->len > sizeof(send_buffer))
		{
			// オーバーフローする場合
			LOG_ETHERNET("Frame is too long!\n");
			return;
		}

		memcpy(&send_buffer[total_len], current->buffer, current->len);

		total_len += current->len;
		current = current->next;
	}

	// ネットワーク・デバイスに送信する
	dev->ops.transmit(dev, send_buffer, total_len);

	// メモリ解放
	my_buf::my_buf_free(header_mybuf, true);
}

struct my_buf
{
	// 前の my_buf
	my_buf *previous = nullptr;
	// 後ろの my_buf
	my_buf *next = nullptr;
	// my_buf に含む buffer の長さ
	uint32_t len = 0;
	uint8_t buffer[];

	/**
	 * my_buf のメモリ確保
	 * @param len 確保するバッファ長
	 */
	static my_buf *create(uint32_t len)
	{
		auto *buf = (my_buf *)calloc(
				1, sizeof(my_buf) + len);
		buf->len = len;
		return buf;
	}

	/**
	 * my_buf のメモリ解放
	 * @param buf
	 * @param is_recursive
	 */
	static void my_buf_free(my_buf *buf, bool is_recursive = false)
	{
		if (!is_recursive)
		{
			free(buf);
			return;
		}

		my_buf *tail = buf->get_tail(), *tmp;
		while (tail != nullptr)
		{
			tmp = tail;
			tail = tmp->previous;
			free(tmp);
		}
	}

	/**
	 * 連結リストの最後を返す
	 */
	my_buf *get_tail()
	{
		my_buf *current = this;
		while (current->next != nullptr)
		{
			current = current->next;
		}
		return current;
	}

	void add_header(my_buf *buf)
	{
		this->previous = buf;
		buf->next = this;
	}
};
