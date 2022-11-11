#ifndef CURO_MY_BUF_H
#define CURO_MY_BUF_H

#include <cstdint>
#include <cstring>
#include <cstdio>
#include <string>

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

#endif // CURO_MY_BUF_H
