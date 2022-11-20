#ifndef CURO_BINARY_TRIE_H
#define CURO_BINARY_TRIE_H

#include <iostream>

#define IP_BIT_LEN 32

template <typename DATA_TYPE>
struct binary_trie_node
{
	DATA_TYPE *data;
	uint32_t depth;
	binary_trie_node *parent;
	binary_trie_node *node_0;
	binary_trie_node *node_1;
};

/**
 * 木構造にノードを作成
 * @tparam DATA_TYPE
 * @param root
 * @param prefix
 * @param prefix_len
 * @param data
 */
template <typename DATA_TYPE>
void binary_trie_add(binary_trie_node<DATA_TYPE> *root, uint32_t prefix, uint32_t prefix_len, DATA_TYPE *data)
{
	binary_trie_node<DATA_TYPE> *current = root; // root node から辿る

	// 枝を辿る
	for (int i = 1; i <= prefix_len; ++i)
	{
		if ((prefix >> (IP_BIT_LEN - i)) & 0x01) // 上から i bit 目が1だったら
		{
			if (current->node_1 == nullptr) // 辿る先の枝がなかったら作る
			{
				current->node_1 = (binary_trie_node<DATA_TYPE> *)calloc(1, sizeof(binary_trie_node<DATA_TYPE>));
				current->node_1->data = 0;
				current->node_1->depth = i;
				current->node_1->parent = current;
			}
			current = current->node_1;
		}
		else // 上から 1 bit 目が0だったら
		{
			if (current->node_0 == nullptr) // 辿る先の枝がなかったら作る
			{
				current->node_0 = (binary_trie_node<DATA_TYPE> *)calloc(1, sizeof(binary_trie_node<DATA_TYPE>));
				current->node_0->data = 0;
				current->node_0->depth = i;
				current->node_0->parent = current;
			}
			current = current->node_0;
		}
	}
	current->data = data;
}

/**
 * prefix からトライ木を検索
 * @tparam DATA_TYPE
 * @param root
 * @param prefix
 * @return
 */
template <typename DATA_TYPE>
DATA_TYPE *binary_trie_search(binary_trie_node<DATA_TYPE> *root, uint32_t prefix)
{
	binary_trie_node<DATA_TYPE> *current = root;

	DATA_TYPE *result = nullptr;

	// 検索する IP アドレスと比較して 1bit ずつ辿っていく
	for (int i = 1; i <= IP_BIT_LEN; ++i)
	{
		if (current->data != nullptr)
		{
			result = current->data;
		}
		if ((prefix >> (IP_BIT_LEN - i)) & 0x01) // 上から i bit 目が1だったら
		{
			if (current->node_1 == nullptr)
			{
				return result;
			}
			current = current->node_1;
		}
		else
		{
			if (current->node_0 == nullptr)
			{
				return result;
			}
			current = current->node_0;
		}
	}

	return result;
}

#endif
