#pragma once
#include <string>

typedef struct rc4_key
{
	unsigned char state[256];
	unsigned char x;
	unsigned char y;
} rc4_key;

void prepare_key(char *key_data_ptr, rc4_key *key);
void rc4_impl(unsigned char *buffer_ptr, int buffer_len, rc4_key *key);