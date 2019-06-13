#include "rc4.h"

// from: http://www.cypherspace.org/adam/rsa/rc4.c

#define swap_byte(x,y) t = *(x); *(x) = *(y); *(y) = t

void prepare_key(char *key_data_ptr, rc4_key *key)
{
	unsigned char seed[256];
	unsigned char t;
	unsigned char index1;
	unsigned char index2;
	unsigned char* state;
	short counter;
	char data[512];
	char digit[5];
	int hex, i;
	int key_data_len;

	key_data_len = (int)strlen(key_data_ptr);
	if (key_data_len > sizeof(data)-2) {
		return;
	}
	strcpy_s(data,key_data_ptr);
	if (key_data_len&1)
	{
		strcat_s(data,"0");
		key_data_len++;
	}
	key_data_len/=2;
	strcpy_s(digit,"AA");
	digit[4]='\0';
	for (i=0;i<key_data_len;i++)
	{
		digit[2] = data[i*2];
		digit[3] = data[i*2+1];
		sscanf_s(digit,"%x",&hex);
		seed[i] = hex;
	}

	state = &key->state[0];
	for(counter = 0; counter < 256; counter++)
		state[counter] = (unsigned char)counter;
	key->x = 0;
	key->y = 0;
	index1 = 0;
	index2 = 0;
	for(counter = 0; counter < 256; counter++)
	{
		index2 = (seed[index1] + state[counter] + index2) % 256;
		swap_byte(&state[counter], &state[index2]);
		index1 = (index1 + 1) % key_data_len;
	}
}

void rc4_impl(unsigned char *buffer_ptr, int buffer_len, rc4_key *key)
{
	unsigned char t;
	unsigned char x;
	unsigned char y;
	unsigned char* state;
	unsigned char xorIndex;
	int counter;

	x = key->x;
	y = key->y;
	state = &key->state[0];
	for(counter = 0; counter < buffer_len; counter++)
	{
		x = (x + 1) % 256;
		y = (state[x] + y) % 256;
		swap_byte(&state[x], &state[y]);
		xorIndex = (state[x] + state[y]) % 256;
		buffer_ptr[counter] ^= state[xorIndex];
	}
	key->x = x;
	key->y = y;
}
