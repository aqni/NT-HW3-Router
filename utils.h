#pragma once
#include <stdint.h>

#define PANIC(...)                     \
	do                                 \
	{                                  \
		fputs("\npanic:\n\t", stderr); \
		fprintf(stderr, __VA_ARGS__);  \
		fputc('\n', stderr);           \
		exit(EXIT_FAILURE);            \
	} while (0)

inline uint16_t swapByteOrder(uint16_t i)
{
	return ((i & 0xff00) >> 8) | ((i & 0x00ff) << 8);
}
