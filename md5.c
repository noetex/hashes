#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>

typedef struct { uint32_t A, B, C, D; } md5_hash;
typedef struct { uint32_t _32[16]; } md5_chunk;

static char HEX_DIGITS[16] =
{
	'0', '1', '2', '3',
	'4', '5', '6', '7',
	'8', '9', 'a', 'b',
	'c', 'd', 'e', 'f',
};

static uint8_t MD5_S[64] =
{
	7, 12, 17, 22,
	7, 12, 17, 22,
	7, 12, 17, 22,
	7, 12, 17, 22,
	5, 9, 14, 20,
	5, 9, 14, 20,
	5, 9, 14, 20,
	5, 9, 14, 20,
	4, 11, 16, 23,
	4, 11, 16, 23,
	4, 11, 16, 23,
	4, 11, 16, 23,
	6, 10, 15, 21,
	6, 10, 15, 21,
	6, 10, 15, 21,
	6, 10, 15, 21,
};

static uint32_t MD5_K[64] =
{
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391,
};

static uint32_t
md5_shuffle_f(uint32_t A, uint32_t B, uint32_t C)
{
	uint32_t Result = (A & B) | (~A & C);
	return Result;
}

static uint32_t
md5_shuffle_g(uint32_t A, uint32_t B, uint32_t C)
{
	uint32_t Result = (A & C) | (B & ~C);
	return Result;
}

static uint32_t
md5_shuffle_h(uint32_t A, uint32_t B, uint32_t C)
{
	uint32_t Result = A ^ B ^ C;
	return Result;
}

static uint32_t
md5_shuffle_i(uint32_t A, uint32_t B, uint32_t C)
{
	uint32_t Result = (A | ~C) ^ B;
	return Result;
}

static uint32_t
rotateleft32(uint32_t Value, uint32_t Amount)
{
	uint32_t Result = (Value << Amount) | (Value >> (32 - Amount));
	return Result;
}

static md5_hash
md5_string(uint8_t* Message, uint64_t Length)
{
	uint64_t OldLength = Length;
	uint8_t* OldMessage = Message;
	Length += (56 - (Length % 56)) + sizeof(uint64_t);
	Message = malloc(Length);
	memcpy(Message, OldMessage, OldLength);
	memset(&Message[OldLength], 0, Length - OldLength);
	Message[OldLength] = 0x80;
	uint64_t* MessageEnd = (uint64_t*)&Message[Length];
	MessageEnd[-1] = (OldLength * 8);
	md5_hash Result = { 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476 };
	md5_chunk* Chunk = (md5_chunk*)Message;
	while((uint64_t*)Chunk < MessageEnd)
	{
		md5_hash Digest = Result;
		for(int Index = 0; Index < 64; Index += 1)
		{
			uint32_t F;
			uint32_t G;
			if(Index < 16)
			{
				F = md5_shuffle_f(Digest.B, Digest.C, Digest.D);
				G = Index;
			}
			else if(Index < 32)
			{
				F = md5_shuffle_g(Digest.B, Digest.C, Digest.D);
				G = (5*Index + 1) & 0xf;
			}
			else if(Index < 48)
			{
				F = md5_shuffle_h(Digest.B, Digest.C, Digest.D);
				G = (3*Index + 5) & 0xf;
			}
			else
			{
				F = md5_shuffle_i(Digest.B, Digest.C, Digest.D);
				G = (7*Index) & 0xf;
			}
			F += Digest.A + MD5_K[Index] + Chunk->_32[G];
			Digest.A = Digest.D;
			Digest.D = Digest.C;
			Digest.C = Digest.B;
			Digest.B += rotateleft32(F, MD5_S[Index]);
		}
		Result.A += Digest.A;
		Result.B += Digest.B;
		Result.C += Digest.C;
		Result.D += Digest.D;
		Chunk += 1;
	}
	free(Message);
	return Result;
}

static void
print_hash(md5_hash Hash)
{
	int Index = 0;
	while(Index < sizeof(Hash))
	{
		uint8_t Value = ((uint8_t*)&Hash)[Index];
		putchar(HEX_DIGITS[Value >> 4]);
		putchar(HEX_DIGITS[Value & 0xf]);
		Index += 1;
	}
}

int main(void)
{
	char* Test = "The quick brown fox jumps over the lazy dog.";
	md5_hash Hash = md5_string(Test, strlen(Test));
	print_hash(Hash);
	return 0;
}
