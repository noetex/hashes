#include<stdio.h>
#include<stdint.h>
#include<stdlib.h>
#include<string.h>

#define BITS_PER_BYTE 8

#define array_length(Array) (sizeof(Array)/sizeof((Array)[0]))
#define static_assert(Expr) typedef int static_assert_typedef[(!!(Expr)) ? 1 : -1]

typedef struct { uint32_t A, B, C, D, E; } sha1_hash;
typedef struct { uint32_t _32[16]; } sha1_chunk;

static_assert(sizeof(sha1_hash) == 20);
static_assert(sizeof(sha1_chunk) == 64);

static sha1_hash SHA1_INITIAL_HASH =
{
	0x67452301,
	0xEFCDAB89,
	0x98BADCFE,
	0x10325476,
	0xC3D2E1F0,
};

static uint64_t
reverse_endianness64(uint64_t Value)
{
	uint8_t* ByteArray = (uint8_t*)&Value;
	uint64_t Result = (uint64_t)ByteArray[0] << 56;
	Result |= (uint64_t)ByteArray[1] << 48;
	Result |= (uint64_t)ByteArray[2] << 40;
	Result |= (uint64_t)ByteArray[3] << 32;
	Result |= (uint64_t)ByteArray[4] << 24;
	Result |= (uint64_t)ByteArray[5] << 16;
	Result |= (uint64_t)ByteArray[6] << 8;
	Result |= (uint64_t)ByteArray[7];
	return Result;
}

static uint32_t
rotateleft32(uint32_t Value, uint32_t Amount)
{
	uint32_t Result = (Value << Amount) | (Value >> (32 - Amount));
	return Result;
}

static sha1_hash
sha1_process_chunk(sha1_chunk* Chunk, sha1_hash Hash)
{
	uint32_t Extension[80];
	memcpy(Extension, Chunk, sizeof(sha1_chunk));
	sha1_hash Result = Hash;
	for(int Index = 16; Index < array_length(Extension); Index += 1)
	{
		uint32_t A = Extension[Index - 3];
		uint32_t B = Extension[Index - 8];
		uint32_t C = Extension[Index - 14];
		uint32_t D = Extension[Index - 16];
		Extension[Index] = rotateleft32((A ^ B ^ C ^ D), 1);
	}
	for(int Index = 0; Index < array_length(Extension); Index += 1)
	{
		uint32_t Temp;
		if(Index < 20)
		{
			Temp = ((Hash.B & Hash.C) | ((~Hash.B) & Hash.D)) + 0x5A827999;
		}
		else if(Index < 40)
		{
			Temp = (Hash.B ^ Hash.C ^ Hash.D) + 0x6ED9EBA1;
		}
		else if(Index < 60)
		{
			Temp = ((Hash.B & Hash.C) | (Hash.B & Hash.D) | (Hash.C & Hash.D)) + 0x8F1BBCDC;
		}
		else
		{
			Temp = (Hash.B ^ Hash.C ^ Hash.D) + 0xCA62C1D6;
		}
		Temp += rotateleft32(Hash.A, 5) + Hash.E + Extension[Index];
		Hash.E = Hash.D;
		Hash.D = Hash.C;
		Hash.C = rotateleft32(Hash.B, 30);
		Hash.B = Hash.A;
		Hash.A = Temp;
	}
	Result.A += Hash.A;
	Result.B += Hash.B;
	Result.C += Hash.C;
	Result.D += Hash.D;
	Result.E += Hash.E;
	return Result;
}

static sha1_hash
sha1_final_append(sha1_chunk* LastChunk, uint64_t MessageLength, sha1_hash Hash)
{
	sha1_chunk Chunk = {0};
	uint64_t BytesLeft = MessageLength % sizeof(sha1_chunk);
	memcpy(&Chunk, LastChunk, BytesLeft);
	((uint8_t*)&Chunk)[BytesLeft] = 0x80;
	uint64_t* ChunkEnd = (uint64_t*)(&Chunk + 1);
	uint64_t BitsLength = MessageLength * BITS_PER_BYTE;
	if(BytesLeft > sizeof(uint64_t))
	{
		ChunkEnd[-1] = BitsLength;
		Hash = sha1_process_chunk(&Chunk, Hash);
	}
	else
	{
		Hash = sha1_process_chunk(&Chunk, Hash);
		memset(&Chunk, 0, sizeof(Chunk) - sizeof(uint64_t));
		ChunkEnd[-1] = BitsLength;
		Hash = sha1_process_chunk(&Chunk, Hash);
	}
	sha1_hash Result = Hash;
	return Result;
}

static sha1_hash
sha1_hash_part(uint8_t* Data, uint64_t Length, sha1_hash Hash)
{
	uint8_t* DataEnd = Data + Length;
	sha1_chunk* Chunk = (sha1_chunk*)Data;
	while((uint8_t*)Chunk < DataEnd)
	{
		Hash = sha1_process_chunk(Chunk, Hash);
		Chunk += 1;
	}
	sha1_hash Result = Hash;
	return Result;
}

static sha1_hash
sha1_hash_data(uint8_t* Message, uint64_t Length)
{
	sha1_hash Hash = SHA1_INITIAL_HASH;
	Hash = sha1_hash_part(Message, Length, Hash);
	uint64_t LastChunkIndex = Length/sizeof(sha1_chunk);
	sha1_chunk* LastChunk = (sha1_chunk*)Message + LastChunkIndex;
	sha1_hash Result = sha1_final_append(LastChunk, Length, Hash);
	return Result;
}

static sha1_hash
sha1_hash_file(FILE* File)
{
	uint8_t Buffer[65536];
	fseek(File, 0, SEEK_SET);
	size_t FileSize = 0;
	sha1_hash Hash = SHA1_INITIAL_HASH;
	for(;;)
	{
		size_t BytesRead = fread(Buffer, 1, sizeof(Buffer), File);
		if(BytesRead == 0)
		{
			break;
		}
		Hash = sha1_hash_part(Buffer, BytesRead, Hash);
		FileSize += BytesRead;
	}
	sha1_chunk* Chunk = (sha1_chunk*)Buffer;
	sha1_hash Result = sha1_final_append(Chunk, FileSize, Hash);
	return Result;
}

static void
print_hash(sha1_hash Hash)
{
	static char HEX_DIGITS[16] = "0123456789abcdef";
	for(int Index = 0; Index < sizeof(Hash); Index += 1)
	{
		uint8_t Value = ((uint8_t*)&Hash)[Index];
		putchar(HEX_DIGITS[Value >> 4]);
		putchar(HEX_DIGITS[Value & 0xf]);
	}
}

int main(void)
{
	char* Test = "The quick brown fox jumps over the lazy dog";
	size_t Length = strlen(Test);
	sha1_hash Hash = sha1_hash_data(Test, Length);
	print_hash(Hash);
	//Assert(memcmp(FileHash, DataHash, sizeof(sha1_hash)) == 0);
	return 0;
}
