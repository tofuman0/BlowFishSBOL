#include "BlowFishSBOL.h"
#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <exception>
#include <chrono>

namespace SBOL {
	BlowFish::BlowFish(char* _SDATKey, char* _PDATKey)
	{
		try
		{
			if (_SDATKey != nullptr)
			{
				memcpy(&SDATkey[0], _SDATKey, 64);
			}
			if (_PDATKey != nullptr)
			{
				memcpy(&PDATkey[0], _PDATKey, 64);
			}
		}
		catch (std::exception ex)
		{
			delete this;
		}
	}
	BlowFish::~BlowFish(){}
	void BlowFish::prepareSP(BLOWFISH_CTX* ctx)
	{
		char* P = (char*)&ctx->P[0];
		char* S = (char*)&ctx->S[0];
		for (int i = 0; i < sizeof(ctx->P); i++)
		{
			P[i] ^= 0x91;
		}
		for (int i = 0; i < sizeof(ctx->S); i++)
		{
			S[i] ^= 0x91;
		}
	}
	unsigned long BlowFish::F(BLOWFISH_CTX *ctx, unsigned long x) {
		unsigned short a, b, c, d;
		unsigned long  y;

		d = (unsigned short)(x & 0xFF);
		x >>= 8;
		c = (unsigned short)(x & 0xFF);
		x >>= 8;
		b = (unsigned short)(x & 0xFF);
		x >>= 8;
		a = (unsigned short)(x & 0xFF);
		y = ctx->S[0][a] + ctx->S[1][b];
		y = y ^ ctx->S[2][c];
		y = y + ctx->S[3][d];

		return y;
	}
	void BlowFish::Blowfish_Encrypt(BLOWFISH_CTX *ctx, unsigned long *xl, unsigned long *xr) {
		unsigned long  Xl;
		unsigned long  Xr;
		unsigned long  temp;
		short       i;

		Xl = *xl;
		Xr = *xr;

		for (i = 0; i < BF_N; ++i) {
			Xl = Xl ^ ctx->P[i];
			Xr = F(ctx, Xl) ^ Xr;

			temp = Xl;
			Xl = Xr;
			Xr = temp;
		}

		temp = Xl;
		Xl = Xr;
		Xr = temp;

		Xr = Xr ^ ctx->P[BF_N];
		Xl = Xl ^ ctx->P[BF_N + 1];

		*xl = Xl;
		*xr = Xr;
	}
	void BlowFish::Blowfish_Decrypt(BLOWFISH_CTX *ctx, unsigned long *xl, unsigned long *xr) {
		unsigned long  Xl;
		unsigned long  Xr;
		unsigned long  temp;
		short       i;

		Xl = *xl;
		Xr = *xr;

		for (i = BF_N + 1; i > 1; --i) {
			Xl = Xl ^ ctx->P[i];
			Xr = F(ctx, Xl) ^ Xr;

			/* Exchange Xl and Xr */
			temp = Xl;
			Xl = Xr;
			Xr = temp;
		}

		/* Exchange Xl and Xr */
		temp = Xl;
		Xl = Xr;
		Xr = temp;

		Xr = Xr ^ ctx->P[1];
		Xl = Xl ^ ctx->P[0];

		*xl = Xl;
		*xr = Xr;
	}
	void BlowFish::Blowfish_Init(BLOWFISH_CTX *ctx, unsigned char *key, int keyLen) {
		int i, j, k;
		unsigned long data, datal, datar;

		MakePS(ctx);

		j = 0;
		for (i = 0; i < BF_N + 2; ++i) {
			data = 0x00000000;
			for (k = 0; k < 4; ++k) {
				data = (data << 8) | key[j];
				j = j + 1;
				if (j >= keyLen)
					j = 0;
			}
			ctx->P[i] ^= data;
		}

		datal = 0x00000000;
		datar = 0x00000000;

		for (i = 0; i < BF_N + 2; i += 2) {
			Blowfish_Encrypt(ctx, &datal, &datar);
			ctx->P[i] = datal;
			ctx->P[i + 1] = datar;
		}

		for (i = 0; i < 4; ++i) {
			for (j = 0; j < 256; j += 2) {
				Blowfish_Encrypt(ctx, &datal, &datar);
				ctx->S[i][j] = datal;
				ctx->S[i][j + 1] = datar;
			}
		}
	}
	void BlowFish::BFBufferDecrypt(char* input, unsigned long inputsize, unsigned char* key, unsigned long keysize)
	{
		BLOWFISH_CTX ctx;
		unsigned long L, R;

		Blowfish_Init(&ctx, key, keysize);

		unsigned long blockSize = sizeof(unsigned long);

		for (unsigned long i = 0; i < inputsize; i += (blockSize * 2))
		{

			memcpy(&L, input + i, blockSize);
			memcpy(&R, input + i + blockSize, blockSize);

			Blowfish_Decrypt(&ctx, &L, &R);

			memcpy(input + i, &L, blockSize);
			memcpy(input + i + blockSize, &R, blockSize);
		}
	}
	void BlowFish::BFBufferEncrypt(char* input, unsigned long inputsize, unsigned char* key, unsigned long keysize)
	{
		BLOWFISH_CTX ctx;
		unsigned long L, R;

		Blowfish_Init(&ctx, key, keysize);
		unsigned long blockSize = sizeof(unsigned long);

		for (unsigned long i = 0; i < inputsize; i += (blockSize * 2))
		{
			memcpy(&L, input + i, blockSize);
			memcpy(&R, input + i + blockSize, blockSize);

			Blowfish_Encrypt(&ctx, &L, &R);

			memcpy(input + i, &L, blockSize);
			memcpy(input + i + blockSize, &R, blockSize);
		}
	}
	int BlowFish::verifyCheckSum(unsigned long CheckSum, char* buf, unsigned long size)
	{
		unsigned long thisCheckSum = 0;
		int count = size / 4;
		if (size % 4) count++;
		for (int i = 0; i < count ; i++)
		{
			thisCheckSum ^= *(unsigned long*)&buf[i * 4];
		}
		if (thisCheckSum == CheckSum)
			return 0;
		else
			return thisCheckSum;
	}
	unsigned long BlowFish::createCheckSum(char* buf, unsigned long size)
	{
		unsigned long thisCheckSum = 0;
		int count = size / 4;
		if (size % 4) count++;
		for (int i = 0; i < count; i++)
		{
			thisCheckSum ^= *(unsigned long*)&buf[i * 4];
		}
		return thisCheckSum;
	}
	void BlowFish::MakePS(BLOWFISH_CTX* ctx)
	{
		memcpy((unsigned char*)&ctx->P[0], (unsigned char*)&ORIG_P[0], sizeof(ORIG_P));
		memcpy((unsigned char*)&ctx->S[0], (unsigned char*)&ORIG_S[0], sizeof(ORIG_S));
		prepareSP(ctx);
	}
	int BlowFish::SDATDecrypt(char* buffer, unsigned long size)
	{
		unsigned char* cryptkey = &SDATkey[0];
		unsigned long cryptokeysize = sizeof(SDATkey);
		int res = BF_OK;
		try
		{
			BFBufferDecrypt(buffer, size, cryptkey, cryptokeysize);
			if (*(unsigned long*)&buffer[0x00] > size) return BF_DECRYPT_FAIL;
			if (verifyCheckSum(*(unsigned long*)&buffer[0x04], &buffer[0x08], *(unsigned long*)&buffer[0x00]) != 0)
				res = BF_CHECKSUM_FAIL;
		}
		catch (std::exception ex)
		{
			res = BF_DECRYPT_FAIL;
		}
		return res;
	}
	int BlowFish::SDATEncrypt(char* buffer, unsigned long size, char** outBuffer)
	{
		unsigned char* cryptkey = &SDATkey[0];
		unsigned long cryptokeysize = sizeof(SDATkey);
		unsigned long outfilesize = size;
		if (outfilesize % 4)
			outfilesize += 4 - (outfilesize % 4);
		int res = BF_OK;
		unsigned long check = createCheckSum(buffer, size);
		outfilesize += 0x08; // file size and checksum
		*outBuffer = (char*)calloc(1, outfilesize);
		if (!*outBuffer)
		{
			return BF_ENCRYPT_FAIL;
		}
		int offset = 0;
		int encryptOffset = offset;
		*(unsigned long*)&outBuffer[0][offset] = size;
		offset += 4;
		*(unsigned long*)&outBuffer[0][offset] = check;
		offset += 4;
		memcpy(&outBuffer[0][offset], buffer, size);

		BFBufferEncrypt(&outBuffer[0][encryptOffset], size + 8, cryptkey, cryptokeysize);
		return outfilesize;
	}
	int BlowFish::PDATDecrypt(char* buffer, unsigned long size)
	{
		unsigned char* cryptkey = &PDATkey[0];
		unsigned long cryptokeysize = sizeof(PDATkey);
		int res = BF_OK;
		try
		{
			BFBufferDecrypt(buffer, size, cryptkey, cryptokeysize);
			if (*(unsigned long*)&buffer[0x00] > size) return BF_DECRYPT_FAIL;
			if (verifyCheckSum(*(unsigned long*)&buffer[0x04], &buffer[0x08], *(unsigned long*)&buffer[0x00]) != 0)
				res = BF_CHECKSUM_FAIL;
		}
		catch (std::exception ex)
		{
			res = BF_DECRYPT_FAIL;
		}
		return res;
	}
	int BlowFish::PDATEncrypt(char* buffer, unsigned long size, char** outBuffer)
	{
		unsigned char* cryptkey = &PDATkey[0];
		unsigned long cryptokeysize = sizeof(PDATkey);
		unsigned long outfilesize = size;
		if (outfilesize % 4)
			outfilesize += 4 - (outfilesize % 4);
		int res = BF_OK;
		unsigned long check = createCheckSum(buffer, size);
		outfilesize += 0x08; // file size and checksum
		*outBuffer = (char*)calloc(1, outfilesize);
		if (!*outBuffer)
		{
			return BF_ENCRYPT_FAIL;
		}
		int offset = 0;
		int encryptOffset = offset;
		*(unsigned long*)&outBuffer[0][offset] = size;
		offset += 4;
		*(unsigned long*)&outBuffer[0][offset] = check;
		offset += 4;
		memcpy(&outBuffer[0][offset], buffer, size);

		BFBufferEncrypt(&outBuffer[0][encryptOffset], size + 8, cryptkey, cryptokeysize);
		return outfilesize;
	}
	int BlowFish::HDATDecrypt(char* buffer, unsigned long size)
	{
		unsigned char* cryptkey = NULL;
		unsigned long cryptokeysize = 16;
		char* cryptBuf = NULL;
		unsigned long _size = size;
		int res = BF_OK;
		if (*(unsigned int*)&buffer[0] == 0x54414443)
		{
			_size -= 20;
			cryptkey = (unsigned char*)&buffer[0x04];
			cryptBuf = &buffer[0x14];
		}
		else return BF_DECRYPT_FAIL;
		try
		{
			BFBufferDecrypt(cryptBuf, _size, cryptkey, cryptokeysize);
			if (*(unsigned long*)&cryptBuf[0x00] > _size) return BF_DECRYPT_FAIL;
			if (verifyCheckSum(*(unsigned long*)&cryptBuf[0x04], &cryptBuf[0x08], *(unsigned long*)&cryptBuf[0x00]) != 0)
				res = BF_CHECKSUM_FAIL;
		}
		catch (std::exception ex)
		{
			res = BF_DECRYPT_FAIL;
		}
		return res;
	}
	int BlowFish::HDATEncrypt(char* buffer, unsigned long size, char** outBuffer)
	{
		unsigned char* cryptkey = nullptr;
		unsigned long cryptokeysize = 16;
		unsigned long outfilesize = size;
		if (outfilesize % 4)
			outfilesize += 4 - (outfilesize % 4);
		int res = BF_OK;
		unsigned long check = createCheckSum(buffer, size);
		unsigned char embeddedKey[16];
		std::chrono::microseconds now = std::chrono::duration_cast<std::chrono::microseconds>(std::chrono::system_clock::now().time_since_epoch()) % 0xffffffff;
		int now32 = 0;
		memcpy((char*)&now32, (char*)&now, 4);
		srand(now32);
		for (int i = 0; i < sizeof(embeddedKey); i++)
		{
			embeddedKey[i] = (rand() % 0xEF) + 0x10;
		}
		cryptkey = &embeddedKey[0x00];

		outfilesize += 0x14; // file identifer and key
		outfilesize += 0x08; // file size and checksum
		*outBuffer = (char*)calloc(1, outfilesize);
		if (!*outBuffer)
		{
			return BF_ENCRYPT_FAIL;
		}
		int offset = 0;
		*(unsigned long*)&outBuffer[0][offset] = 0x54414443;
		offset += 4;
		memcpy(&outBuffer[0][offset], &embeddedKey[0x00], 0x10);
		offset += 0x10;
		*(unsigned long*)&outBuffer[0][offset] = size;
		offset += 4;
		*(unsigned long*)&outBuffer[0][offset] = check;
		offset += 4;
		memcpy(&outBuffer[0][offset], buffer, size);

		BFBufferEncrypt(&outBuffer[0][0x14], size + 8, cryptkey, cryptokeysize);
		return outfilesize;
	}
}