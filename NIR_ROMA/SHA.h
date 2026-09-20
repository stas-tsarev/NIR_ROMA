#pragma once

#include <iostream>
#include <hex.h>
#include <sha3.h>
#include <osrng.h>
#include <files.h>

#include "Params.h"


using namespace CryptoPP;
using namespace std;


//  Значение хеш-функции SHA3 от сообщения
//  Допустимые размеры хеша: 224, 256, 384, 512
string SHA_3_For_String(string msg, int size) {
	if (
		size != 224 &&
		size != 256 &&
		size != 384 &&
		size != 512) {
		throw invalid_argument("Неподдерживаемый размер хеш-функции!!!");
	}

	string result;

	if (size == 224) {
		string digest;

		SHA3_224 hash;
		hash.Update((const byte*)msg.data(), msg.size());
		digest.resize(hash.DigestSize());
		hash.Final((byte*)&digest[0]);

		StringSource f(digest, true,
			new HexEncoder(
				new StringSink(result)
			)
		);
	}

	if (size == 256) {
		string digest;

		SHA3_256 hash;
		hash.Update((const byte*)msg.data(), msg.size());
		digest.resize(hash.DigestSize());
		hash.Final((byte*)&digest[0]);

		StringSource f(digest, true,
			new HexEncoder(
				new StringSink(result)
			)
		);
	}

	if (size == 384) {
		string digest;

		SHA3_384 hash;
		hash.Update((const byte*)msg.data(), msg.size());
		digest.resize(hash.DigestSize());
		hash.Final((byte*)&digest[0]);

		StringSource f(digest, true,
			new HexEncoder(
				new StringSink(result)
			)
		);
	}

	if (size == 512) {
		string digest;

		SHA3_512 hash;
		hash.Update((const byte*)msg.data(), msg.size());
		digest.resize(hash.DigestSize());
		hash.Final((byte*)&digest[0]);

		StringSource f(digest, true,
			new HexEncoder(
				new StringSink(result)
			)
		);
	}

	return result;
}


//  Значение хеш-функции SHA3 от файла
//  Допустимые размеры хеша: 224, 256, 384, 512
string SHA_3_For_File(string filename, int size) {
	if (
		size != 224 &&
		size != 256 &&
		size != 384 &&
		size != 512) {
		throw invalid_argument("Неподдерживаемый размер хеш-функции!!!");
	}

	ifstream file(FOLDER + filename, ios::binary);
	if (!file.is_open())
	{
		throw runtime_error("Не удалось открыть файл: " + filename);
	}

	const size_t buffer_size = 8192; // 8KB буфер
	byte buffer[buffer_size];

	string result;

	if (size == 224) {
		string digest;

		SHA3_224 hash;

		while (file.read(reinterpret_cast<char*>(buffer), buffer_size) || file.gcount() > 0)
		{
			hash.Update(buffer, file.gcount());
		}
		file.close();

		digest.resize(hash.DigestSize());
		hash.Final(reinterpret_cast<byte*>(&digest[0]));

		StringSource f(digest, true,
			new HexEncoder(
				new StringSink(result)
			)
		);
	}

	if (size == 256) {
		string digest;

		SHA3_256 hash;

		while (file.read(reinterpret_cast<char*>(buffer), buffer_size) || file.gcount() > 0)
		{
			hash.Update(buffer, file.gcount());
		}
		file.close();

		digest.resize(hash.DigestSize());
		hash.Final(reinterpret_cast<byte*>(&digest[0]));

		StringSource f(digest, true,
			new HexEncoder(
				new StringSink(result)
			)
		);
	}

	if (size == 384) {
		string digest;

		SHA3_384 hash;

		while (file.read(reinterpret_cast<char*>(buffer), buffer_size) || file.gcount() > 0)
		{
			hash.Update(buffer, file.gcount());
		}
		file.close();

		digest.resize(hash.DigestSize());
		hash.Final(reinterpret_cast<byte*>(&digest[0]));

		StringSource f(digest, true,
			new HexEncoder(
				new StringSink(result)
			)
		);
	}

	if (size == 512) {
		string digest;

		SHA3_512 hash;

		while (file.read(reinterpret_cast<char*>(buffer), buffer_size) || file.gcount() > 0)
		{
			hash.Update(buffer, file.gcount());
		}
		file.close();

		digest.resize(hash.DigestSize());
		hash.Final(reinterpret_cast<byte*>(&digest[0]));

		StringSource f(digest, true,
			new HexEncoder(
				new StringSink(result)
			)
		);
	}

	return result;
}