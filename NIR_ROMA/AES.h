#pragma once

#include <rijndael.h>
#include <osrng.h>
#include <hex.h>
#include <files.h>
#include <modes.h>

#include <iostream>
#include <fstream>

#include "Params.h"


using namespace std;
using namespace CryptoPP;


//	Генерация ключа и веткора инициализации,
//	ключ может иметь длину 128, 192 и 256 бит.
void Generic_Key_and_IV_For_AES(int key_size)
{
	AutoSeededRandomPool prng;

	if (key_size != 128 && key_size != 192 && key_size != 256) {
		throw invalid_argument("Неподдерживаемый размер ключа!!!");
	}

	SecByteBlock key(key_size / 8);
	SecByteBlock iv(AES::BLOCKSIZE);

	prng.GenerateBlock(key, key.size());
	prng.GenerateBlock(iv, iv.size());

	ofstream key_file, iv_file;

	key_file.open(KEYS_FOLDER + "KEY_AES_" + to_string(key_size) + ".dat");
	iv_file.open(KEYS_FOLDER + "IV_AES_" + to_string(128) + ".dat");

	HexEncoder key_hex_encoder(new FileSink(key_file));
	HexEncoder iv_hex_encoder(new FileSink(iv_file));

	key_hex_encoder.Put(key, key.size());
	iv_hex_encoder.Put(iv, iv.size());

	key_file.close();
	iv_file.close();
}


//	Чтение ключа из файла
SecByteBlock Read_AES_Key_From_File(string key_file_name)
{
	ifstream key_file(key_file_name);

	string key_hex_str, key_byte_str;
	key_file >> key_hex_str;
	StringSource ss1(key_hex_str, true,
		new HexDecoder(
			new StringSink(key_byte_str)));
	SecByteBlock key(
		reinterpret_cast<const byte*>(key_byte_str.data()),
		key_byte_str.size());

	key_file.close();
	return key;
}


//	Чтение вектора инициализации из файла
SecByteBlock Read_AES_IV_From_File(string iv_file_name)
{
	ifstream iv_file(iv_file_name);

	string iv_hex_str, iv_byte_str;
	iv_file >> iv_hex_str;
	StringSource ss2(iv_hex_str, true,
		new HexDecoder(
			new StringSink(iv_byte_str)));
	SecByteBlock iv(
		reinterpret_cast<const byte*>(iv_byte_str.data()),
		iv_byte_str.size());

	iv_file.close();
	return iv;
}


//	Шифрование файла при помощи AES
//	Доступные режимы:	ECB, CBC, CFB, OFB, CTR
//	Размеры ключей:		128, 192, 256
bool Encrypt_AES(string file_name, int key_size, string mode)
{
	if (key_size != 128 && key_size != 192 && key_size != 256) {
		throw invalid_argument("Неподдерживаемый размер ключа!!!");
	}

	if (mode != "ECB" &&
		mode != "CBC" &&
		mode != "CFB" &&
		mode != "OFB" &&
		mode != "CTR") {
		throw invalid_argument("Неподдерживаемый режим для AES!!!");
	}

	string filename = FOLDER + file_name;
	string encrfile = ENCRYPT_FOLDER + mode + "_AES_" + to_string(key_size) + "_ENCRYPT_" + file_name;

	if (mode == "ECB") {
		try {
			SecByteBlock key = Read_AES_Key_From_File(KEYS_FOLDER + "KEY_AES_" + to_string(key_size) + ".dat");

			ECB_Mode< AES >::Encryption e;
			e.SetKey(key, key.size());

			FileSource sf(filename.c_str(), true,
				new StreamTransformationFilter(e,
					new FileSink(encrfile.c_str())));
		}
		catch (const Exception& e) {
			std::cerr << e.what() << std::endl;
			exit(1);
		}
	}

	if (mode == "CBC") {
		try
		{
			SecByteBlock key = Read_AES_Key_From_File(KEYS_FOLDER + "KEY_AES_" + to_string(key_size) + ".dat");
			SecByteBlock iv = Read_AES_IV_From_File(KEYS_FOLDER + "IV_AES_" + to_string(key_size) + ".dat");

			CBC_Mode< AES >::Encryption e;
			e.SetKeyWithIV(key, key.size(), iv);

			FileSource sf(filename.c_str(), true,
				new StreamTransformationFilter(e,
					new FileSink(encrfile.c_str())));
		}
		catch (const Exception& e)
		{
			std::cerr << e.what() << std::endl;
			exit(1);
		}
	}

	if (mode == "CFB") {
		try
		{
			SecByteBlock key = Read_AES_Key_From_File(KEYS_FOLDER + "KEY_AES_" + to_string(key_size) + ".dat");
			SecByteBlock iv = Read_AES_IV_From_File(KEYS_FOLDER + "IV_AES_" + to_string(key_size) + ".dat");

			CFB_Mode< AES >::Encryption e;
			e.SetKeyWithIV(key, key.size(), iv);

			FileSource sf(filename.c_str(), true,
				new StreamTransformationFilter(e,
					new FileSink(encrfile.c_str())));
		}
		catch (const Exception& e)
		{
			std::cerr << e.what() << std::endl;
			exit(1);
		}
	}

	if (mode == "OFB") {
		try
		{
			SecByteBlock key = Read_AES_Key_From_File(KEYS_FOLDER + "KEY_AES_" + to_string(key_size) + ".dat");
			SecByteBlock iv = Read_AES_IV_From_File(KEYS_FOLDER + "IV_AES_" + to_string(key_size) + ".dat");

			OFB_Mode< AES >::Encryption e;
			e.SetKeyWithIV(key, key.size(), iv);

			FileSource sf(filename.c_str(), true,
				new StreamTransformationFilter(e,
					new FileSink(encrfile.c_str())));
		}
		catch (const Exception& e)
		{
			std::cerr << e.what() << std::endl;
			exit(1);
		}
	}

	if (mode == "CTR") {
		try
		{
			SecByteBlock key = Read_AES_Key_From_File(KEYS_FOLDER + "KEY_AES_" + to_string(key_size) + ".dat");
			SecByteBlock iv = Read_AES_IV_From_File(KEYS_FOLDER + "IV_AES_" + to_string(key_size) + ".dat");

			CTR_Mode< AES >::Encryption e;
			e.SetKeyWithIV(key, key.size(), iv);

			FileSource sf(filename.c_str(), true,
				new StreamTransformationFilter(e,
					new FileSink(encrfile.c_str())));
		}
		catch (const Exception& e)
		{
			std::cerr << e.what() << std::endl;
			exit(1);
		}
	}
}


//	Расшифрование файла при помощи AES
//	Доступные режимы:	ECB, CBC, CFB, OFB, CTR
//	Размеры ключей:		128, 192, 256
bool Decrypt_AES(string file_name, int key_size, string mode)
{
	if (key_size != 128 && key_size != 192 && key_size != 256) {
		throw invalid_argument("Неподдерживаемый размер ключа!!!");
	}

	if (mode != "ECB" &&
		mode != "CBC" &&
		mode != "CFB" &&
		mode != "OFB" &&
		mode != "CTR") {
		throw invalid_argument("Неподдерживаемый режим для AES!!!");
	}

	string encrfile = ENCRYPT_FOLDER + mode + "_AES_" + to_string(key_size) + "_ENCRYPT_" + file_name;
	string decrfile = DECRYPT_FOLDER + mode + "_AES_" + to_string(key_size) + "_DECRYPT_" + file_name;

	if (mode == "ECB") {
		try {
			SecByteBlock key = Read_AES_Key_From_File(KEYS_FOLDER + "KEY_AES_" + to_string(key_size) + ".dat");

			ECB_Mode< AES >::Decryption d;
			d.SetKey(key, key.size());

			FileSource sf(encrfile.c_str(), true,
				new StreamTransformationFilter(d,
					new FileSink(decrfile.c_str())));
		}
		catch (const Exception& e) {
			std::cerr << e.what() << std::endl;
			exit(2);
		}
	}

	if (mode == "CBC") {
		try {
			SecByteBlock key = Read_AES_Key_From_File(KEYS_FOLDER + "KEY_AES_" + to_string(key_size) + ".dat");
			SecByteBlock iv = Read_AES_IV_From_File(KEYS_FOLDER + "IV_AES_" + to_string(key_size) + ".dat");

			CBC_Mode< AES >::Decryption d;
			d.SetKeyWithIV(key, key.size(), iv);

			FileSource sf(encrfile.c_str(), true,
				new StreamTransformationFilter(d,
					new FileSink(decrfile.c_str())));
		}
		catch (const Exception& e)
		{
			std::cerr << e.what() << std::endl;
			exit(2);
		}
	}

	if (mode == "CFB") {
		try {
			SecByteBlock key = Read_AES_Key_From_File(KEYS_FOLDER + "KEY_AES_" + to_string(key_size) + ".dat");
			SecByteBlock iv = Read_AES_IV_From_File(KEYS_FOLDER + "IV_AES_" + to_string(key_size) + ".dat");

			CFB_Mode< AES >::Decryption d;
			d.SetKeyWithIV(key, key.size(), iv);

			FileSource sf(encrfile.c_str(), true,
				new StreamTransformationFilter(d,
					new FileSink(decrfile.c_str())));
		}
		catch (const Exception& e)
		{
			std::cerr << e.what() << std::endl;
			exit(2);
		}
	}

	if (mode == "OFB") {
		try {
			SecByteBlock key = Read_AES_Key_From_File(KEYS_FOLDER + "KEY_AES_" + to_string(key_size) + ".dat");
			SecByteBlock iv = Read_AES_IV_From_File(KEYS_FOLDER + "IV_AES_" + to_string(key_size) + ".dat");

			OFB_Mode< AES >::Decryption d;
			d.SetKeyWithIV(key, key.size(), iv);

			FileSource sf(encrfile.c_str(), true,
				new StreamTransformationFilter(d,
					new FileSink(decrfile.c_str())));
		}
		catch (const Exception& e)
		{
			std::cerr << e.what() << std::endl;
			exit(2);
		}
	}

	if (mode == "CTR") {
		try {
			SecByteBlock key = Read_AES_Key_From_File(KEYS_FOLDER + "KEY_AES_" + to_string(key_size) + ".dat");
			SecByteBlock iv = Read_AES_IV_From_File(KEYS_FOLDER + "IV_AES_" + to_string(key_size) + ".dat");

			CTR_Mode< AES >::Decryption d;
			d.SetKeyWithIV(key, key.size(), iv);

			FileSource sf(encrfile.c_str(), true,
				new StreamTransformationFilter(d,
					new FileSink(decrfile.c_str())));
		}
		catch (const Exception& e)
		{
			std::cerr << e.what() << std::endl;
			exit(2);
		}
	}
}