#pragma once

#include <iostream>

#include <osrng.h>
#include <rsa.h>
#include <files.h>
#include <hex.h>

#include "Params.h"


using namespace CryptoPP;
using namespace std;


//  Генерация публичного и секретного ключей для RSA
//  Рекомендуемые размеры ключей: 2048, 3072, 4096
void Generate_Public_and_Private_Keys_For_RSA(int keysize) {
	AutoSeededRandomPool rng;

	InvertibleRSAFunction params;
	params.GenerateRandomWithKeySize(rng, keysize);

	RSA::PrivateKey privateKey(params);
	RSA::PublicKey publicKey(params);

	FileSink private_key_file((KEYS_FOLDER + "PRIVATE_KEY_RSA_" + to_string(keysize) + ".dat").c_str());
	FileSink public_key_file((KEYS_FOLDER + "PUBLIC_KEY_RSA_" + to_string(keysize) + ".dat").c_str());

	privateKey.Save(private_key_file);
	publicKey.Save(public_key_file);
}


//	Чтение публичного ключа из файла
RSA::PublicKey Read_RSA_Public_Key_From_File(string public_key_file_name) {
	RSA::PublicKey publicKey;

	FileSource public_key_file(public_key_file_name.c_str(), true);
	publicKey.Load(public_key_file);

	return publicKey;
}


//  Чтение секретного ключа из файла
RSA::PrivateKey Read_RSA_Private_Key_From_File(string public_key_file_name) {
	RSA::PrivateKey publicKey;

	FileSource public_key_file(public_key_file_name.c_str(), true);
	publicKey.Load(public_key_file);

	return publicKey;
}


//	Шифрование файла при помощи RSA публичным ключом
//  Рекомендуемые размеры ключей: 2048, 3072, 4096
void Encrypt_RSA(string file_name, RSA::PublicKey publicKey) {
	try {
		AutoSeededRandomPool rng;

		RSAES_OAEP_SHA_Encryptor e(publicKey);

		string filename = FOLDER + file_name;
		string encrfile = ENCRYPT_FOLDER + "RSA_ENCRYPT_" + file_name;

		FileSource fs(filename.c_str(), true,
			new PK_EncryptorFilter(rng, e,
				new FileSink(encrfile.c_str())
			)
		);
	}
	catch (const Exception& e) {
		cerr << "Ошибка шифрования файла: " << e.what() << endl;
		throw;
	}
}


//	Расшифрование файла при помощи RSA секретным ключом
//  Рекомендуемые размеры ключей: 2048, 3072, 4096
void Decrypt_RSA(string file_name, RSA::PrivateKey privateKey) {
	try {
		AutoSeededRandomPool rng;

		RSAES_OAEP_SHA_Decryptor d(privateKey);

		string encrfile = ENCRYPT_FOLDER + "RSA_ENCRYPT_" + file_name;
		string decrfile = DECRYPT_FOLDER + "RSA_DECRYPT_" + file_name;

		FileSource fs(encrfile.c_str(), true,
			new PK_DecryptorFilter(rng, d,
				new FileSink(decrfile.c_str())
			)
		);
	}
	catch (const Exception& e) {
		cerr << "Ошибка расшифрования файла: " << e.what() << endl;
		throw;
	}
}