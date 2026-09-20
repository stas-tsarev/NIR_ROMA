#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <Windows.h>

#include "AES.h"
#include "Magma.h"
#include "SHA.h"
#include "Stribog.h"
#include "RSA.h"
#include "ElGamal.h"


using namespace std;
using namespace CryptoPP;


int main() {
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);

	while (true) {
		cout << endl;
		cout << "Выберите шифр:" << endl;
		cout << " 1. AES" << endl;
		cout << " 2. Магма" << endl;
		cout << " 3. SHA3" << endl;
		cout << " 4. Стрибог" << endl;
		cout << " 5. RSA" << endl;
		cout << " 6. Выход из программы" << endl;

		int action;
		cin >> action;

		// AES
		if (action == 1) {
			cout << endl;
			cout << "  Шифр AES:" << endl;
			cout << "   1. Генерация ключа и вектора инициализации" << endl;
			cout << "   2. Шифрование файла" << endl;
			cout << "   3. Расшифрование файла" << endl;
			cout << "   4. Вернуться назад" << endl;

			int temp_action;
			cin >> temp_action;

			if (temp_action == 1) {
				cout << endl;
				cout << "  Шифр AES (Генерация ключа и вектора инициализации):" << endl;

				cout << "  Введите размер ключа (128/192/256):" << endl;
				int key_size;
				cin >> key_size;

				Generic_Key_and_IV_For_AES(key_size);

				cout << "Ключ и вектор инициализации были сгенерированы и сохранены в папке KEYS" << endl;

				continue;
			}

			if (temp_action == 2) {
				cout << endl;
				cout << "  Шифр AES (Шифрование файла):" << endl;
				cout << "  Введите название файла (вместе с его расширением):" << endl;
				string filename;
				cin.ignore();
				getline(cin, filename);

				cout << "  Введите размер ключа (128/192/256):" << endl;
				int key_size;
				cin >> key_size;

				cout << "  Выберите режим шифра:" << endl;
				cout << "   1. ECB - режим простой замены" << endl;
				cout << "   2. CBC - режим простой замены с зацеплением" << endl;
				cout << "   3. CFB - режим гаммирования с обратной связью по шифртексту" << endl;
				cout << "   4. OFB - режим гаммирования с обратной связью по выходу" << endl;
				cout << "   5. CTR - режим гаммирования" << endl;
				int mode_index;
				cin >> mode_index;

				if (mode_index == 1)
					Encrypt_AES(filename, key_size, "ECB");
				if (mode_index == 2)
					Encrypt_AES(filename, key_size, "CBC");
				if (mode_index == 3)
					Encrypt_AES(filename, key_size, "CFB");
				if (mode_index == 4)
					Encrypt_AES(filename, key_size, "OFB");
				if (mode_index == 5)
					Encrypt_AES(filename, key_size, "CTR");

				cout << "Зашифрованный файл был сохранен в папку ENCRYPT" << endl;

				continue;
			}

			if (temp_action == 3) {
				cout << endl;
				cout << "  Шифр AES (Расшифрование файла):" << endl;
				cout << "  Введите название файла (вместе с его расширением):" << endl;
				string filename;
				cin.ignore();
				getline(cin, filename);

				cout << "  Введите размер ключа (128/192/256):" << endl;
				int key_size;
				cin >> key_size;

				cout << "  Выберите режим шифра:" << endl;
				cout << "   1. ECB - режим простой замены" << endl;
				cout << "   2. CBC - режим простой замены с зацеплением" << endl;
				cout << "   3. CFB - режим гаммирования с обратной связью по шифртексту" << endl;
				cout << "   4. OFB - режим гаммирования с обратной связью по выходу" << endl;
				cout << "   5. CTR - режим гаммирования" << endl;
				int mode_index;
				cin >> mode_index;

				if (mode_index == 1)
					Decrypt_AES(filename, key_size, "ECB");
				if (mode_index == 2)
					Decrypt_AES(filename, key_size, "CBC");
				if (mode_index == 3)
					Decrypt_AES(filename, key_size, "CFB");
				if (mode_index == 4)
					Decrypt_AES(filename, key_size, "OFB");
				if (mode_index == 5)
					Decrypt_AES(filename, key_size, "CTR");

				cout << "Расшифрованный файл был сохранен в папку DECRYPT" << endl;

				continue;
			}

			if (temp_action == 4) {
				continue;
			}
		}


		// Magma
		if (action == 2) {
			cout << endl;
			cout << "  Шифр Magma:" << endl;
			cout << "   1. Генерация ключа и вектора инициализации" << endl;
			cout << "   2. Шифрование файла" << endl;
			cout << "   3. Расшифрование файла" << endl;
			cout << "   4. Вернуться назад" << endl;

			int temp_action;
			cin >> temp_action;

			if (temp_action == 1) {
				cout << endl;
				cout << "  Шифр Магма (Генерация ключа и вектора инициализации):" << endl;

				magma::generateKeyToFile(KEYS_FOLDER + "KEY_Magma_256.dat");
				magma::generateIVToFile(KEYS_FOLDER + "IV_Magma_" + to_string(128) + ".dat");

				cout << "Ключ и вектор инициализации были сгенерированы и сохранены в папке KEYS" << endl;

				continue;
			}

			if (temp_action == 2) {
				cout << endl;
				cout << "  Шифр Magma (Шифрование файла):" << endl;
				cout << "  Введите название файла (вместе с его расширением):" << endl;
				string filename;
				cin.ignore();
				getline(cin, filename);

				cout << "  Выберите режим шифра:" << endl;
				cout << "   1. ECB - режим простой замены" << endl;
				cout << "   2. CBC - режим простой замены с зацеплением" << endl;
				cout << "   3. CFB - режим гаммирования с обратной связью по шифртексту" << endl;
				cout << "   4. OFB - режим гаммирования с обратной связью по выходу" << endl;
				cout << "   5. CTR - режим гаммирования" << endl;
				int mode_index;
				cin >> mode_index;

				if (mode_index == 1)
					magma::encryptFile(FOLDER + filename, ENCRYPT_FOLDER + "ECB_Magma_256_ENCRYPT_" + filename, KEYS_FOLDER + "KEY_Magma_256.dat", KEYS_FOLDER + "IV_Magma_" + to_string(128) + ".dat", magma::Mode::ECB);
				if (mode_index == 2)
					magma::encryptFile(FOLDER + filename, ENCRYPT_FOLDER + "CBC_Magma_256_ENCRYPT_" + filename, KEYS_FOLDER + "KEY_Magma_256.dat", KEYS_FOLDER + "IV_Magma_" + to_string(128) + ".dat", magma::Mode::CBC);
				if (mode_index == 3)
					magma::encryptFile(FOLDER + filename, ENCRYPT_FOLDER + "CFB_Magma_256_ENCRYPT_" + filename, KEYS_FOLDER + "KEY_Magma_256.dat", KEYS_FOLDER + "IV_Magma_" + to_string(128) + ".dat", magma::Mode::CFB);
				if (mode_index == 4)
					magma::encryptFile(FOLDER + filename, ENCRYPT_FOLDER + "OFB_Magma_256_ENCRYPT_" + filename, KEYS_FOLDER + "KEY_Magma_256.dat", KEYS_FOLDER + "IV_Magma_" + to_string(128) + ".dat", magma::Mode::OFB);
				if (mode_index == 5)
					magma::encryptFile(FOLDER + filename, ENCRYPT_FOLDER + "CTR_Magma_256_ENCRYPT_" + filename, KEYS_FOLDER + "KEY_Magma_256.dat", KEYS_FOLDER + "IV_Magma_" + to_string(128) + ".dat", magma::Mode::CTR);

				cout << "Зашифрованный файл был сохранен в папку ENCRYPT" << endl;

				continue;
			}

			if (temp_action == 3) {
				cout << endl;
				cout << "  Шифр Магма (Расшифрование файла):" << endl;
				cout << "  Введите название файла (вместе с его расширением):" << endl;
				string filename;
				cin.ignore();
				getline(cin, filename);

				cout << "  Выберите режим шифра:" << endl;
				cout << "   1. ECB - режим простой замены" << endl;
				cout << "   2. CBC - режим простой замены с зацеплением" << endl;
				cout << "   3. CFB - режим гаммирования с обратной связью по шифртексту" << endl;
				cout << "   4. OFB - режим гаммирования с обратной связью по выходу" << endl;
				cout << "   5. CTR - режим гаммирования" << endl;
				int mode_index;
				cin >> mode_index;

				if (mode_index == 1)
					magma::decryptFile(ENCRYPT_FOLDER + "ECB_Magma_256_ENCRYPT_" + filename, DECRYPT_FOLDER + "ECB_Magma_256_ENCRYPT_" + filename, KEYS_FOLDER + "KEY_Magma_256.dat", KEYS_FOLDER + "IV_Magma_" + to_string(128) + ".dat", magma::Mode::ECB);
				if (mode_index == 2)
					magma::decryptFile(ENCRYPT_FOLDER + "CBC_Magma_256_ENCRYPT_" + filename, DECRYPT_FOLDER + "CBC_Magma_256_ENCRYPT_" + filename, KEYS_FOLDER + "KEY_Magma_256.dat", KEYS_FOLDER + "IV_Magma_" + to_string(128) + ".dat", magma::Mode::CBC);
				if (mode_index == 3)
					magma::decryptFile(ENCRYPT_FOLDER + "CFB_Magma_256_ENCRYPT_" + filename, DECRYPT_FOLDER + "CFB_Magma_256_ENCRYPT_" + filename, KEYS_FOLDER + "KEY_Magma_256.dat", KEYS_FOLDER + "IV_Magma_" + to_string(128) + ".dat", magma::Mode::CFB);
				if (mode_index == 4)
					magma::decryptFile(ENCRYPT_FOLDER + "OFB_Magma_256_ENCRYPT_" + filename, DECRYPT_FOLDER + "OFB_Magma_256_ENCRYPT_" + filename, KEYS_FOLDER + "KEY_Magma_256.dat", KEYS_FOLDER + "IV_Magma_" + to_string(128) + ".dat", magma::Mode::OFB);
				if (mode_index == 5)
					magma::decryptFile(ENCRYPT_FOLDER + "CTR_Magma_256_ENCRYPT_" + filename, DECRYPT_FOLDER + "CTR_Magma_256_ENCRYPT_" + filename, KEYS_FOLDER + "KEY_Magma_256.dat", KEYS_FOLDER + "IV_Magma_" + to_string(128) + ".dat", magma::Mode::CTR);

				cout << "Расшифрованный файл был сохранен в папку DECRYPT" << endl;

				continue;
			}

			if (temp_action == 4) {
				continue;
			}
		}


		// SHA3
		if (action == 3) {
			cout << endl;
			cout << "  Хеш-функция SHA3:" << endl;
			cout << "   1. Хеш от строки" << endl;
			cout << "   2. Хеш от файла" << endl;
			cout << "   3. Вернуться назад" << endl;

			int temp_action;
			cin >> temp_action;

			if (temp_action == 1) {
				cout << endl;
				cout << "  Хеш-функция SHA3 (Хеш от строки):" << endl;

				cout << "  Введите длину хеша в битах (224/256/384/512):" << endl;
				int hash_size;
				cin >> hash_size;

				cout << "  Введите сообщение:" << endl;;
				string message;
				cin.ignore();
				getline(cin, message);

				cout << "Значение хеша: " << SHA_3_For_String(message, hash_size) << endl;

				continue;
			}

			if (temp_action == 2) {
				cout << endl;
				cout << "  Хеш-функция SHA3 (Хеш от файла):" << endl;

				cout << "  Введите длину хеша в битах (224/256/384/512):" << endl;
				int hash_size;
				cin >> hash_size;

				cout << "  Введите название файла (вместе с его расширением):" << endl;;
				string filename;
				cin.ignore();
				getline(cin, filename);

				cout << "Значение хеша: " << SHA_3_For_File(filename, hash_size) << endl;

				continue;
			}

			if (temp_action == 3) {
				continue;
			}
		}

		
		// Stribog
		if (action == 4) {
			cout << endl;
			cout << "  Хеш-функция Стрибог:" << endl;
			cout << "   1. Хеш от строки" << endl;
			cout << "   2. Хеш от файла" << endl;
			cout << "   3. Вернуться назад" << endl;

			int temp_action;
			cin >> temp_action;

			if (temp_action == 1) {
				cout << endl;
				cout << "  Хеш-функция Стрибог (Хеш от строки):" << endl;

				cout << "  Введите длину хеша в битах (256 / 512):" << endl;
				int hash_size;
				cin >> hash_size;

				cout << "  Введите сообщение:" << endl;;
				string message;
				cin.ignore();
				getline(cin, message);

				if (hash_size == 256)
					cout << "Значение хеша: " << streebog::Streebog::hashString(message, 256) << endl;
				if (hash_size == 512)
					cout << "Значение хеша: " << streebog::Streebog::hashString(message, 512) << endl;

				continue;
			}

			if (temp_action == 2) {
				cout << endl;
				cout << "  Хеш-функция Стрибог (Хеш от файла):" << endl;

				cout << "  Введите длину хеша в битах (256 / 512):" << endl;
				int hash_size;
				cin >> hash_size;

				cout << "  Введите название файла (вместе с его расширением):" << endl;;
				string filename;
				cin.ignore();
				getline(cin, filename);

				if (hash_size == 256)
					cout << "Значение хеша: " << streebog::Streebog::hashFile(FOLDER + filename, 256) << endl;
				if (hash_size == 512)
					cout << "Значение хеша: " << streebog::Streebog::hashFile(FOLDER + filename, 512) << endl;

				continue;
			}

			if (temp_action == 3) {
				continue;
			}
		}

		// RSA
		if (action == 5) {
			cout << endl;
			cout << "  Шифр RSA:" << endl;
			cout << "   1. Генерация публичного и секретного ключей" << endl;
			cout << "   2. Шифрование файла" << endl;
			cout << "   3. Расшифрование файла" << endl;
			cout << "   4. Вернуться назад" << endl;

			int temp_action;
			cin >> temp_action;

			if (temp_action == 1) {
				cout << endl;
				cout << "  Шифр RSA (Генерация публичного и секретного ключей):" << endl;

				cout << "  Введите размер ключа (Рекомендуемые: 2048/3072/4096):" << endl;
				int key_size;
				cin >> key_size;

				Generate_Public_and_Private_Keys_For_RSA(key_size);

				cout << "Публичный и секретный ключи были сгенерированы и сохранены в папке KEYS" << endl;

				continue;
			}

			if (temp_action == 2) {
				cout << endl;
				cout << "  Шифр RSA (Шифрование файла):" << endl;
				cout << "  Введите название файла (вместе с его расширением):" << endl;
				string filename;
				cin.ignore();
				getline(cin, filename);

				cout << "  Введите размер ключа (Рекомендуемые: 2048/3072/4096):" << endl;
				int key_size;
				cin >> key_size;

				RSA::PublicKey public_key = Read_RSA_Public_Key_From_File(KEYS_FOLDER + "PUBLIC_KEY_RSA_" + to_string(key_size) + ".dat");
				Encrypt_RSA(filename, public_key);

				cout << "Зашифрованный файл был сохранен в папку ENCRYPT" << endl;

				continue;
			}

			if (temp_action == 3) {
				cout << endl;
				cout << "  Шифр RSA (Расшифрование файла):" << endl;
				cout << "  Введите название файла (вместе с его расширением):" << endl;
				string filename;
				cin.ignore();
				getline(cin, filename);

				cout << "  Введите размер ключа (Рекомендуемые: 2048/3072/4096):" << endl;
				int key_size;
				cin >> key_size;

				RSA::PrivateKey private_key = Read_RSA_Private_Key_From_File(KEYS_FOLDER + "PRIVATE_KEY_RSA_" + to_string(key_size) + ".dat");
				Decrypt_RSA(filename, private_key);

				cout << "Расшифрованный файл был сохранен в папку DECRYPT" << endl;

				continue;
			}

			if (temp_action == 4) {
				continue;
			}
		}

		// Выход из программы
		if (action == 6)
			break;
	}
	return 0;
}