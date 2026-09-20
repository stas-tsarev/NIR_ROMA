#ifndef MAGMA_H
#define MAGMA_H

#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <fstream>
#include <stdexcept>
#include <random>
#include <algorithm>

namespace magma {

    // ==================== S-блоки ГОСТ Р 34.12-2015 ====================

    const uint8_t SBOX[8][16] = {
        {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1},
        {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15},
        {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0},
        {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11},
        {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12},
        {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0},
        {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7},
        {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2}
    };

    using Block = std::vector<uint8_t>;
    using Key = std::vector<uint8_t>;

    // ==================== Вспомогательные ====================

    inline uint32_t load_le32(const uint8_t* p) {
        return static_cast<uint32_t>(p[0]) |
            (static_cast<uint32_t>(p[1]) << 8) |
            (static_cast<uint32_t>(p[2]) << 16) |
            (static_cast<uint32_t>(p[3]) << 24);
    }

    inline void store_le32(uint8_t* p, uint32_t v) {
        p[0] = static_cast<uint8_t>(v);
        p[1] = static_cast<uint8_t>(v >> 8);
        p[2] = static_cast<uint8_t>(v >> 16);
        p[3] = static_cast<uint8_t>(v >> 24);
    }

    inline uint32_t rotl32(uint32_t v, int n) {
        return (v << n) | (v >> (32 - n));
    }

    inline void xorBlock(uint8_t* dst, const uint8_t* src, size_t len = 8) {
        for (size_t i = 0; i < len; ++i) dst[i] ^= src[i];
    }

    inline void addMod2_64(uint8_t* block, uint64_t add) {
        uint64_t val = 0;
        for (int i = 0; i < 8; ++i) {
            val |= static_cast<uint64_t>(block[i]) << (i * 8);
        }
        val += add;
        for (int i = 0; i < 8; ++i) {
            block[i] = static_cast<uint8_t>(val >> (i * 8));
        }
    }

    // ==================== Файловые утилиты ====================

    inline std::vector<uint8_t> readFile(const std::string& path) {
        std::ifstream f(path, std::ios::binary | std::ios::ate);
        if (!f) throw std::runtime_error("Cannot open file for reading: " + path);
        std::streamsize size = f.tellg();
        f.seekg(0, std::ios::beg);
        std::vector<uint8_t> data(static_cast<size_t>(size));
        if (size > 0) {
            if (!f.read(reinterpret_cast<char*>(data.data()), size)) {
                throw std::runtime_error("Failed to read file: " + path);
            }
        }
        return data;
    }

    inline void writeFile(const std::string& path, const std::vector<uint8_t>& data) {
        std::ofstream f(path, std::ios::binary | std::ios::trunc);
        if (!f) throw std::runtime_error("Cannot open file for writing: " + path);
        if (!data.empty()) {
            f.write(reinterpret_cast<const char*>(data.data()),
                static_cast<std::streamsize>(data.size()));
        }
        if (!f) throw std::runtime_error("Failed to write file: " + path);
    }

    // ==================== Генерация и сохранение ключа/IV ====================

    inline Key generateKeyToFile(const std::string& path) {
        Key key(32);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(0, 255);
        for (auto& b : key) b = static_cast<uint8_t>(dist(gen));
        writeFile(path, key);
        return key;
    }

    inline Block generateIVToFile(const std::string& path) {
        Block iv(8);
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<int> dist(0, 255);
        for (auto& b : iv) b = static_cast<uint8_t>(dist(gen));
        writeFile(path, iv);
        return iv;
    }

    inline Key readKeyFromFile(const std::string& path) {
        auto data = readFile(path);
        if (data.size() != 32)
            throw std::runtime_error("Key file must be 32 bytes: " + path);
        return data;
    }

    inline Block readIVFromFile(const std::string& path) {
        auto data = readFile(path);
        if (data.size() != 8)
            throw std::runtime_error("IV file must be 8 bytes: " + path);
        return data;
    }

    // ==================== Преобразования Магмы ====================

    inline uint32_t transformT(uint32_t x) {
        uint32_t result = 0;
        for (int i = 0; i < 8; ++i) {
            uint8_t nibble = (x >> (i * 4)) & 0x0F;
            result |= static_cast<uint32_t>(SBOX[i][nibble]) << (i * 4);
        }
        return result;
    }

    inline uint32_t g(uint32_t a, uint32_t k) {
        return rotl32(transformT(a + k), 11);
    }

    // ==================== Блочные операции ====================

    inline void encryptBlock(const Key& key, const uint8_t* input, uint8_t* output) {
        uint32_t n1 = load_le32(input);
        uint32_t n2 = load_le32(input + 4);

        uint32_t roundKeys[32];
        for (int i = 0; i < 8; ++i) {
            roundKeys[i] = load_le32(key.data() + i * 4);
            roundKeys[i + 8] = roundKeys[i];
            roundKeys[i + 16] = roundKeys[i];
        }
        for (int i = 0; i < 8; ++i) {
            roundKeys[24 + i] = roundKeys[7 - i];
        }

        for (int i = 0; i < 31; ++i) {
            uint32_t tmp = n1;
            n1 = n2 ^ g(n1, roundKeys[i]);
            n2 = tmp;
        }
        n2 = n2 ^ g(n1, roundKeys[31]);

        store_le32(output, n2);
        store_le32(output + 4, n1);
    }

    inline void decryptBlock(const Key& key, const uint8_t* input, uint8_t* output) {
        uint32_t n1 = load_le32(input);
        uint32_t n2 = load_le32(input + 4);

        uint32_t roundKeys[32];
        for (int i = 0; i < 8; ++i) {
            roundKeys[i] = load_le32(key.data() + i * 4);
            roundKeys[i + 8] = roundKeys[i];
            roundKeys[i + 16] = roundKeys[i];
        }
        for (int i = 0; i < 8; ++i) {
            roundKeys[24 + i] = roundKeys[7 - i];
        }

        for (int i = 0; i < 31; ++i) {
            uint32_t tmp = n1;
            n1 = n2 ^ g(n1, roundKeys[31 - i]);
            n2 = tmp;
        }
        n2 = n2 ^ g(n1, roundKeys[0]);

        store_le32(output, n2);
        store_le32(output + 4, n1);
    }

    // ==================== Padding (ISO/IEC 9797-1, метод 2) ====================

    // Добавляем 0x80, затем нули до кратности 8
    inline std::vector<uint8_t> padMessage(const std::vector<uint8_t>& data) {
        std::vector<uint8_t> padded(data);
        padded.push_back(0x80);
        while (padded.size() % 8 != 0) padded.push_back(0x00);
        return padded;
    }

    // Корректное снятие padding: ищем последний 0x80, отбрасываем всё после него
    inline std::vector<uint8_t> unpadMessage(const std::vector<uint8_t>& data) {
        if (data.empty()) return data;
        // Идём с конца, отбрасываем нули
        size_t i = data.size();
        while (i > 0 && data[i - 1] == 0x00) --i;
        // Ожидаем 0x80
        if (i == 0 || data[i - 1] != 0x80) {
            throw std::runtime_error("Invalid padding: no 0x80 marker found");
        }
        return std::vector<uint8_t>(data.begin(), data.begin() + (i - 1));
    }

    // ==================== Режимы (буферные) ====================

    // ---- ECB ----
    inline std::vector<uint8_t> encryptECBBuf(const Key& key, const std::vector<uint8_t>& plaintext) {
        auto data = padMessage(plaintext);
        std::vector<uint8_t> ciphertext(data.size());
        for (size_t i = 0; i < data.size(); i += 8)
            encryptBlock(key, data.data() + i, ciphertext.data() + i);
        return ciphertext;
    }

    inline std::vector<uint8_t> decryptECBBuf(const Key& key, const std::vector<uint8_t>& ciphertext) {
        if (ciphertext.empty() || ciphertext.size() % 8 != 0)
            throw std::runtime_error("ECB: ciphertext size must be non-zero multiple of 8");
        std::vector<uint8_t> plaintext(ciphertext.size());
        for (size_t i = 0; i < ciphertext.size(); i += 8)
            decryptBlock(key, ciphertext.data() + i, plaintext.data() + i);
        return unpadMessage(plaintext);
    }

    // ---- CBC ----
    inline std::vector<uint8_t> encryptCBCBuf(const Key& key, const Block& iv, const std::vector<uint8_t>& plaintext) {
        if (iv.size() != 8) throw std::runtime_error("CBC: IV must be 8 bytes");
        auto data = padMessage(plaintext);
        std::vector<uint8_t> ciphertext(data.size());
        uint8_t prev[8];
        memcpy(prev, iv.data(), 8);

        for (size_t i = 0; i < data.size(); i += 8) {
            uint8_t block[8];
            memcpy(block, data.data() + i, 8);
            xorBlock(block, prev);
            encryptBlock(key, block, ciphertext.data() + i);
            memcpy(prev, ciphertext.data() + i, 8);
        }
        return ciphertext;
    }

    inline std::vector<uint8_t> decryptCBCBuf(const Key& key, const Block& iv, const std::vector<uint8_t>& ciphertext) {
        if (iv.size() != 8) throw std::runtime_error("CBC: IV must be 8 bytes");
        if (ciphertext.empty() || ciphertext.size() % 8 != 0)
            throw std::runtime_error("CBC: ciphertext size must be non-zero multiple of 8");
        std::vector<uint8_t> plaintext(ciphertext.size());
        uint8_t prev[8];
        memcpy(prev, iv.data(), 8);

        for (size_t i = 0; i < ciphertext.size(); i += 8) {
            uint8_t block[8];
            decryptBlock(key, ciphertext.data() + i, block);
            xorBlock(block, prev);
            memcpy(plaintext.data() + i, block, 8);
            memcpy(prev, ciphertext.data() + i, 8);
        }
        return unpadMessage(plaintext);
    }

    // ---- CFB ----
    inline std::vector<uint8_t> encryptCFBBuf(const Key& key, const Block& iv, const std::vector<uint8_t>& plaintext) {
        if (iv.size() != 8) throw std::runtime_error("CFB: IV must be 8 bytes");
        std::vector<uint8_t> ciphertext(plaintext.size());
        uint8_t feedback[8];
        memcpy(feedback, iv.data(), 8);

        for (size_t i = 0; i < plaintext.size(); i += 8) {
            uint8_t keystream[8];
            encryptBlock(key, feedback, keystream);
            size_t blockLen = std::min<size_t>(8, plaintext.size() - i);
            for (size_t j = 0; j < blockLen; ++j)
                ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
            if (blockLen == 8) {
                memcpy(feedback, ciphertext.data() + i, 8);
            }
            else {
                memmove(feedback, feedback + blockLen, 8 - blockLen);
                memcpy(feedback + 8 - blockLen, ciphertext.data() + i, blockLen);
            }
        }
        return ciphertext;
    }

    inline std::vector<uint8_t> decryptCFBBuf(const Key& key, const Block& iv, const std::vector<uint8_t>& ciphertext) {
        if (iv.size() != 8) throw std::runtime_error("CFB: IV must be 8 bytes");
        std::vector<uint8_t> plaintext(ciphertext.size());
        uint8_t feedback[8];
        memcpy(feedback, iv.data(), 8);

        for (size_t i = 0; i < ciphertext.size(); i += 8) {
            uint8_t keystream[8];
            encryptBlock(key, feedback, keystream);
            size_t blockLen = std::min<size_t>(8, ciphertext.size() - i);
            for (size_t j = 0; j < blockLen; ++j)
                plaintext[i + j] = ciphertext[i + j] ^ keystream[j];
            if (blockLen == 8) {
                memcpy(feedback, ciphertext.data() + i, 8);
            }
            else {
                memmove(feedback, feedback + blockLen, 8 - blockLen);
                memcpy(feedback + 8 - blockLen, ciphertext.data() + i, blockLen);
            }
        }
        return plaintext;
    }

    // ---- OFB ----
    inline std::vector<uint8_t> encryptOFBBuf(const Key& key, const Block& iv, const std::vector<uint8_t>& plaintext) {
        if (iv.size() != 8) throw std::runtime_error("OFB: IV must be 8 bytes");
        std::vector<uint8_t> ciphertext(plaintext.size());
        uint8_t feedback[8];
        memcpy(feedback, iv.data(), 8);

        for (size_t i = 0; i < plaintext.size(); i += 8) {
            uint8_t keystream[8];
            encryptBlock(key, feedback, keystream);
            memcpy(feedback, keystream, 8);
            size_t blockLen = std::min<size_t>(8, plaintext.size() - i);
            for (size_t j = 0; j < blockLen; ++j)
                ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
        }
        return ciphertext;
    }

    inline std::vector<uint8_t> decryptOFBBuf(const Key& key, const Block& iv, const std::vector<uint8_t>& ciphertext) {
        return encryptOFBBuf(key, iv, ciphertext);
    }

    // ---- CTR ----
    inline std::vector<uint8_t> encryptCTRBuf(const Key& key, const Block& iv, const std::vector<uint8_t>& plaintext) {
        if (iv.size() != 8) throw std::runtime_error("CTR: IV must be 8 bytes");
        std::vector<uint8_t> ciphertext(plaintext.size());
        uint8_t counter[8];
        memcpy(counter, iv.data(), 8);

        for (size_t i = 0; i < plaintext.size(); i += 8) {
            uint8_t keystream[8];
            encryptBlock(key, counter, keystream);
            size_t blockLen = std::min<size_t>(8, plaintext.size() - i);
            for (size_t j = 0; j < blockLen; ++j)
                ciphertext[i + j] = plaintext[i + j] ^ keystream[j];
            addMod2_64(counter, 1);
        }
        return ciphertext;
    }

    inline std::vector<uint8_t> decryptCTRBuf(const Key& key, const Block& iv, const std::vector<uint8_t>& ciphertext) {
        return encryptCTRBuf(key, iv, ciphertext);
    }

    // ==================== Режимы (над файлами) ====================

    enum class Mode { ECB, CBC, CFB, OFB, CTR };

    inline void encryptFile(const std::string& inputPath,
        const std::string& outputPath,
        const std::string& keyPath,
        const std::string& ivPath,
        Mode mode) {
        Key key = readKeyFromFile(keyPath);
        auto plaintext = readFile(inputPath);

        std::vector<uint8_t> ciphertext;
        if (mode == Mode::ECB) {
            ciphertext = encryptECBBuf(key, plaintext);
        }
        else {
            Block iv = readIVFromFile(ivPath);
            switch (mode) {
            case Mode::CBC: ciphertext = encryptCBCBuf(key, iv, plaintext); break;
            case Mode::CFB: ciphertext = encryptCFBBuf(key, iv, plaintext); break;
            case Mode::OFB: ciphertext = encryptOFBBuf(key, iv, plaintext); break;
            case Mode::CTR: ciphertext = encryptCTRBuf(key, iv, plaintext); break;
            default: throw std::runtime_error("Unsupported mode");
            }
        }
        writeFile(outputPath, ciphertext);
    }

    inline void decryptFile(const std::string& inputPath,
        const std::string& outputPath,
        const std::string& keyPath,
        const std::string& ivPath,
        Mode mode) {
        Key key = readKeyFromFile(keyPath);
        auto ciphertext = readFile(inputPath);

        std::vector<uint8_t> plaintext;
        if (mode == Mode::ECB) {
            plaintext = decryptECBBuf(key, ciphertext);
        }
        else {
            Block iv = readIVFromFile(ivPath);
            switch (mode) {
            case Mode::CBC: plaintext = decryptCBCBuf(key, iv, ciphertext); break;
            case Mode::CFB: plaintext = decryptCFBBuf(key, iv, ciphertext); break;
            case Mode::OFB: plaintext = decryptOFBBuf(key, iv, ciphertext); break;
            case Mode::CTR: plaintext = decryptCTRBuf(key, iv, ciphertext); break;
            default: throw std::runtime_error("Unsupported mode");
            }
        }
        writeFile(outputPath, plaintext);
    }

} // namespace magma

#endif // MAGMA_H