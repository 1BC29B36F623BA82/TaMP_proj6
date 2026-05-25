#include "sha1.h"
#include <cstring>
#include <algorithm>

// Вспомогательные функции (ротация влево)
static inline uint32_t left_rotate(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

std::vector<unsigned char> sha1(const unsigned char* data, size_t len) {
    // Размер исходного сообщения в битах
    uint64_t bit_len = len * 8;
    
    // 1. Подготовка: добавляем бит '1' и нули, затем 64-битную длину
    // Буфер для обработки: копируем исходные данные
    std::vector<unsigned char> msg(data, data + len);
    msg.push_back(0x80); // добавляем единичный бит (0b10000000)
    
    // Дополняем нулями, пока длина в байтах не станет сравнима с 56 по модулю 64
    while ((msg.size() % 64) != 56) {
        msg.push_back(0x00);
    }
    
    // Добавляем 64-битную длину исходного сообщения (big-endian)
    for (int i = 7; i >= 0; --i) {
        msg.push_back(static_cast<unsigned char>((bit_len >> (8 * i)) & 0xFF));
    }
    
    // 2. Инициализация хэш-переменных (константы SHA-1)
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;
    
    // 3. Обработка блоков по 512 бит (64 байта)
    for (size_t i = 0; i < msg.size(); i += 64) {
        uint32_t w[80] = {0};
        
        // Копируем текущий блок в w[0..15] (big-endian)
        for (int t = 0; t < 16; ++t) {
            w[t] = (msg[i + 4*t] << 24) |
                   (msg[i + 4*t + 1] << 16) |
                   (msg[i + 4*t + 2] << 8)  |
                   (msg[i + 4*t + 3]);
        }
        
        // Расширяем до 80 слов
        for (int t = 16; t < 80; ++t) {
            w[t] = left_rotate(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);
        }
        
        // Инициализируем временные переменные
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;
        
        // Основной цикл
        for (int t = 0; t < 80; ++t) {
            uint32_t f, k;
            if (t < 20) {
                f = (b & c) | ((~b) & d);
                k = 0x5A827999;
            } else if (t < 40) {
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
            } else if (t < 60) {
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
            }
            
            uint32_t temp = left_rotate(a, 5) + f + e + k + w[t];
            e = d;
            d = c;
            c = left_rotate(b, 30);
            b = a;
            a = temp;
        }
        
        // Добавляем результат текущего блока к общему хэшу
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }
    
    // 4. Формируем итоговый хэш (20 байт, big-endian)
    std::vector<unsigned char> hash(20);
    for (int i = 0; i < 4; ++i) {
        hash[i]     = static_cast<unsigned char>((h0 >> (24 - 8*i)) & 0xFF);
        hash[4+i]   = static_cast<unsigned char>((h1 >> (24 - 8*i)) & 0xFF);
        hash[8+i]   = static_cast<unsigned char>((h2 >> (24 - 8*i)) & 0xFF);
        hash[12+i]  = static_cast<unsigned char>((h3 >> (24 - 8*i)) & 0xFF);
        hash[16+i]  = static_cast<unsigned char>((h4 >> (24 - 8*i)) & 0xFF);
    }
    
    return hash;
}
