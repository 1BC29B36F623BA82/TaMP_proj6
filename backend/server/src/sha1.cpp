#include "sha1.h"
#include <cstring>
#include <algorithm>

/**
 * @brief Циклический сдвиг 32-битного числа влево.
 *
 * Используется в основном цикле SHA-1 для перемешивания битов.
 * Биты, «выпавшие» слева, возвращаются справа.
 *
 * @param value Исходное значение
 * @param shift Количество позиций сдвига
 * @return Результат циклического сдвига
 */
static inline uint32_t left_rotate(uint32_t value, int shift) {
    return (value << shift) | (value >> (32 - shift));
}

/**
 * @brief Вычисление SHA-1 хэша.
 *
 * Реализация стандарта FIPS PUB 180-1.
 *
 * Алгоритм:
 *   1. Подготовка (padding):
 *      - К сообщению добавляется бит '1' (байт 0x80)
 *      - Дополняется нулями до длины ≡ 56 (mod 64)
 *      - В конец записывается 64-битная длина исходного сообщения (big-endian)
 *
 *   2. Инициализация:
 *      - 5 хэш-переменных h0..h4 (стандартные константы)
 *
 *   3. Обработка блоков по 512 бит (64 байта):
 *      - 16 слов из блока расширяются до 80 слов (с циклическим сдвигом)
 *      - 80 раундов с нелинейными функциями f(b,c,d) и константами k:
 *          Раунды  0..19: f = (b & c) | (~b & d),       k = 0x5A827999
 *          Раунды 20..39: f = b ^ c ^ d,                k = 0x6ED9EBA1
 *          Раунды 40..59: f = (b&c) | (b&d) | (c&d),   k = 0x8F1BBCDC
 *          Раунды 60..79: f = b ^ c ^ d,                k = 0xCA62C1D6
 *
 *   4. Итоговый хэш — конкатенация h0..h4 (20 байт = 160 бит)
 *
 * @param data Указатель на входные данные
 * @param len Длина входных данных в байтах
 * @return 20-байтный хэш в виде вектора
 */
std::vector<unsigned char> sha1(const unsigned char* data, size_t len) {
    // Размер исходного сообщения в битах
    uint64_t bit_len = len * 8;

    // === Шаг 1: Подготовка сообщения (padding) ===
    std::vector<unsigned char> msg(data, data + len);
    msg.push_back(0x80);  // добавляем бит '1' (0b10000000)

    // Дополняем нулями, пока длина не станет ≡ 56 (mod 64)
    while ((msg.size() % 64) != 56) {
        msg.push_back(0x00);
    }

    // Добавляем 64-битную длину исходного сообщения (big-endian)
    for (int i = 7; i >= 0; --i) {
        msg.push_back(static_cast<unsigned char>((bit_len >> (8 * i)) & 0xFF));
    }

    // === Шаг 2: Инициализация хэш-переменных (стандартные константы SHA-1) ===
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xEFCDAB89;
    uint32_t h2 = 0x98BADCFE;
    uint32_t h3 = 0x10325476;
    uint32_t h4 = 0xC3D2E1F0;

    // === Шаг 3: Обработка блоков по 512 бит (64 байта) ===
    for (size_t i = 0; i < msg.size(); i += 64) {
        uint32_t w[80] = {0};

        // Копируем текущий блок в w[0..15] (big-endian → uint32_t)
        for (int t = 0; t < 16; ++t) {
            w[t] = (msg[i + 4*t] << 24) |
                   (msg[i + 4*t + 1] << 16) |
                   (msg[i + 4*t + 2] << 8)  |
                   (msg[i + 4*t + 3]);
        }

        // Расширяем 16 слов до 80 (с циклическим сдвигом на 1 бит)
        for (int t = 16; t < 80; ++t) {
            w[t] = left_rotate(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16], 1);
        }

        // Инициализируем рабочие переменные текущими значениями хэша
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;
        uint32_t e = h4;

        // 80 раундов хэширования
        for (int t = 0; t < 80; ++t) {
            uint32_t f, k;
            if (t < 20) {
                f = (b & c) | ((~b) & d);     // функция выбора (Ch)
                k = 0x5A827999;
            } else if (t < 40) {
                f = b ^ c ^ d;                 // функция чётности (Parity)
                k = 0x6ED9EBA1;
            } else if (t < 60) {
                f = (b & c) | (b & d) | (c & d);  // функция большинства (Maj)
                k = 0x8F1BBCDC;
            } else {
                f = b ^ c ^ d;                 // функция чётности (Parity)
                k = 0xCA62C1D6;
            }

            // temp = ROTL5(a) + f + e + k + w[t]
            uint32_t temp = left_rotate(a, 5) + f + e + k + w[t];
            e = d;
            d = c;
            c = left_rotate(b, 30);  // ROTL30(b)
            b = a;
            a = temp;
        }

        // Прибавляем результат текущего блока к общему хэшу
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
        h4 += e;
    }

    // === Шаг 4: Формируем итоговый хэш (20 байт = 160 бит, big-endian) ===
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
