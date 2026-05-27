#include "rsa.h"
#include <algorithm>

/**
 * @brief Наибольший общий делитель (алгоритм Евклида).
 *
 * Используется для проверки взаимной простоты e и φ(n):
 * если gcd(e, φ(n)) == 1, то e подходит в качестве открытой экспоненты.
 */
static uint64_t gcd(uint64_t a, uint64_t b) {
    while (b) {
        a %= b;
        std::swap(a, b);
    }
    return a;
}

/**
 * @brief Расширенный алгоритм Евклида.
 *
 * Находит x и y такие, что: a*x + b*y = gcd(a, b).
 * Используется для вычисления модульного обратного элемента d = e^{-1} mod φ(n).
 *
 * @param a Первое число
 * @param b Второе число
 * @param x Коэффициент при a (выходной параметр)
 * @param y Коэффициент при b (выходной параметр)
 * @return gcd(a, b)
 */
static int64_t extended_gcd(int64_t a, int64_t b, int64_t& x, int64_t& y) {
    if (a == 0) {
        x = 0;
        y = 1;
        return b;
    }
    int64_t x1, y1;
    int64_t g = extended_gcd(b % a, a, x1, y1);
    // Пересчёт коэффициентов по рекуррентной формуле
    x = y1 - (b / a) * x1;
    y = x1;
    return g;
}

/**
 * @brief Модульный обратный элемент: находит d такое, что e*d ≡ 1 (mod phi).
 *
 * Если gcd(e, phi) != 1, обратный элемент не существует — возвращает 0.
 */
static uint64_t mod_inverse(uint64_t e, uint64_t phi) {
    int64_t x, y;
    int64_t g = extended_gcd(static_cast<int64_t>(e), static_cast<int64_t>(phi), x, y);
    if (g != 1) return 0;  // обратный элемент не существует
    // Приводим x к положительному значению в диапазоне [0, phi)
    return static_cast<uint64_t>(((x % static_cast<int64_t>(phi)) + static_cast<int64_t>(phi)) % static_cast<int64_t>(phi));
}

/**
 * @brief Быстрое модульное возведение в степень: вычисляет (base^exp) mod mod.
 *
 * Алгоритм «возведение в степень по квадрату» (binary exponentiation):
 *   - Если текущий бит exp равен 1: result = result * base mod m
 *   - На каждом шаге: base = base * base mod m
 *   - Сложность: O(log exp)
 */
static uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) {                        // если текущий бит показателя = 1
            result = (result * base) % mod;   // домножаем результат
        }
        exp >>= 1;                            // сдвигаем показатель вправо
        base = (base * base) % mod;           // возводим основание в квадрат
    }
    return result;
}

/**
 * @brief Генерация ключей RSA.
 *
 * Этапы:
 *   1. n = p * q                           — модуль RSA
 *   2. φ(n) = (p-1)(q-1)                   — функция Эйлера
 *   3. Выбор e: gcd(e, φ(n)) == 1          — открытая экспонента
 *   4. d = e^{-1} mod φ(n)                 — закрытая экспонента
 */
RSAKeyPair generate_keys(uint64_t p, uint64_t q) {
    RSAKeyPair keys;
    keys.n = p * q;                       // модуль
    uint64_t phi = (p - 1) * (q - 1);    // функция Эйлера

    // Ищем e, взаимно простое с φ(n), начиная с 17
    keys.e = 17;
    while (gcd(keys.e, phi) != 1) {
        keys.e += 2;
    }

    // Вычисляем закрытую экспоненту d через расширенный алгоритм Евклида
    keys.d = mod_inverse(keys.e, phi);
    return keys;
}

/**
 * @brief Шифрование: каждый байт m открытого текста → c = m^e mod n.
 */
std::vector<uint64_t> rsa_encrypt(const std::string& plaintext, uint64_t e, uint64_t n) {
    std::vector<uint64_t> ciphertext;
    for (unsigned char c : plaintext) {
        // Шифруем каждый байт как отдельное число m (0..255)
        ciphertext.push_back(mod_pow(c, e, n));
    }
    return ciphertext;
}

/**
 * @brief Расшифрование: каждый блок c шифротекста → m = c^d mod n.
 */
std::string rsa_decrypt(const std::vector<uint64_t>& ciphertext, uint64_t d, uint64_t n) {
    std::string plaintext;
    for (uint64_t c : ciphertext) {
        // Расшифровываем блок обратно в байт
        plaintext.push_back(static_cast<char>(mod_pow(c, d, n)));
    }
    return plaintext;
}

/**
 * @brief Сериализация шифротекста в бинарную строку.
 *
 * Формат (big-endian):
 *   Байты 0..3:  количество блоков (uint32_t)
 *   Байты 4..7:  первый зашифрованный блок (uint32_t)
 *   Байты 8..11: второй зашифрованный блок
 *   ...и т.д.
 */
std::string serialize_ciphertext(const std::vector<uint64_t>& ciphertext) {
    std::string data;
    uint32_t count = static_cast<uint32_t>(ciphertext.size());

    // Записываем количество блоков (4 байта, big-endian)
    data.push_back(static_cast<char>((count >> 24) & 0xFF));
    data.push_back(static_cast<char>((count >> 16) & 0xFF));
    data.push_back(static_cast<char>((count >> 8) & 0xFF));
    data.push_back(static_cast<char>(count & 0xFF));

    // Записываем каждый блок (4 байта, big-endian)
    for (uint64_t val : ciphertext) {
        uint32_t v = static_cast<uint32_t>(val);
        data.push_back(static_cast<char>((v >> 24) & 0xFF));
        data.push_back(static_cast<char>((v >> 16) & 0xFF));
        data.push_back(static_cast<char>((v >> 8) & 0xFF));
        data.push_back(static_cast<char>(v & 0xFF));
    }
    return data;
}

/**
 * @brief Десериализация бинарной строки обратно в вектор блоков шифротекста.
 */
std::vector<uint64_t> deserialize_ciphertext(const std::string& data) {
    if (data.size() < 4) return {};

    // Считываем количество блоков (4 байта, big-endian)
    uint32_t count = (static_cast<unsigned char>(data[0]) << 24) |
                     (static_cast<unsigned char>(data[1]) << 16) |
                     (static_cast<unsigned char>(data[2]) << 8) |
                     static_cast<unsigned char>(data[3]);

    if (data.size() < 4 + count * 4) return {};

    // Считываем каждый блок (4 байта, big-endian)
    std::vector<uint64_t> ciphertext;
    for (uint32_t i = 0; i < count; i++) {
        size_t offset = 4 + i * 4;
        uint32_t val = (static_cast<unsigned char>(data[offset]) << 24) |
                       (static_cast<unsigned char>(data[offset + 1]) << 16) |
                       (static_cast<unsigned char>(data[offset + 2]) << 8) |
                       static_cast<unsigned char>(data[offset + 3]);
        ciphertext.push_back(val);
    }
    return ciphertext;
}
