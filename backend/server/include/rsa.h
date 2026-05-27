#ifndef RSA_H
#define RSA_H

#include <vector>
#include <string>
#include <cstdint>

/**
 * @brief Структура для хранения пары ключей RSA.
 *
 * n = p * q  — модуль (произведение двух простых чисел)
 * e          — открытая экспонента (публичный ключ: {e, n})
 * d          — закрытая экспонента (приватный ключ: {d, n})
 */
struct RSAKeyPair {
    uint64_t n;  // модуль RSA
    uint64_t e;  // открытая экспонента
    uint64_t d;  // закрытая экспонента
};

/**
 * @brief Генерация пары ключей RSA из двух простых чисел.
 *
 * Алгоритм:
 *   1. Вычисляется n = p * q
 *   2. Вычисляется функция Эйлера: φ(n) = (p-1)(q-1)
 *   3. Выбирается e, взаимно простое с φ(n) (начиная с 17)
 *   4. Вычисляется d = e^{-1} mod φ(n) (расширенный алгоритм Евклида)
 *
 * @param p Первое простое число
 * @param q Второе простое число
 * @return RSAKeyPair Сгенерированная пара ключей
 */
RSAKeyPair generate_keys(uint64_t p, uint64_t q);

/**
 * @brief Шифрование открытого текста алгоритмом RSA.
 *
 * Каждый байт сообщения m шифруется отдельно по формуле:
 *   c = m^e mod n
 *
 * @param plaintext Исходный текст (строка)
 * @param e Открытая экспонента
 * @param n Модуль RSA
 * @return Вектор зашифрованных блоков (по одному на каждый байт)
 */
std::vector<uint64_t> rsa_encrypt(const std::string& plaintext, uint64_t e, uint64_t n);

/**
 * @brief Расшифрование шифротекста алгоритмом RSA.
 *
 * Каждый блок c расшифровывается по формуле:
 *   m = c^d mod n
 *
 * @param ciphertext Вектор зашифрованных блоков
 * @param d Закрытая экспонента
 * @param n Модуль RSA
 * @return Расшифрованная строка
 */
std::string rsa_decrypt(const std::vector<uint64_t>& ciphertext, uint64_t d, uint64_t n);

/**
 * @brief Сериализация шифротекста в бинарную строку для встраивания в WAV.
 *
 * Формат: [4 байта — количество блоков (big-endian)]
 *         [4 байта на каждый блок (big-endian)]
 *
 * @param ciphertext Вектор зашифрованных блоков
 * @return Бинарная строка
 */
std::string serialize_ciphertext(const std::vector<uint64_t>& ciphertext);

/**
 * @brief Десериализация бинарной строки обратно в вектор блоков шифротекста.
 *
 * @param data Бинарная строка (результат serialize_ciphertext)
 * @return Вектор зашифрованных блоков (пустой при ошибке формата)
 */
std::vector<uint64_t> deserialize_ciphertext(const std::string& data);

#endif // RSA_H
