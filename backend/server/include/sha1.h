/**
 * @file sha1.h
 * @brief Интерфейс хэш-функции SHA-1 (FIPS PUB 180-1).
 *
 * SHA-1 (Secure Hash Algorithm 1) вычисляет 160-битный (20-байтный) хэш.
 *
 * Применение в проекте:
 *   - Хэширование паролей пользователей (Database.hpp)
 *   - Генерация seed для ГПСЧ при выборе позиций стеганографии (steganography.cpp)
 */
#ifndef SHA1_H
#define SHA1_H

#include <string>
#include <vector>
#include <cstdint>

/**
 * @brief Вычисляет SHA-1 хэш от массива байтов.
 *
 * @param data Указатель на входные данные
 * @param len Длина данных в байтах
 * @return 20-байтный хэш в виде std::vector<unsigned char>
 */
std::vector<unsigned char> sha1(const unsigned char* data, size_t len);

/**
 * @brief Удобная обёртка: вычисляет SHA-1 хэш от std::string.
 */
inline std::vector<unsigned char> sha1(const std::string& str) {
    return sha1(reinterpret_cast<const unsigned char*>(str.c_str()), str.size());
}

#endif // SHA1_H
