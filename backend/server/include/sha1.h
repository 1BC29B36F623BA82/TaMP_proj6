#ifndef SHA1_H
#define SHA1_H

#include <string>
#include <vector>
#include <cstdint>

// Вычисляет SHA-1 хэш от входных данных (массив байт)
// Возвращает 20-байтный хэш в виде std::vector<unsigned char>
std::vector<unsigned char> sha1(const unsigned char* data, size_t len);

// Удобная обёртка для std::string
inline std::vector<unsigned char> sha1(const std::string& str) {
    return sha1(reinterpret_cast<const unsigned char*>(str.c_str()), str.size());
}

#endif // SHA1_H
