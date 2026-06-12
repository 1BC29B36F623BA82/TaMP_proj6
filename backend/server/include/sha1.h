#ifndef SHA1_H
#define SHA1_H

#include <string>
#include <vector>
#include <cstdint>

std::vector<unsigned char> sha1(const unsigned char* data, size_t len);

inline std::vector<unsigned char> sha1(const std::string& str) {
    return sha1(reinterpret_cast<const unsigned char*>(str.c_str()), str.size());
}

#endif // SHA1_H
