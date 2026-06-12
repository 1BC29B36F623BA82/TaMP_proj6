#ifndef STEGANOGRAPHY_H
#define STEGANOGRAPHY_H

#include <vector>
#include <string>
#include <cstdint>

bool embed_message(std::vector<int16_t>& samples, const std::string& message, const std::string& password);
std::string extract_message(const std::vector<int16_t>& samples, const std::string& password);

#endif // STEGANOGRAPHY_H
