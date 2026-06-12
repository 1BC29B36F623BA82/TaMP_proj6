#include "steganography.h"
#include "sha1.h"
#include <random>
#include <cmath>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <cstdlib>

static int16_t apply_newton_lsb(int16_t original, int target_bit) {
    if ((original & 1) == target_bit) {
        return original;
    }

    const double pi = 3.14159265358979323846;
    double x = static_cast<double>(original) + 0.5;

    for (int iter = 0; iter < 10; ++iter) {
        double arg = pi * (x - target_bit) / 2.0;
        double fx = std::sin(arg);
        double fpx = (pi / 2.0) * std::cos(arg);

        if (std::abs(fpx) < 1e-12) break;

        double x_new = x - fx / fpx;
        if (std::abs(x_new - x) < 1e-10) break;
        x = x_new;
    }

    int16_t candidate = static_cast<int16_t>(std::round(x));

    if ((candidate & 1) != target_bit) {
        int16_t down = candidate - 1;
        int16_t up   = candidate + 1;
        if (std::abs(down - original) <= std::abs(up - original))
            candidate = down;
        else
            candidate = up;
    }

    if (candidate < -32768) candidate = -32768;
    if (candidate > 32767)  candidate = 32767;

    return candidate;
}

bool embed_message(std::vector<int16_t>& samples, const std::string& message, const std::string& password) {
    uint32_t msg_len = static_cast<uint32_t>(message.size());
    std::string data;
    data.push_back(static_cast<char>((msg_len >> 24) & 0xFF));
    data.push_back(static_cast<char>((msg_len >> 16) & 0xFF));
    data.push_back(static_cast<char>((msg_len >> 8) & 0xFF));
    data.push_back(static_cast<char>(msg_len & 0xFF));
    data += message;

    if (samples.size() < data.size() * 8) {
        return false;
    }

    std::vector<unsigned char> hash = sha1(password);
    std::seed_seq seed(hash.begin(), hash.end());
    std::mt19937 gen(seed);
    std::uniform_int_distribution<size_t> dist(0, samples.size() - 1);
    std::vector<bool> used(samples.size(), false);

    for (size_t byte_idx = 0; byte_idx < data.size(); ++byte_idx) {
        unsigned char c = static_cast<unsigned char>(data[byte_idx]);
        for (int i = 7; i >= 0; --i) {
            int target_bit = (c >> i) & 1;

            size_t pos;
            do {
                pos = dist(gen);
            } while (used[pos]);
            used[pos] = true;

            samples[pos] = apply_newton_lsb(samples[pos], target_bit);
        }
    }
    return true;
}

std::string extract_message(const std::vector<int16_t>& samples, const std::string& password) {
    std::vector<unsigned char> hash = sha1(password);
    std::seed_seq seed(hash.begin(), hash.end());
    std::mt19937 gen(seed);
    std::uniform_int_distribution<size_t> dist(0, samples.size() - 1);
    std::vector<bool> used(samples.size(), false);

    std::string length_bytes;
    for (int byte_idx = 0; byte_idx < 4; ++byte_idx) {
        unsigned char current_byte = 0;
        for (int bit = 7; bit >= 0; --bit) {
            size_t pos;
            do {
                pos = dist(gen);
            } while (used[pos]);
            used[pos] = true;

            int bit_val = samples[pos] & 1;
            current_byte |= (bit_val << bit);
        }
        length_bytes.push_back(static_cast<char>(current_byte));
    }

    uint32_t msg_len = (static_cast<unsigned char>(length_bytes[0]) << 24) |
                       (static_cast<unsigned char>(length_bytes[1]) << 16) |
                       (static_cast<unsigned char>(length_bytes[2]) << 8) |
                       static_cast<unsigned char>(length_bytes[3]);

    if (msg_len == 0 || msg_len > samples.size() / 8) return "";

    std::string message;
    for (uint32_t byte_idx = 0; byte_idx < msg_len; ++byte_idx) {
        unsigned char current_byte = 0;
        for (int bit = 7; bit >= 0; --bit) {
            size_t pos;
            do {
                pos = dist(gen);
            } while (used[pos]);
            used[pos] = true;

            int bit_val = samples[pos] & 1;
            current_byte |= (bit_val << bit);
        }
        message.push_back(static_cast<char>(current_byte));
    }
    return message;
}
