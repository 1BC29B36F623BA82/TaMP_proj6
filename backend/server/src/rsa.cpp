#include "rsa.h"
#include <algorithm>

static uint64_t gcd(uint64_t a, uint64_t b) {
    while (b) {
        a %= b;
        std::swap(a, b);
    }
    return a;
}

static int64_t extended_gcd(int64_t a, int64_t b, int64_t& x, int64_t& y) {
    if (a == 0) {
        x = 0;
        y = 1;
        return b;
    }
    int64_t x1, y1;
    int64_t g = extended_gcd(b % a, a, x1, y1);
    x = y1 - (b / a) * x1;
    y = x1;
    return g;
}

static uint64_t mod_inverse(uint64_t e, uint64_t phi) {
    int64_t x, y;
    int64_t g = extended_gcd(static_cast<int64_t>(e), static_cast<int64_t>(phi), x, y);
    if (g != 1) return 0;
    return static_cast<uint64_t>(((x % static_cast<int64_t>(phi)) + static_cast<int64_t>(phi)) % static_cast<int64_t>(phi));
}

static uint64_t mod_pow(uint64_t base, uint64_t exp, uint64_t mod) {
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) {
            result = (result * base) % mod;
        }
        exp >>= 1;
        base = (base * base) % mod;
    }
    return result;
}

RSAKeyPair generate_keys(uint64_t p, uint64_t q) {
    RSAKeyPair keys;
    keys.n = p * q;
    uint64_t phi = (p - 1) * (q - 1);

    keys.e = 17;
    while (gcd(keys.e, phi) != 1) {
        keys.e += 2;
    }

    keys.d = mod_inverse(keys.e, phi);
    return keys;
}

std::vector<uint64_t> rsa_encrypt(const std::string& plaintext, uint64_t e, uint64_t n) {
    std::vector<uint64_t> ciphertext;
    for (unsigned char c : plaintext) {
        ciphertext.push_back(mod_pow(c, e, n));
    }
    return ciphertext;
}

std::string rsa_decrypt(const std::vector<uint64_t>& ciphertext, uint64_t d, uint64_t n) {
    std::string plaintext;
    for (uint64_t c : ciphertext) {
        plaintext.push_back(static_cast<char>(mod_pow(c, d, n)));
    }
    return plaintext;
}

std::string serialize_ciphertext(const std::vector<uint64_t>& ciphertext) {
    std::string data;
    uint32_t count = static_cast<uint32_t>(ciphertext.size());

    data.push_back(static_cast<char>((count >> 24) & 0xFF));
    data.push_back(static_cast<char>((count >> 16) & 0xFF));
    data.push_back(static_cast<char>((count >> 8) & 0xFF));
    data.push_back(static_cast<char>(count & 0xFF));

    for (uint64_t val : ciphertext) {
        uint32_t v = static_cast<uint32_t>(val);
        data.push_back(static_cast<char>((v >> 24) & 0xFF));
        data.push_back(static_cast<char>((v >> 16) & 0xFF));
        data.push_back(static_cast<char>((v >> 8) & 0xFF));
        data.push_back(static_cast<char>(v & 0xFF));
    }
    return data;
}

std::vector<uint64_t> deserialize_ciphertext(const std::string& data) {
    if (data.size() < 4) return {};

    uint32_t count = (static_cast<unsigned char>(data[0]) << 24) |
                     (static_cast<unsigned char>(data[1]) << 16) |
                     (static_cast<unsigned char>(data[2]) << 8) |
                     static_cast<unsigned char>(data[3]);

    if (data.size() < 4 + count * 4) return {};

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
