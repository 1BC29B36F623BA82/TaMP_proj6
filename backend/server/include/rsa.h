#ifndef RSA_H
#define RSA_H

#include <vector>
#include <string>
#include <cstdint>

struct RSAKeyPair {
    uint64_t n;
    uint64_t e;
    uint64_t d;
};

RSAKeyPair generate_keys(uint64_t p, uint64_t q);
std::vector<uint64_t> rsa_encrypt(const std::string& plaintext, uint64_t e, uint64_t n);
std::string rsa_decrypt(const std::vector<uint64_t>& ciphertext, uint64_t d, uint64_t n);
std::string serialize_ciphertext(const std::vector<uint64_t>& ciphertext);
std::vector<uint64_t> deserialize_ciphertext(const std::string& data);

#endif // RSA_H
