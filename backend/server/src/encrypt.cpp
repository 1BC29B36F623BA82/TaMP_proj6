/**
 * @file encrypt.cpp
 * @brief Автономная консольная утилита для стеганографии в WAV-файлах.
 *
 * Позволяет встраивать и извлекать секретные сообщения без запуска сервера.
 * Использует ту же цепочку: RSA-шифрование → сериализация → стеганография (метод Ньютона + SHA-1).
 *
 * Режимы работы:
 *   1 — Встраивание сообщения в WAV-файл
 *   2 — Извлечение сообщения из WAV-файла
 */

#include <iostream>
#include <string>
#include <vector>
#include "wav_handler.h"
#include "steganography.h"
#include "rsa.h"

// RSA-ключи (те же, что на сервере: p=61, q=53)
static RSAKeyPair keys = generate_keys(61, 53);

int main() {
    std::cout << "=== Steganography in WAV (RSA + Newton + SHA-1) ===" << std::endl;
    std::cout << "RSA keys: n=" << keys.n << " e=" << keys.e << " d=" << keys.d << std::endl;
    std::cout << "\nSelect mode:\n";
    std::cout << "1 - Embed message into WAV\n";
    std::cout << "2 - Extract message from WAV\n";
    std::cout << "Your choice: ";

    int choice;
    std::cin >> choice;
    std::cin.ignore();  // очистка буфера после ввода числа

    if (choice == 1) {
        // === РЕЖИМ ВСТРАИВАНИЯ ===
        std::string inputFilename, outputFilename, message, password;

        std::cout << "Enter the name of the source WAV file: ";
        std::getline(std::cin, inputFilename);
        std::cout << "Enter a secret message: ";
        std::getline(std::cin, message);
        std::cout << "Enter password (key for SHA-1): ";
        std::getline(std::cin, password);
        std::cout << "Enter a name for the output WAV file: ";
        std::getline(std::cin, outputFilename);

        // 1. Загружаем WAV-файл
        WavHeader header;
        std::vector<int16_t> samples = read_wav(inputFilename, header);
        if (samples.empty()) {
            std::cerr << "Error: Failed to read file " << inputFilename << std::endl;
            return 1;
        }
        std::cout << "File loaded. Samples count: " << samples.size() << std::endl;

        // 2. RSA-шифрование: каждый байт m → c = m^e mod n
        std::vector<uint64_t> cipher = rsa_encrypt(message, keys.e, keys.n);
        std::string cipher_data = serialize_ciphertext(cipher);
        std::cout << "RSA encryption done. Ciphertext size: " << cipher_data.size() << " bytes" << std::endl;

        // 3. Встраиваем шифротекст в сэмплы (метод Ньютона для LSB + SHA-1 для позиций)
        if (!embed_message(samples, cipher_data, password)) {
            std::cerr << "Error: Failed to embed message. The audio file may be too short." << std::endl;
            return 1;
        }
        std::cout << "Message embedded using Newton's method." << std::endl;

        // 4. Сохраняем результат
        if (!write_wav(outputFilename, samples, header)) {
            std::cerr << "Error: Failed to save file " << outputFilename << std::endl;
            return 1;
        }
        std::cout << "Result saved to: " << outputFilename << std::endl;
    }
    else if (choice == 2) {
        // === РЕЖИМ ИЗВЛЕЧЕНИЯ ===
        std::string inputFilename, password;

        std::cout << "Enter the name of the WAV file with hidden message: ";
        std::getline(std::cin, inputFilename);
        std::cout << "Enter password (key for SHA-1): ";
        std::getline(std::cin, password);

        // 1. Загружаем WAV-файл
        WavHeader header;
        std::vector<int16_t> samples = read_wav(inputFilename, header);
        if (samples.empty()) {
            std::cerr << "Error: Failed to read file " << inputFilename << std::endl;
            return 1;
        }
        std::cout << "File loaded. Samples count: " << samples.size() << std::endl;

        // 2. Извлекаем бинарные данные из LSB сэмплов
        std::string cipher_data = extract_message(samples, password);
        if (cipher_data.empty()) {
            std::cerr << "Error: No hidden message found or wrong password." << std::endl;
            return 1;
        }

        // 3. Десериализуем шифротекст
        std::vector<uint64_t> cipher = deserialize_ciphertext(cipher_data);
        if (cipher.empty()) {
            std::cerr << "Error: Failed to deserialize ciphertext." << std::endl;
            return 1;
        }

        // 4. RSA-расшифрование: каждый блок c → m = c^d mod n
        std::string plaintext = rsa_decrypt(cipher, keys.d, keys.n);

        std::cout << "\n=== Extracted message ===\n" << plaintext << "\n=========================\n";
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
    }
    else {
        std::cerr << "Invalid choice." << std::endl;
        return 1;
    }

    return 0;
}
