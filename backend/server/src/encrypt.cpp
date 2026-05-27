#include <iostream>
#include <string>
#include <vector>
#include <clocale>
#include "wav_handler.h"
#include "steganography.h"

int main() {

    std::cout << "=== Steganography in WAV (Newton's method + SHA-1) ===" << std::endl;
    std::cout << "Select mode:\n";
    std::cout << "1 - Embed message into WAV\n";
    std::cout << "2 - Extract message from WAV\n";
    std::cout << "Your choice: ";
    
    int choice;
    std::cin >> choice;
    std::cin.ignore(); // очистка буфера после ввода числа

    if (choice == 1) {
        // --- РЕЖИМ ВНЕДРЕНИЯ ---
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

        // 2. Внедряем сообщение
        if (!embed_message(samples, message, password)) {
            std::cerr << "Error: Failed to embed message. The audio file may be too short." << std::endl;
            return 1;
        }
        std::cout << "Message successfully embedded." << std::endl;

        // 3. Сохраняем результат
        if (!write_wav(outputFilename, samples, header)) {
            std::cerr << "Error: Failed to save file " << outputFilename << std::endl;
            return 1;
        }
        std::cout << "Result saved to: " << outputFilename << std::endl;
    }
    else if (choice == 2) {
        // --- РЕЖИМ ИЗВЛЕЧЕНИЯ ---
        std::string inputFilename, password;

        std::cout << "Enter the name of the WAV file with hidden message: ";
        std::getline(std::cin, inputFilename);
        std::cout << "Enter password (key for SHA-1): ";
        std::getline(std::cin, password);

        // Загружаем WAV-файл
        WavHeader header;
        std::vector<int16_t> samples = read_wav(inputFilename, header);
        if (samples.empty()) {
            std::cerr << "Error: Failed to read file " << inputFilename << std::endl;
            return 1;
        }
        std::cout << "File loaded. Samples count: " << samples.size() << std::endl;

        // Извлекаем сообщение
        std::string extracted = extract_message(samples, password);
        if (extracted.empty()) {
            std::cerr << "Error: No hidden message found or wrong password." << std::endl;
            return 1;
        }
        std::cout << "\n=== Extracted message ===\n" << extracted << "\n=========================\n";
        std::cout << "\nPress Enter to exit...";
        std::cin.get();
    }
    else {
        std::cerr << "Invalid choice. Please run the program again." << std::endl;
        return 1;
    }

    return 0;
}