#include <iostream>
#include <string>
#include <vector>
#include <clocale>
#include "wav_handler.h"
#include "steganography.h"

int main() {
    std::string inputFilename, outputFilename, message, password;

    std::cout << "=== Steganography in WAV (Newton's method + SHA-1) ===" << std::endl;
    std::cout << "Enter the name of the source WAV-file: ";
    std::getline(std::cin, inputFilename);
    std::cout << "Enter a secret message: ";
    std::getline(std::cin, message);
    std::cout << "Enter password (key for SHA-1): ";
    std::getline(std::cin, password);
    std::cout << "Enter a name for the output WAV-file.: ";
    std::getline(std::cin, outputFilename);

    // 1. Загружаем WAV-файл
    WavHeader header;
    std::vector<int16_t> samples = read_wav(inputFilename, header);
    if (samples.empty()) {
        std::cerr << "Error: Failed to read file " << inputFilename << std::endl;
        return 1;
    }
    std::cout << "File uploaded successfully. Samples found.: " << samples.size() << std::endl;

    // 2. Внедряем сообщение
    if (!embed_message(samples, message, password)) {
        std::cerr << "Error: Failed to embed message. File may be too small." << std::endl;
        return 1;
    }
    std::cout << "The message has been successfully implemented." << std::endl;

    // 3. Сохраняем результат
    if (!write_wav(outputFilename, samples, header)) {
        std::cerr << "Error: Failed to save file " << outputFilename << std::endl;
        return 1;
    }
    std::cout << "The result is saved to a file: " << outputFilename << std::endl;

    return 0;
}
