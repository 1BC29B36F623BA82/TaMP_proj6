// main.cpp
#include <iostream>
#include <string>
#include <vector>
#include "wav_handler.h"
#include "steganography.h"

int main() {
    setlocale(LC_ALL, "Russian");
    std::string inputFilename, outputFilename, message, password;

    std::cout << "=== Стеганография в WAV (Метод Ньютона + SHA-1) ===" << std::endl;
    std::cout << "Введите имя исходного WAV-файла: ";
    std::getline(std::cin, inputFilename);
    std::cout << "Введите секретное сообщение: ";
    std::getline(std::cin, message);
    std::cout << "Введите пароль (ключ для SHA-1): ";
    std::getline(std::cin, password);
    std::cout << "Введите имя для выходного WAV-файла: ";
    std::getline(std::cin, outputFilename);

    // 1. Загружаем WAV-файл
    WavHeader header;
    std::vector<int16_t> samples = read_wav(inputFilename, header);
    if (samples.empty()) {
        std::cerr << "Ошибка: не удалось прочитать файл " << inputFilename << std::endl;
        return 1;
    }
    std::cout << "Файл успешно загружен. Найдено сэмплов: " << samples.size() << std::endl;

    // 2. Внедряем сообщение
    if (!embed_message(samples, message, password)) {
        std::cerr << "Ошибка: не удалось внедрить сообщение. Возможно, файл слишком мал." << std::endl;
        return 1;
    }
    std::cout << "Сообщение успешно внедрено." << std::endl;

    // 3. Сохраняем результат
    if (!write_wav(outputFilename, samples, header)) {
        std::cerr << "Ошибка: не удалось сохранить файл " << outputFilename << std::endl;
        return 1;
    }
    std::cout << "Результат сохранен в файл: " << outputFilename << std::endl;

    return 0;
}
