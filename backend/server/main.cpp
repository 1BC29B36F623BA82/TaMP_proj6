#include <iostream>
#include <string>
#include "wav_handler.h"
#include "steganography.h"

int main() {
    setlocale(LC_ALL, "Russian");
    int choice;
    std::string filename, message, output_filename;

    std::cout << "=== TaMP_proj6: Стеганография в WAV ===\n";
    std::cout << "1. Внедрить сообщение\n";
    std::cout << "2. Извлечь сообщение\n";
    std::cout << "Выберите действие: ";
    std::cin >> choice;
    std::cin.ignore();

    if (choice == 1) {
        std::cout << "Введите имя WAV-файла: ";
        std::getline(std::cin, filename);
        std::cout << "Введите секретное сообщение: ";
        std::getline(std::cin, message);
        std::cout << "Введите имя для выходного файла: ";
        std::getline(std::cin, output_filename);

        // --- Шаг 1: Загрузка аудио ---
        WavHeader header;
        std::vector<int16_t> samples = read_wav(filename, header);
        if (samples.empty()) {
            std::cerr << "Ошибка: не удалось прочитать файл " << filename << std::endl;
            return 1;
        }

        // --- Шаг 2: Шифрование сообщения (RSA) ---
        // Здесь будет вызов функции для шифрования сообщения.
        // std::string encrypted_message = rsa_encrypt(message);
        // Для теста пока просто скопируем оригинал.
        std::string data_to_hide = message; 

        // --- Шаг 3: Внедрение сообщения (Steganography) ---
        if (embed_message(samples, data_to_hide, header)) {
            if (write_wav(output_filename, samples, header)) {
                std::cout << "Сообщение успешно внедрено в " << output_filename << std::endl;
            } else {
                std::cerr << "Ошибка при записи файла " << output_filename << std::endl;
                return 1;
            }
        } else {
            std::cerr << "Ошибка: не удалось внедрить сообщение (возможно, файл слишком мал)." << std::endl;
            return 1;
        }
    } 
    else if (choice == 2) {
        // ... (логика извлечения сообщения)
    }
    return 0;
}
