#ifndef STEGANOGRAPHY_H
#define STEGANOGRAPHY_H

#include <vector>
#include <string>
#include <cstdint>

// Функция внедрения сообщения в аудио-сэмплы
// Возвращает true в случае успеха, false – если не хватило места или ошибка
bool embed_message(std::vector<int16_t>& samples, const std::string& message, const std::string& password);

// Функция извлечения сообщения из аудио-сэмплов
// Параметр password – секретная фраза/ключ, которая использовалась при внедрении
// Возвращает извлечённую строку (или пустую строку при ошибке)
std::string extract_message(const std::vector<int16_t>& samples, const std::string& password);

#endif // STEGANOGRAPHY_H
