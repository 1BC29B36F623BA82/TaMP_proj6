/**
 * @file steganography.h
 * @brief Интерфейс модуля LSB-стеганографии в WAV-файлах.
 *
 * Метод внедрения:
 *   - Биты сообщения записываются в младшие биты (LSB) аудиосэмплов
 *   - Позиции сэмплов выбираются псевдослучайно (ГПСЧ mt19937, seed = SHA-1(пароль))
 *   - Значение LSB устанавливается методом Ньютона (нахождение ближайшего целого с нужным битом)
 *   - Формат данных: [4 байта длины] [данные] (поддерживает бинарные данные, включая RSA-шифротекст)
 */
#ifndef STEGANOGRAPHY_H
#define STEGANOGRAPHY_H

#include <vector>
#include <string>
#include <cstdint>

/**
 * @brief Внедрение сообщения в аудиосэмплы.
 *
 * @param samples Вектор 16-битных PCM-сэмплов (модифицируется)
 * @param message Данные для встраивания (строка, может содержать бинарные данные)
 * @param password Пароль — SHA-1 хэш используется как seed для генерации позиций
 * @return true — успех, false — не хватает сэмплов для встраивания
 */
bool embed_message(std::vector<int16_t>& samples, const std::string& message, const std::string& password);

/**
 * @brief Извлечение сообщения из аудиосэмплов.
 *
 * @param samples Вектор 16-битных PCM-сэмплов (не модифицируется)
 * @param password Тот же пароль, что при внедрении (для воспроизведения порядка позиций)
 * @return Извлечённые данные (пустая строка при ошибке или неверном пароле)
 */
std::string extract_message(const std::vector<int16_t>& samples, const std::string& password);

#endif // STEGANOGRAPHY_H
