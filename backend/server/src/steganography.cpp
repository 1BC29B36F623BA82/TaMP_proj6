#include "steganography.h"
#include "sha1.h"
#include <random>
#include <cmath>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <cstdlib>

/**
 * @brief Метод Ньютона для нахождения ближайшего целого с заданным LSB.
 *
 * Задача: найти ближайшее к original целое число x, у которого x mod 2 == target_bit.
 *
 * Математическая формулировка:
 *   Функция: f(x) = sin( π·(x − target_bit) / 2 )
 *
 *   Корни f(x) = 0 — это все целые числа с чётностью, совпадающей с target_bit:
 *     x = target_bit, target_bit ± 2, target_bit ± 4, ...
 *     Например, при target_bit=1: x = ..., -3, -1, 1, 3, 5, ... (нечётные)
 *
 *   Производная: f'(x) = (π/2) · cos( π·(x − target_bit) / 2 )
 *
 *   Итерация Ньютона:
 *     x_{n+1} = x_n − f(x_n) / f'(x_n)
 *
 *   Начальное приближение: x₀ = original + 0.5
 *   (смещение на 0.5 необходимо, чтобы избежать нулевой производной
 *    в точках, не являющихся корнями — там sin = ±1, cos = 0)
 *
 *   Метод сходится за 3–4 итерации к ближайшему целому с нужным LSB.
 *
 * @param original Исходное значение сэмпла
 * @param target_bit Требуемый младший бит (0 или 1)
 * @return Ближайшее целое с заданным LSB
 */
static int16_t apply_newton_lsb(int16_t original, int target_bit) {
    // Если младший бит уже совпадает — модификация не нужна
    if ((original & 1) == target_bit) {
        return original;
    }

    const double pi = 3.14159265358979323846;
    // Начальное приближение со смещением 0.5
    double x = static_cast<double>(original) + 0.5;

    // Итерации Ньютона: x_{n+1} = x_n - f(x_n) / f'(x_n)
    for (int iter = 0; iter < 10; ++iter) {
        double arg = pi * (x - target_bit) / 2.0;
        double fx = std::sin(arg);                    // f(x) = sin(arg)
        double fpx = (pi / 2.0) * std::cos(arg);     // f'(x) = (π/2)·cos(arg)

        if (std::abs(fpx) < 1e-12) break;            // защита от деления на ноль

        double x_new = x - fx / fpx;                  // шаг Ньютона
        if (std::abs(x_new - x) < 1e-10) break;      // сходимость достигнута
        x = x_new;
    }

    // Округляем результат до ближайшего целого
    int16_t candidate = static_cast<int16_t>(std::round(x));

    // Страховка: если после округления LSB не совпал — берём ближайшее с нужным битом
    if ((candidate & 1) != target_bit) {
        int16_t down = candidate - 1;
        int16_t up   = candidate + 1;
        if (std::abs(down - original) <= std::abs(up - original))
            candidate = down;
        else
            candidate = up;
    }

    // Ограничение диапазона int16_t (-32768 .. 32767)
    if (candidate < -32768) candidate = -32768;
    if (candidate > 32767)  candidate = 32767;

    return candidate;
}

/**
 * @brief Внедрение сообщения в аудиосэмплы методом LSB-стеганографии.
 *
 * Алгоритм:
 *   1. К сообщению добавляется 4-байтный префикс длины (big-endian),
 *      чтобы при извлечении знать, сколько байтов читать.
 *   2. SHA-1 хэш пароля используется как seed для ГПСЧ (mt19937),
 *      который генерирует псевдослучайные позиции в массиве сэмплов.
 *      Это обеспечивает секретность: без пароля нельзя восстановить
 *      порядок позиций, а значит и сообщение.
 *   3. Для каждого бита сообщения выбирается уникальная случайная позиция,
 *      и младший бит (LSB) сэмпла устанавливается методом Ньютона.
 *
 * @param samples Вектор 16-битных PCM-сэмплов (модифицируется на месте)
 * @param message Данные для встраивания (может содержать бинарные данные)
 * @param password Пароль — ключ для генерации порядка позиций (через SHA-1)
 * @return true — успех, false — не хватает места в аудиофайле
 */
bool embed_message(std::vector<int16_t>& samples, const std::string& message, const std::string& password) {
    // Формат данных: [4 байта длины (big-endian)] [данные сообщения]
    uint32_t msg_len = static_cast<uint32_t>(message.size());
    std::string data;
    data.push_back(static_cast<char>((msg_len >> 24) & 0xFF));
    data.push_back(static_cast<char>((msg_len >> 16) & 0xFF));
    data.push_back(static_cast<char>((msg_len >> 8) & 0xFF));
    data.push_back(static_cast<char>(msg_len & 0xFF));
    data += message;

    // Проверяем, хватит ли сэмплов (1 бит на сэмпл)
    if (samples.size() < data.size() * 8) {
        return false;
    }

    // Генерируем ГПСЧ на основе SHA-1 хэша пароля
    std::vector<unsigned char> hash = sha1(password);
    std::seed_seq seed(hash.begin(), hash.end());
    std::mt19937 gen(seed);
    std::uniform_int_distribution<size_t> dist(0, samples.size() - 1);
    std::vector<bool> used(samples.size(), false);  // отметки использованных позиций

    // Встраиваем каждый бит данных в случайную позицию
    for (size_t byte_idx = 0; byte_idx < data.size(); ++byte_idx) {
        unsigned char c = static_cast<unsigned char>(data[byte_idx]);
        for (int i = 7; i >= 0; --i) {              // от старшего бита к младшему
            int target_bit = (c >> i) & 1;

            // Выбираем уникальную случайную позицию (без повторов)
            size_t pos;
            do {
                pos = dist(gen);
            } while (used[pos]);
            used[pos] = true;

            // Применяем метод Ньютона для установки LSB сэмпла
            samples[pos] = apply_newton_lsb(samples[pos], target_bit);
        }
    }
    return true;
}

/**
 * @brief Извлечение сообщения из аудиосэмплов.
 *
 * Алгоритм (обратный к embed_message):
 *   1. SHA-1 хэш пароля → seed ГПСЧ → тот же порядок позиций, что при внедрении.
 *   2. Читаем первые 4 байта → длина сообщения.
 *   3. Читаем msg_len байтов → данные сообщения.
 *   4. Из каждого сэмпла извлекаем LSB (младший бит).
 *
 * @param samples Вектор 16-битных PCM-сэмплов (не модифицируется)
 * @param password Тот же пароль, что использовался при внедрении
 * @return Извлечённые данные (пустая строка при ошибке)
 */
std::string extract_message(const std::vector<int16_t>& samples, const std::string& password) {
    // Инициализируем ГПСЧ тем же seed (SHA-1 от пароля)
    std::vector<unsigned char> hash = sha1(password);
    std::seed_seq seed(hash.begin(), hash.end());
    std::mt19937 gen(seed);
    std::uniform_int_distribution<size_t> dist(0, samples.size() - 1);
    std::vector<bool> used(samples.size(), false);

    // Читаем 4 байта длины сообщения
    std::string length_bytes;
    for (int byte_idx = 0; byte_idx < 4; ++byte_idx) {
        unsigned char current_byte = 0;
        for (int bit = 7; bit >= 0; --bit) {
            size_t pos;
            do {
                pos = dist(gen);
            } while (used[pos]);
            used[pos] = true;

            // Извлекаем LSB сэмпла
            int bit_val = samples[pos] & 1;
            current_byte |= (bit_val << bit);
        }
        length_bytes.push_back(static_cast<char>(current_byte));
    }

    // Декодируем длину (big-endian)
    uint32_t msg_len = (static_cast<unsigned char>(length_bytes[0]) << 24) |
                       (static_cast<unsigned char>(length_bytes[1]) << 16) |
                       (static_cast<unsigned char>(length_bytes[2]) << 8) |
                       static_cast<unsigned char>(length_bytes[3]);

    // Проверка на корректность длины
    if (msg_len == 0 || msg_len > samples.size() / 8) return "";

    // Читаем msg_len байтов данных сообщения
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
