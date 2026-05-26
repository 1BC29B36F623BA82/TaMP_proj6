#include "steganography.h"
#include "sha1.h"   
#include <random>
#include <cmath>
#include <vector>
#include <string>
#include <cstring>
#include <algorithm>
#include <cstdlib>

// Вспомогательная функция: применяет метод Ньютона для поиска сэмпла с заданным LSB
// Возвращает новое значение, максимально близкое к original, с младшим битом = target_bit
static int16_t apply_newton_lsb(int16_t original, int target_bit) {
    // Метод Ньютона для минимизации (y - original)^2
    // Первая производная: 2*(y - original)
    // Вторая производная: 2
    // Итерация: y_new = y - (2*(y - original))/2 = original (сходится за 1 шаг)
    double y = static_cast<double>(original);
    for (int iter = 0; iter < 5; ++iter) {
        double derivative = 2.0 * (y - original);
        double second_derivative = 2.0;
        y = y - derivative / second_derivative;
    }
    
    // Округляем до целого
    int16_t candidate = static_cast<int16_t>(std::round(y));
    
    // Если LSB не совпадает, берём ближайшее число с нужным битом
    if ((candidate & 1) != target_bit) {
        int16_t down = candidate - 1;
        int16_t up   = candidate + 1;
        // Выбираем то, которое ближе к original
        if (std::llabs(down - original) <= std::llabs(up - original))
            candidate = down;
        else
            candidate = up;
    }
    
    // Ограничиваем диапазон int16_t
    if (candidate < -32768) candidate = -32768;
    if (candidate > 32767) candidate = 32767;
    
    return candidate;
}

// Основная функция внедрения сообщения
bool embed_message(std::vector<int16_t>& samples, const std::string& message, const std::string& password) {
    // 1. Проверяем, хватит ли места (1 бит на сэмпл)
    if (samples.size() < message.size() * 8) {
        return false;
    }

    // 2. Генерируем seed на основе SHA-1 от пароля (не от сообщения!)
    std::vector<unsigned char> hash = sha1(password);
    std::seed_seq seed(hash.begin(), hash.end());
    std::mt19937 gen(seed);
    std::uniform_int_distribution<size_t> dist(0, samples.size() - 1);
    std::vector<bool> used(samples.size(), false);

    // 3. Встраиваем биты сообщения
    for (char c : message) {
        for (int i = 7; i >= 0; --i) {
            int target_bit = (c >> i) & 1;
            
            // Выбираем уникальную случайную позицию
            size_t pos;
            do {
                pos = dist(gen);
            } while (used[pos]);
            used[pos] = true;

            int16_t original_sample = samples[pos];
            int16_t new_sample = apply_newton_lsb(original_sample, target_bit);
            samples[pos] = new_sample;
        }
    }
    return true;
}

// Функция извлечения сообщения
std::string extract_message(const std::vector<int16_t>& samples, const std::string& password) {
    // 1. Вычисляем SHA-1 от пароля (должен быть тот же, что при встраивании)
    std::vector<unsigned char> hash = sha1(password);
    std::seed_seq seed(hash.begin(), hash.end());
    std::mt19937 gen(seed);
    std::uniform_int_distribution<size_t> dist(0, samples.size() - 1);
    std::vector<bool> used(samples.size(), false);

    std::string extracted_message;
    // Читаем байты, пока не встретим нулевой или не превысим разумный лимит
    for (size_t byte_count = 0; byte_count < 10000; ++byte_count) {
        char current_byte = 0;
        for (int bit = 7; bit >= 0; --bit) {
            size_t pos;
            do {
                pos = dist(gen);
            } while (used[pos]);
            used[pos] = true;
            
            int bit_val = samples[pos] & 1;
            current_byte |= (bit_val << bit);
        }
        if (current_byte == '\0') break;  // конец сообщения
        extracted_message.push_back(current_byte);
    }
    return extracted_message;
}
