#include "steganography.h"
#include <random>
#include <cmath>

// Функция, которую мы будрешателььно использовать для метода Ньютона.
// Наша цель — найти такое значение сэмпла (y), которое:
// 1. Находится в пределах допустимого диапазона (не выходит за int16_t).
// 2. Его младший бит равен заданному биту сообщения (target_bit).
// 3. Максимально близко к исходному сэмплу (x). Мы будем "минимизировать" разницу.
double f(double y, int16_t x, int target_bit) {
    // Условие: младший бит y должен быть равен target_bit.
    // (static_cast<int>(y) & 1) == target_bit
    // Уравнение для метода Ньютона: f(y) = (y - x)^2
    return (y - x) * (y - x);
}

double df(double y, int16_t x) {
    // Производная от f(y) = 2*(y - x)
    return 2.0 * (y - x);
}

// Основная функция внедрения
bool embed_message(std::vector<int16_t>& samples, const std::string& message, const WavHeader& header) {
    // 1. Проверяем, хватит ли места (1 бит на сэмпл)
    if (samples.size() < message.size() * 8) {
        return false;
    }

    // 2. Генерируем seed на основе SHA-1 от сообщения
    unsigned char hash[SHA_DIGEST_LENGTH];
    SHA1(reinterpret_cast<const unsigned char*>(message.c_str()), message.size(), hash);
    
    std::seed_seq seed(hash, hash + SHA_DIGEST_LENGTH);
    std::mt19937 gen(seed);
    std::uniform_int_distribution<size_t> dist(0, samples.size() - 1);
    std::vector<bool> used(samples.size(), false);

    // 3. Встраиваем биты сообщения
    int bit_index = 0;
    for (char c : message) {
        for (int i = 7; i >= 0; --i) {
            int target_bit = (c >> i) & 1;
            
            // Выбираем случайную позицию для встраивания
            size_t pos;
            do {
                pos = dist(gen);
            } while (used[pos]);
            used[pos] = true;

            int16_t original_sample = samples[pos];
            
            // ----- Применяем метод Ньютона для поиска нового значения сэмпла -----
            double y = original_sample; // Начальное приближение
            double new_y;
            for (int iter = 0; iter < 10; ++iter) { // Ограничиваем число итераций
                double fy = f(y, original_sample, target_bit);
                double dfy = df(y, original_sample);
                if (std::fabs(dfy) < 1e-6) break;
                new_y = y - fy / dfy;
                if (std::fabs(new_y - y) < 1e-6) break;
                y = new_y;
            }
            
            // Округляем до ближайшего целого
            int16_t new_sample = static_cast<int16_t>(std::round(new_y));
            
            // Корректируем, чтобы LSB совпадал с target_bit
            if (((new_sample & 1) != target_bit)) {
                new_sample ^= 1;
            }
            
            // Проверяем, не вышли ли за границы
            if (new_sample > 32767) new_sample = 32767;
            if (new_sample < -32768) new_sample = -32768;
            
            samples[pos] = new_sample;
            bit_index++;
        }
    }
    return true;
}
