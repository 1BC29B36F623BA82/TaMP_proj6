#include "wav_handler.h"
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cstring>

// Проверка корректности заголовка (PCM, 16 бит, непустой)
bool is_valid_wav(const WavHeader& header) {
    // Проверка сигнатур
    if (std::memcmp(header.chunkID, "RIFF", 4) != 0) return false;
    if (std::memcmp(header.format, "WAVE", 4) != 0) return false;
    if (std::memcmp(header.subchunk1ID, "fmt ", 4) != 0) return false;
    if (std::memcmp(header.subchunk2ID, "data", 4) != 0) return false;

    // Должен быть PCM
    if (header.audioFormat != 1) return false;
    // Поддерживаем только 16 бит на сэмпл
    if (header.bitsPerSample != 16) return false;
    // Размер данных не должен быть нулевым
    if (header.subchunk2Size == 0) return false;

    return true;
}

// Чтение WAV-файла
std::vector<int16_t> read_wav(const std::string& filename, WavHeader& header) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Ошибка: не удалось открыть файл " << filename << std::endl;
        return {};
    }

    // Считываем заголовок
    file.read(reinterpret_cast<char*>(&header), sizeof(WavHeader));
    if (!file) {
        std::cerr << "Ошибка: не удалось прочитать заголовок WAV" << std::endl;
        return {};
    }

    // Проверяем корректность
    if (!is_valid_wav(header)) {
        std::cerr << "Ошибка: неподдерживаемый формат WAV (требуется PCM 16 бит)" << std::endl;
        return {};
    }

    // Вычисляем количество сэмплов
    size_t numSamples = header.subchunk2Size / (header.bitsPerSample / 8);
    std::vector<int16_t> samples(numSamples);

    // Читаем данные
    file.read(reinterpret_cast<char*>(samples.data()), header.subchunk2Size);
    if (!file && !file.eof()) {
        std::cerr << "Ошибка: не удалось прочитать аудиоданные" << std::endl;
        return {};
    }

    return samples;
}

// Запись WAV-файла
bool write_wav(const std::string& filename, const std::vector<int16_t>& samples, const WavHeader& original_header) {
    if (samples.empty()) {
        std::cerr << "Ошибка: нет данных для записи" << std::endl;
        return false;
    }

    // Создаём копию заголовка и корректируем поля под новые данные
    WavHeader header = original_header;

    // Размер данных в байтах
    uint32_t dataSize = static_cast<uint32_t>(samples.size() * sizeof(int16_t));
    header.subchunk2Size = dataSize;

    // Общий размер файла: 36 + dataSize (стандартно для PCM)
    header.chunkSize = 36 + dataSize;

    // Убедимся, что остальные поля заголовка не противоречат данным
    if (header.bitsPerSample != 16) {
        std::cerr << "Предупреждение: bitsPerSample принудительно установлен в 16" << std::endl;
        header.bitsPerSample = 16;
    }
    if (header.blockAlign == 0) {
        header.blockAlign = header.numChannels * (header.bitsPerSample / 8);
    }
    if (header.byteRate == 0) {
        header.byteRate = header.sampleRate * header.blockAlign;
    }

    // Открываем файл для записи
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Ошибка: не удалось создать файл " << filename << std::endl;
        return false;
    }

    // Пишем заголовок
    file.write(reinterpret_cast<const char*>(&header), sizeof(WavHeader));
    if (!file) {
        std::cerr << "Ошибка: не удалось записать заголовок" << std::endl;
        return false;
    }

    // Пишем сэмплы
    file.write(reinterpret_cast<const char*>(samples.data()), dataSize);
    if (!file) {
        std::cerr << "Ошибка: не удалось записать аудиоданные" << std::endl;
        return false;
    }

    return true;
}
