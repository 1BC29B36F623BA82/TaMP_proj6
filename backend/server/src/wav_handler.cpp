/**
 * @file wav_handler.cpp
 * @brief Модуль чтения и записи WAV-файлов (формат PCM, 16 бит).
 *
 * Поддерживается только стандартный WAV-формат:
 *   - RIFF-заголовок с подтипом WAVE
 *   - Формат PCM (audioFormat = 1)
 *   - 16 бит на сэмпл (bitsPerSample = 16)
 */

#include "wav_handler.h"
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cstring>

/**
 * @brief Проверка корректности WAV-заголовка.
 *
 * Проверяет:
 *   - Сигнатуры RIFF, WAVE, fmt, data
 *   - Формат PCM (audioFormat == 1)
 *   - Глубину 16 бит (bitsPerSample == 16)
 *   - Ненулевой размер данных
 *
 * @param header Заголовок WAV-файла
 * @return true — заголовок корректен, false — файл не поддерживается
 */
bool is_valid_wav(const WavHeader& header) {
    // Проверка сигнатур
    if (std::memcmp(header.chunkID, "RIFF", 4) != 0) return false;
    if (std::memcmp(header.format, "WAVE", 4) != 0) return false;
    if (std::memcmp(header.subchunk1ID, "fmt ", 4) != 0) return false;
    if (std::memcmp(header.subchunk2ID, "data", 4) != 0) return false;

    if (header.audioFormat != 1) return false;   // только PCM
    if (header.bitsPerSample != 16) return false; // только 16 бит
    if (header.subchunk2Size == 0) return false;  // данные не пусты

    return true;
}

/**
 * @brief Чтение WAV-файла в вектор 16-битных сэмплов.
 *
 * Считывает заголовок (44 байта), проверяет корректность,
 * затем считывает PCM-данные в вектор int16_t.
 *
 * @param filename Путь к WAV-файлу
 * @param header Ссылка на структуру заголовка (будет заполнена)
 * @return Вектор сэмплов (пустой при ошибке)
 */
std::vector<int16_t> read_wav(const std::string& filename, WavHeader& header) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Error: cannot open file " << filename << std::endl;
        return {};
    }

    std::memset(&header, 0, sizeof(header));

    // Читаем RIFF chunk (12 байт)
    char riff[4], wave[4];
    uint32_t riffSize;
    file.read(riff, 4);
    file.read(reinterpret_cast<char*>(&riffSize), 4);
    file.read(wave, 4);

    if (std::memcmp(riff, "RIFF", 4) != 0 || std::memcmp(wave, "WAVE", 4) != 0) {
        std::cerr << "Error: not a valid RIFF/WAVE file" << std::endl;
        return {};
    }

    std::memcpy(header.chunkID, riff, 4);
    header.chunkSize = riffSize;
    std::memcpy(header.format, wave, 4);

    // Ищет fmt и data subchunks
    char subchunkID[4];
    uint32_t subchunkSize;
    bool foundFmt = false, foundData = false;

    while (file.read(subchunkID, 4) && file.read(reinterpret_cast<char*>(&subchunkSize), 4)) {
        if (std::memcmp(subchunkID, "fmt ", 4) == 0) {
            foundFmt = true;
            std::memcpy(header.subchunk1ID, subchunkID, 4);
            header.subchunk1Size = subchunkSize;
            file.read(reinterpret_cast<char*>(&header.audioFormat), 2);
            file.read(reinterpret_cast<char*>(&header.numChannels), 2);
            file.read(reinterpret_cast<char*>(&header.sampleRate), 4);
            file.read(reinterpret_cast<char*>(&header.byteRate), 4);
            file.read(reinterpret_cast<char*>(&header.blockAlign), 2);
            file.read(reinterpret_cast<char*>(&header.bitsPerSample), 2);
            if (subchunkSize > 16) file.ignore(subchunkSize - 16);
        }
        else if (std::memcmp(subchunkID, "data", 4) == 0) {
            foundData = true;
            std::memcpy(header.subchunk2ID, subchunkID, 4);
            header.subchunk2Size = subchunkSize;
            break;
        }
        else {
            file.ignore(subchunkSize);
        }
    }

    if (!foundFmt || !foundData) {
        std::cerr << "Error: fmt or data subchunk not found" << std::endl;
        return {};
    }

    std::cerr << "[read_wav] File: " << filename << std::endl;
    std::cerr << "  audioFormat: " << header.audioFormat << " (need 1)" << std::endl;
    std::cerr << "  bitsPerSample: " << header.bitsPerSample << " (need 16)" << std::endl;
    std::cerr << "  numChannels: " << header.numChannels << std::endl;
    std::cerr << "  sampleRate: " << header.sampleRate << std::endl;
    std::cerr << "  subchunk2Size: " << header.subchunk2Size << " bytes" << std::endl;

    if (!is_valid_wav(header)) {
        std::cerr << "Error: unsupported WAV format (need PCM 16 bit)" << std::endl;
        return {};
    }

    size_t numSamples = header.subchunk2Size / (header.bitsPerSample / 8);
    std::vector<int16_t> samples(numSamples);
    file.read(reinterpret_cast<char*>(samples.data()), header.subchunk2Size);

    if (!file && !file.eof()) {
        std::cerr << "Error: cannot read audio data" << std::endl;
        return {};
    }

    std::cerr << "[read_wav] Loaded " << numSamples << " samples" << std::endl;
    return samples;
}

/**
 * @brief Запись вектора сэмплов в WAV-файл.
 *
 * Копирует исходный заголовок, пересчитывает поля chunkSize и subchunk2Size
 * под актуальный размер данных, затем записывает заголовок и сэмплы.
 *
 * @param filename Путь к выходному WAV-файлу
 * @param samples Вектор 16-битных PCM-сэмплов
 * @param original_header Исходный заголовок (частота, каналы и т.д.)
 * @return true — запись успешна, false — ошибка
 */
bool write_wav(const std::string& filename, const std::vector<int16_t>& samples, const WavHeader& original_header) {
    if (samples.empty()) {
        std::cerr << "Ошибка: нет данных для записи" << std::endl;
        return false;
    }

    // Копирка заголовка и пересчёт размера
    WavHeader header = original_header;

    // Размер PCM-данных в байтах
    uint32_t dataSize = static_cast<uint32_t>(samples.size() * sizeof(int16_t));
    header.subchunk2Size = dataSize;

    // Общий размер файла: 36 (заголовок без RIFF ID и chunkSize) + dataSize
    header.chunkSize = 36 + dataSize;

    // Корректируем поля, если они были нулевыми
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

    // Открытие файла для записи
    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Ошибка: не удалось создать файл " << filename << std::endl;
        return false;
    }

    // Запись заголовка (44 байта)
    file.write(reinterpret_cast<const char*>(&header), sizeof(WavHeader));
    if (!file) {
        std::cerr << "Ошибка: не удалось записать заголовок" << std::endl;
        return false;
    }

    // Запись PCM-данных
    file.write(reinterpret_cast<const char*>(samples.data()), dataSize);
    if (!file) {
        std::cerr << "Ошибка: не удалось записать аудиоданные" << std::endl;
        return false;
    }

    return true;
}