/**
 * @file wav_handler.h
 * @brief Интерфейс модуля чтения/записи WAV-файлов (PCM, 16 бит).
 *
 * Поддерживается стандартный формат WAV:
 *   - Контейнер: RIFF / WAVE
 *   - Кодирование: PCM (без сжатия, audioFormat = 1)
 *   - Глубина: 16 бит на сэмпл (int16_t, диапазон -32768..32767)
 */
#ifndef WAV_HANDLER_H
#define WAV_HANDLER_H

#include <vector>
#include <string>
#include <cstdint>

/**
 * @brief Структура 44-байтного заголовка WAV-файла.
 *
 * Содержит три секции:
 *   - RIFF chunk: идентификатор формата и общий размер файла
 *   - fmt subchunk: параметры аудио (частота, каналы, глубина)
 *   - data subchunk: размер PCM-данных
 */
struct WavHeader {
    // --- RIFF chunk ---
    char     chunkID[4];        // Сигнатура "RIFF"
    uint32_t chunkSize;         // Размер файла минус 8 байтов (RIFF + chunkSize)
    char     format[4];         // Формат "WAVE"

    // --- fmt subchunk ---
    char     subchunk1ID[4];    // Сигнатура "fmt "
    uint32_t subchunk1Size;     // Размер fmt-блока (16 для PCM)
    uint16_t audioFormat;       // Формат аудио (1 = PCM, без сжатия)
    uint16_t numChannels;       // Количество каналов (1 = моно, 2 = стерео)
    uint32_t sampleRate;        // Частота дискретизации (Гц), например 44100
    uint32_t byteRate;          // Байт в секунду: sampleRate * numChannels * bitsPerSample/8
    uint16_t blockAlign;        // Байт на один фрейм: numChannels * bitsPerSample/8
    uint16_t bitsPerSample;     // Бит на сэмпл (16 для данного проекта)

    // --- data subchunk ---
    char     subchunk2ID[4];    // Сигнатура "data"
    uint32_t subchunk2Size;     // Размер PCM-данных в байтах
};

/**
 * @brief Чтение WAV-файла.
 *
 * @param filename Путь к WAV-файлу
 * @param header Ссылка на заголовок (будет заполнен при чтении)
 * @return Вектор 16-битных PCM-сэмплов (пустой при ошибке)
 */
std::vector<int16_t> read_wav(const std::string& filename, WavHeader& header);

/**
 * @brief Запись WAV-файла.
 *
 * @param filename Путь к выходному файлу
 * @param samples Вектор 16-битных PCM-сэмплов
 * @param header Заголовок (chunkSize и subchunk2Size будут пересчитаны)
 * @return true — запись успешна, false — ошибка
 */
bool write_wav(const std::string& filename, const std::vector<int16_t>& samples, const WavHeader& header);

/**
 * @brief Проверка корректности WAV-заголовка.
 *
 * @param header Заголовок для проверки
 * @return true — формат поддерживается (PCM, 16 бит), false — нет
 */
bool is_valid_wav(const WavHeader& header);

#endif // WAV_HANDLER_H
