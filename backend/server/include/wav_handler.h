#ifndef WAV_HANDLER_H
#define WAV_HANDLER_H

#include <vector>
#include <string>
#include <cstdint>

// Структура, представляющая WAV-заголовок (только необходимые поля)
struct WavHeader {
    // RIFF chunk
    char     chunkID[4];        // "RIFF"
    uint32_t chunkSize;         // размер файла - 8
    char     format[4];         // "WAVE"

    // fmt subchunk
    char     subchunk1ID[4];    // "fmt "
    uint32_t subchunk1Size;     // 16 для PCM
    uint16_t audioFormat;       // 1 для PCM
    uint16_t numChannels;       // количество каналов
    uint32_t sampleRate;        // частота дискретизации
    uint32_t byteRate;          // sampleRate * numChannels * bitsPerSample/8
    uint16_t blockAlign;        // numChannels * bitsPerSample/8
    uint16_t bitsPerSample;     // бит на сэмпл (обычно 16)

    // Data subchunk
    char     subchunk2ID[4];    // "data"
    uint32_t subchunk2Size;     // размер данных в байтах
};

// Функция для чтения WAV-файла
// Принимает имя файла и ссылку на структуру заголовка (заполнится)
// Возвращает вектор 16-битных сэмплов (PCM)
std::vector<int16_t> read_wav(const std::string& filename, WavHeader& header);

// Функция для записи WAV-файла
// Принимает имя выходного файла, вектор сэмплов и заголовок (частота, каналы и т.д.)
// Заголовок будет пересчитан в соответствии с размером данных
bool write_wav(const std::string& filename, const std::vector<int16_t>& samples, const WavHeader& header);

// Вспомогательная функция для проверки корректности WAV
bool is_valid_wav(const WavHeader& header);

#endif // WAV_HANDLER_H
