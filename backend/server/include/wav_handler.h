#ifndef WAV_HANDLER_H
#define WAV_HANDLER_H

#include <vector>
#include <string>
#include <cstdint>

struct WavHeader {
    char     chunkID[4];
    uint32_t chunkSize;
    char     format[4];
    char     subchunk1ID[4];
    uint32_t subchunk1Size;
    uint16_t audioFormat;
    uint16_t numChannels;
    uint32_t sampleRate;
    uint32_t byteRate;
    uint16_t blockAlign;
    uint16_t bitsPerSample;
    char     subchunk2ID[4];
    uint32_t subchunk2Size;
};

std::vector<int16_t> read_wav(const std::string& filename, WavHeader& header);
bool write_wav(const std::string& filename, const std::vector<int16_t>& samples, const WavHeader& header);
bool is_valid_wav(const WavHeader& header);

#endif // WAV_HANDLER_H
