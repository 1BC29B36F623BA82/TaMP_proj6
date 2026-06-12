#include "wav_handler.h"
#include <fstream>
#include <iostream>
#include <algorithm>
#include <cstring>

bool is_valid_wav(const WavHeader& header) {
    if (std::memcmp(header.chunkID, "RIFF", 4) != 0) return false;
    if (std::memcmp(header.format, "WAVE", 4) != 0) return false;
    if (std::memcmp(header.subchunk1ID, "fmt ", 4) != 0) return false;
    if (std::memcmp(header.subchunk2ID, "data", 4) != 0) return false;

    if (header.audioFormat != 1) return false;
    if (header.bitsPerSample != 16) return false;
    if (header.subchunk2Size == 0) return false;

    return true;
}

std::vector<int16_t> read_wav(const std::string& filename, WavHeader& header) {
    std::ifstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Cannot open file " << filename << std::endl;
        return {};
    }

    file.read(reinterpret_cast<char*>(&header), sizeof(WavHeader));
    if (!file) {
        std::cerr << "Cannot read WAV header" << std::endl;
        return {};
    }

    if (!is_valid_wav(header)) {
        std::cerr << "Unsupported WAV format (PCM 16-bit required)" << std::endl;
        return {};
    }

    size_t numSamples = header.subchunk2Size / (header.bitsPerSample / 8);
    std::vector<int16_t> samples(numSamples);

    file.read(reinterpret_cast<char*>(samples.data()), header.subchunk2Size);
    if (!file && !file.eof()) {
        std::cerr << "Cannot read audio data" << std::endl;
        return {};
    }

    return samples;
}

bool write_wav(const std::string& filename, const std::vector<int16_t>& samples, const WavHeader& original_header) {
    if (samples.empty()) {
        std::cerr << "No data to write" << std::endl;
        return false;
    }

    WavHeader header = original_header;

    uint32_t dataSize = static_cast<uint32_t>(samples.size() * sizeof(int16_t));
    header.subchunk2Size = dataSize;
    header.chunkSize = 36 + dataSize;

    if (header.bitsPerSample != 16) {
        header.bitsPerSample = 16;
    }
    if (header.blockAlign == 0) {
        header.blockAlign = header.numChannels * (header.bitsPerSample / 8);
    }
    if (header.byteRate == 0) {
        header.byteRate = header.sampleRate * header.blockAlign;
    }

    std::ofstream file(filename, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Cannot create file " << filename << std::endl;
        return false;
    }

    file.write(reinterpret_cast<const char*>(&header), sizeof(WavHeader));
    if (!file) {
        std::cerr << "Cannot write header" << std::endl;
        return false;
    }

    file.write(reinterpret_cast<const char*>(samples.data()), dataSize);
    if (!file) {
        std::cerr << "Cannot write audio data" << std::endl;
        return false;
    }

    return true;
}
