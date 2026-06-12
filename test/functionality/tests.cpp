/**
 * @file tests.cpp
 * @brief Модульные тесты (Qt Test) для серверных модулей проекта TaMP_proj6.
 *
 * Сборка:  qmake6 tests.pro && make && ./tst_functionality
 */
#include <QtTest>
#include <vector>
#include <string>
#include <cstdint>
#include <cstring>

#include "rsa.h"
#include "sha1.h"
#include "steganography.h"
#include "wav_handler.h"

static QString toHex(const std::vector<unsigned char>& bytes) {
    QString out;
    static const char* h = "0123456789abcdef";
    for (unsigned char b : bytes) { out += h[(b >> 4) & 0xF]; out += h[b & 0xF]; }
    return out;
}

static std::vector<int16_t> makeSamples(size_t n) {
    std::vector<int16_t> s(n);
    for (size_t i = 0; i < n; ++i)
        s[i] = static_cast<int16_t>((i * 37) % 1000 - 500);
    return s;
}

class TestFunctionality : public QObject
{
    Q_OBJECT

private slots:
    void rsa_keys_known_values();
    void rsa_roundtrip_data();
    void rsa_roundtrip();
    void rsa_serialize_roundtrip();

    void sha1_vectors_data();
    void sha1_vectors();

    void wav_write_read_roundtrip();
    void wav_invalid_header();

    void steg_embed_extract_roundtrip();
    void steg_wrong_password_fails();
    void steg_too_short_fails();
    void steg_newton_preserves_amplitude();

    void full_pipeline_rsa_steg();
};

void TestFunctionality::rsa_keys_known_values() {
    RSAKeyPair k = generate_keys(61, 53);
    QCOMPARE(k.n, static_cast<uint64_t>(3233));
    uint64_t phi = 60 * 52;
    QCOMPARE((k.e * k.d) % phi, static_cast<uint64_t>(1));
}

void TestFunctionality::rsa_roundtrip_data() {
    QTest::addColumn<QString>("text");
    QTest::newRow("ascii")   << "Hello";
    QTest::newRow("digits")  << "12345";
    QTest::newRow("symbols") << "a,b.c!?";
    QTest::newRow("single")  << "Z";
}

void TestFunctionality::rsa_roundtrip() {
    QFETCH(QString, text);
    RSAKeyPair k = generate_keys(61, 53);
    std::string in = text.toStdString();
    auto cipher = rsa_encrypt(in, k.e, k.n);
    QCOMPARE(cipher.size(), in.size());
    std::string out = rsa_decrypt(cipher, k.d, k.n);
    QCOMPARE(QString::fromStdString(out), text);
}

void TestFunctionality::rsa_serialize_roundtrip() {
    RSAKeyPair k = generate_keys(61, 53);
    auto cipher = rsa_encrypt("payload", k.e, k.n);
    std::string blob = serialize_ciphertext(cipher);
    auto restored = deserialize_ciphertext(blob);
    QCOMPARE(restored, cipher);
    QVERIFY(deserialize_ciphertext("ab").empty());
}

void TestFunctionality::sha1_vectors_data() {
    QTest::addColumn<QString>("input");
    QTest::addColumn<QString>("digest");
    QTest::newRow("empty") << "" << "da39a3ee5e6b4b0d3255bfef95601890afd80709";
    QTest::newRow("abc")   << "abc" << "a9993e364706816aba3e25717850c26c9cd0d89d";
    QTest::newRow("hello") << "hello" << "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d";
    QTest::newRow("quick_brown")
        << "The quick brown fox jumps over the lazy dog"
        << "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12";
}

void TestFunctionality::sha1_vectors() {
    QFETCH(QString, input);
    QFETCH(QString, digest);
    QCOMPARE(toHex(sha1(input.toStdString())), digest);
}

static WavHeader makeHeader(uint32_t dataBytes) {
    WavHeader h{};
    std::memcpy(h.chunkID, "RIFF", 4);
    std::memcpy(h.format, "WAVE", 4);
    std::memcpy(h.subchunk1ID, "fmt ", 4);
    h.subchunk1Size = 16;
    h.audioFormat = 1;
    h.numChannels = 1;
    h.sampleRate = 8000;
    h.bitsPerSample = 16;
    h.byteRate = h.sampleRate * h.numChannels * h.bitsPerSample / 8;
    h.blockAlign = h.numChannels * h.bitsPerSample / 8;
    std::memcpy(h.subchunk2ID, "data", 4);
    h.subchunk2Size = dataBytes;
    h.chunkSize = 36 + dataBytes;
    return h;
}

void TestFunctionality::wav_write_read_roundtrip() {
    auto samples = makeSamples(2000);
    WavHeader h = makeHeader(static_cast<uint32_t>(samples.size() * 2));
    QString path = QDir::temp().filePath("tamp_test.wav");

    QVERIFY(write_wav(path.toStdString(), samples, h));
    WavHeader rh;
    auto read = read_wav(path.toStdString(), rh);
    QCOMPARE(read.size(), samples.size());
    QCOMPARE(read, samples);
    QVERIFY(is_valid_wav(rh));
    QFile::remove(path);
}

void TestFunctionality::wav_invalid_header() {
    WavHeader bad = makeHeader(100);
    bad.bitsPerSample = 8;
    QVERIFY(!is_valid_wav(bad));
    WavHeader bad2 = makeHeader(100);
    std::memcpy(bad2.format, "AVI ", 4);
    QVERIFY(!is_valid_wav(bad2));
}

void TestFunctionality::steg_embed_extract_roundtrip() {
    auto samples = makeSamples(8000);
    std::string msg = "Secret";
    QVERIFY(embed_message(samples, msg, "pwd123"));
    std::string out = extract_message(samples, "pwd123");
    QCOMPARE(QString::fromStdString(out), QString::fromStdString(msg));
}

void TestFunctionality::steg_wrong_password_fails() {
    auto samples = makeSamples(8000);
    QVERIFY(embed_message(samples, "TopSecret", "right"));
    std::string out = extract_message(samples, "wrong");
    QVERIFY(QString::fromStdString(out) != "TopSecret");
}

void TestFunctionality::steg_too_short_fails() {
    auto samples = makeSamples(8);
    QVERIFY(!embed_message(samples, "this message will not fit", "p"));
}

void TestFunctionality::steg_newton_preserves_amplitude() {
    auto original = makeSamples(8000);
    auto modified = original;
    QVERIFY(embed_message(modified, "abcDEF123", "key"));
    for (size_t i = 0; i < original.size(); ++i)
        QVERIFY(std::abs(int(modified[i]) - int(original[i])) <= 1);
}

void TestFunctionality::full_pipeline_rsa_steg() {
    RSAKeyPair k = generate_keys(61, 53);
    std::string secret = "Pipeline!";

    auto cipher = rsa_encrypt(secret, k.e, k.n);
    std::string blob = serialize_ciphertext(cipher);
    auto samples = makeSamples(16000);
    QVERIFY(embed_message(samples, blob, "chainpwd"));

    std::string got = extract_message(samples, "chainpwd");
    QVERIFY(!got.empty());
    auto restored = deserialize_ciphertext(got);
    QCOMPARE(restored, cipher);
    std::string plain = rsa_decrypt(restored, k.d, k.n);
    QCOMPARE(QString::fromStdString(plain), QString::fromStdString(secret));
}

QTEST_MAIN(TestFunctionality)
#include "tests.moc"
