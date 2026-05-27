/**
 * @file main.cpp
 * @brief TCP-сервер для стеганографии в WAV-файлах.
 *
 * Поддерживаемые команды:
 *   REG  <логин> <пароль> <RSA-ключ>  — регистрация пользователя
 *   AUTH <логин> <пароль>              — авторизация
 *   ENCRYPT <текст> <аудиофайл>       — шифрование RSA и встраивание в WAV
 *   DECRYPT <аудиофайл>               — извлечение из WAV и расшифрование RSA
 *
 * Цепочка обработки при шифровании:
 *   Открытый текст → RSA-шифрование → Сериализация → Стеганография (метод Ньютона + SHA-1) → WAV
 *
 * Цепочка обработки при расшифровании:
 *   WAV → Извлечение (SHA-1 для позиций) → Десериализация → RSA-расшифрование → Открытый текст
 */

#include <iostream>
#include <string>
#include <sstream>
#include <winsock2.h>
#include "Database.hpp"
#include "wav_handler.h"
#include "steganography.h"
#include "rsa.h"
#include <filesystem>
#include <fstream>
#include <vector>
#pragma comment(lib, "ws2_32.lib")

// Генерация RSA-ключей при запуске сервера (p=61, q=53 → n=3233)
static RSAKeyPair rsa_keys = generate_keys(61, 53);

/// Формирует полный путь к WAV-файлу в каталоге ./wav/
std::string getWavPath(const std::string& filename) {
    return "./wav/" + filename;
}

/**
 * @brief Шифрование текста и встраивание в WAV-файл.
 *
 * 1. Загружает WAV-файл (PCM 16 бит)
 * 2. Шифрует текст алгоритмом RSA (побайтово: c = m^e mod n)
 * 3. Сериализует шифротекст в бинарный формат
 * 4. Встраивает в аудиосэмплы методом LSB (позиции скремблируются через SHA-1 от пароля)
 * 5. Сохраняет результат в новый WAV-файл
 *
 * @param text Открытый текст для шифрования
 * @param audioPath Имя исходного WAV-файла (в каталоге ./wav/)
 * @return Строка с результатом операции (SUCCESS или ERROR)
 */
std::string Encrypt(const std::string& text, const std::string& audioPath) {
    std::string inputFile = getWavPath(audioPath);
    std::string outputFile = getWavPath("encrypted_" + audioPath);

    // Загружаем WAV-файл
    WavHeader header;
    std::vector<int16_t> samples = read_wav(inputFile, header);
    if (samples.empty()) {
        return "ERROR: Failed to read " + inputFile;
    }

    // Шифруем текст алгоритмом RSA
    std::vector<uint64_t> cipher = rsa_encrypt(text, rsa_keys.e, rsa_keys.n);
    // Сериализуем шифротекст в бинарный формат для встраивания
    std::string cipher_data = serialize_ciphertext(cipher);

    // Встраиваем шифротекст в аудиосэмплы (метод Ньютона + SHA-1)
    std::string password = "my_secret_server_key";
    if (!embed_message(samples, cipher_data, password)) {
        return "ERROR: Embedding failed (file too small?)";
    }

    // Сохраняем изменённые сэмплы в новый WAV-файл
    if (!write_wav(outputFile, samples, header)) {
        return "ERROR: Failed to write " + outputFile;
    }

    return "SUCCESS: Message encrypted (RSA) and hidden in " + outputFile;
}

/**
 * @brief Извлечение и расшифрование текста из WAV-файла.
 *
 * 1. Загружает WAV-файл
 * 2. Извлекает бинарные данные из LSB сэмплов (используя SHA-1 от пароля)
 * 3. Десериализует шифротекст
 * 4. Расшифровывает алгоритмом RSA (m = c^d mod n)
 *
 * @param audioPath Имя WAV-файла с внедрённым сообщением
 * @return Строка с расшифрованным текстом или сообщение об ошибке
 */
std::string Decrypt(const std::string& audioPath) {
    std::string inputFile = getWavPath(audioPath);
    WavHeader header;
    std::vector<int16_t> samples = read_wav(inputFile, header);
    if (samples.empty()) {
        return "ERROR: Cannot read " + inputFile;
    }

    // Извлекаем бинарные данные из аудиосэмплов
    std::string password = "my_secret_server_key";
    std::string cipher_data = extract_message(samples, password);
    if (cipher_data.empty()) {
        return "ERROR: No message found or wrong password";
    }

    // Десериализуем шифротекст
    std::vector<uint64_t> cipher = deserialize_ciphertext(cipher_data);
    if (cipher.empty()) {
        return "ERROR: Failed to deserialize ciphertext";
    }

    // Расшифровываем алгоритмом RSA
    std::string plaintext = rsa_decrypt(cipher, rsa_keys.d, rsa_keys.n);

    return "DECRYPTED_TEXT: " + plaintext;
}

/**
 * @brief Обработка TCP-запроса от клиента.
 *
 * Читает команду из сокета, выполняет соответствующее действие,
 * отправляет ответ и закрывает соединение.
 */
void handleClient(SOCKET clientSocket) {
    char buffer[2048] = {0};
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

    if (bytesReceived > 0) {
        std::string request(buffer);
        std::cout << "\n[Server] New request received:\n" << request << std::endl;

        // Разбираем команду (первое слово)
        std::stringstream ss(request);
        std::string command;
        ss >> command;

        std::string response;

        // Обработка команды REG: регистрация нового пользователя
        if (command == "REG") {
            std::string username, password, rsaKey;
            ss >> username >> password >> rsaKey;

            if (Database::getInstance().registerUser(username, password, rsaKey)) {
                response = "STATUS: REGISTER_SUCCESS\n";
            } else {
                response = "STATUS: REGISTER_FAILED (User might already exist)\n";
            }
        }
        // Обработка команды AUTH: авторизация пользователя
        else if (command == "AUTH") {
            std::string username, password;
            ss >> username >> password;

            if (Database::getInstance().authenticateUser(username, password)) {
                response = "STATUS: AUTH_SUCCESS\n";
            } else {
                response = "STATUS: AUTH_FAILED\n";
            }
        }
        // Обработка команды ENCRYPT: шифрование и внедрение в WAV
        else if (command == "ENCRYPT") {
            std::string textToHide, audioFile;
            ss >> textToHide >> audioFile;
            response = Encrypt(textToHide, audioFile) + "\n";
        }
        // Обработка команды DECRYPT: извлечение и расшифрование из WAV
        else if (command == "DECRYPT") {
            std::string audioFile;
            ss >> audioFile;
            response = Decrypt(audioFile) + "\n";
        }
        else {
            response = "STATUS: ERROR_UNKNOWN_COMMAND\n";
        }

        // Отправляем ответ клиенту
        send(clientSocket, response.c_str(), response.length(), 0);
    }
    closesocket(clientSocket);
}

/**
 * @brief Точка входа сервера.
 *
 * Инициализирует Winsock, создаёт TCP-сокет на порту 8080,
 * ожидает подключений и обрабатывает запросы последовательно.
 */
int main() {
    // Вывод сгенерированных RSA-ключей
    std::cout << "[Server] RSA keys: n=" << rsa_keys.n
              << " e=" << rsa_keys.e
              << " d=" << rsa_keys.d << std::endl;

    // Инициализация Winsock
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[Error] Winsock initialization failed." << std::endl;
        return 1;
    }

    // Создание TCP-сокета
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "[Error] Socket creation failed." << std::endl;
        WSACleanup();
        return 1;
    }

    // Настройка адреса и порта сервера
    sockaddr_in serverService;
    serverService.sin_family = AF_INET;
    serverService.sin_addr.s_addr = inet_addr("127.0.0.1");  // только localhost
    serverService.sin_port = htons(8080);                     // порт 8080

    // Привязка сокета к адресу
    if (bind(serverSocket, (SOCKADDR*)&serverService, sizeof(serverService)) == SOCKET_ERROR) {
        std::cerr << "[Error] Bind failed." << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    // Перевод сокета в режим прослушивания (максимум 3 в очереди)
    if (listen(serverSocket, 3) == SOCKET_ERROR) {
        std::cerr << "[Error] Listen failed." << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "[Server] Server is running on port 8080. Waiting for commands..." << std::endl;

    // Основной цикл: принимаем и обрабатываем подключения
    while (true) {
        SOCKET clientSocket = accept(serverSocket, NULL, NULL);
        if (clientSocket != INVALID_SOCKET) {
            handleClient(clientSocket);
        }
    }

    closesocket(serverSocket);
    WSACleanup();
    return 0;
}
