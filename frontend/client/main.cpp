/**
 * @file main.cpp
 * @brief Тестовый TCP-клиент для проверки серверных команд.
 *
 * Последовательно отправляет серверу команды:
 *   1. REG     — регистрация пользователя
 *   2. REG     — повторная регистрация (ожидается ошибка)
 *   3. AUTH    — авторизация с верным паролем
 *   4. AUTH    — авторизация с неверным паролем
 *   5. ENCRYPT — шифрование текста в WAV-файл
 *   6. DECRYPT — извлечение текста из WAV-файла
 */

#include <iostream>
#include <string>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

/**
 * @brief Отправка одной команды серверу и получение ответа.
 *
 * Создаёт TCP-соединение с сервером (127.0.0.1:8080),
 * отправляет сообщение, читает ответ и выводит его в консоль.
 *
 * @param message Текст команды для отправки
 */
void sendCommand(const std::string& message) {
    // Создаём TCP-сокет
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8080);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    // Подключаемся к серверу
    if (connect(sock, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) != SOCKET_ERROR) {
        // Отправляем команду
        send(sock, message.c_str(), message.length(), 0);

        // Получаем ответ
        char buffer[1024] = {0};
        recv(sock, buffer, sizeof(buffer) - 1, 0);

        std::cout << "-> Request: " << message;
        std::cout << "<- Response: " << buffer << std::endl;
    } else {
        std::cout << "[ERROR] Could not connect to server. Is server.exe running?" << std::endl;
    }
    closesocket(sock);
}

int main() {
    // Инициализация Winsock
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    std::cout << "=== STARTING SERVER TESTS ===\n" << std::endl;

    // 1. Тест регистрации нового пользователя
    sendCommand("REG vasiliy_user my_secret_password RSA_KEY_ABC123\n");

    // 2. Тест повторной регистрации (должна вернуть ошибку — пользователь уже существует)
    sendCommand("REG vasiliy_user my_secret_password RSA_KEY_ABC123\n");

    // 3. Тест успешной авторизации (верный пароль)
    sendCommand("AUTH vasiliy_user my_secret_password\n");

    // 4. Тест неудачной авторизации (неверный пароль)
    sendCommand("AUTH vasiliy_user wrong_password\n");

    // 5. Тест шифрования текста в WAV-файл (RSA + стеганография)
    sendCommand("ENCRYPT SecretMessage track1.wav\n");

    // 6. Тест извлечения текста из WAV-файла (стеганография + RSA)
    sendCommand("DECRYPT track1.wav\n");

    WSACleanup();
    return 0;
}

