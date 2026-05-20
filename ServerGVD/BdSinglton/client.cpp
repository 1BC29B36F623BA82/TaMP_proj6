#include <iostream>
#include <string>
#include <winsock2.h>

#pragma comment(lib, "ws2_32.lib")

void sendCommand(const std::string& message) {
    SOCKET sock = socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8080);
    serverAddr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(sock, (SOCKADDR*)&serverAddr, sizeof(serverAddr)) != SOCKET_ERROR) {
        send(sock, message.c_str(), message.length(), 0);
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
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2, 2), &wsaData);

    std::cout << "=== STARTING SERVER TESTS ===\n" << std::endl;

    // 1. Тест регистрации
    sendCommand("REG vasiliy_user my_secret_password RSA_KEY_ABC123\n");

    // 2. Тест повторной регистрации (должен выдать ошибку, так как юзер уже есть)
    sendCommand("REG vasiliy_user my_secret_password RSA_KEY_ABC123\n");

    // 3. Тест успешной авторизации
    sendCommand("AUTH vasiliy_user my_secret_password\n");

    // 4. Тест неверного пароля
    sendCommand("AUTH vasiliy_user wrong_password\n");

    // 5. Тест заглушки шифрования текста в аудио
    sendCommand("ENCRYPT SecretMessage track1.wav\n");

    // 6. Тест заглушки извлечения текста из аудио
    sendCommand("DECRYPT track1.wav\n");

    WSACleanup();
    return 0;
}