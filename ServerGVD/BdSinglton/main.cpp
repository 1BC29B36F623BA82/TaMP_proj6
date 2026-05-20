#include <iostream>
#include <string>
#include <sstream>
#include <winsock2.h>
#include "Database.hpp"

#pragma comment(lib, "ws2_32.lib")

// --- ЗАГЛУШКИ ДЛЯ БУДУЩЕЙ СТЫКОВКИ С ОСНОВНОЙ ПРОГРАММОЙ ---

std::string placeholderEncrypt(const std::string& text, const std::string& audioPath) {
    std::cout << "[CORE] Calling RSA encryption & SHA-1 calculation..." << std::endl;
    std::cout << "[CORE] Inserting message into " << audioPath << " using Newton's method..." << std::endl;
    // Здесь потом будет вызов твоих функций
    return "SUCCESS: Message hidden in encrypted_" + audioPath;
}

std::string placeholderDecrypt(const std::string& audioPath) {
    std::cout << "[CORE] Extracting data from " << audioPath << " using Newton's method..." << std::endl;
    std::cout << "[CORE] Checking SHA-1 integrity and decrypting via RSA..." << std::endl;
    // Здесь потом будет вызов твоих функций
    return "DECRYPTED_TEXT: Hello, this is a secret message from audio!";
}

// -----------------------------------------------------------

void handleClient(SOCKET clientSocket) {
    char buffer[2048] = {0};
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    
    if (bytesReceived > 0) {
        std::string request(buffer);
        std::cout << "\n[Server] New request received:\n" << request << std::endl;

        std::stringstream ss(request);
        std::string command;
        ss >> command;

        std::string response;

        // 1. КОМАНДА РЕГИСТРАЦИИ: REG [логин] [пароль] [открытый_ключ_RSA]
        if (command == "REG") {
            std::string username, password, rsaKey;
            ss >> username >> password >> rsaKey;
            
            if (Database::getInstance().registerUser(username, password, rsaKey)) {
                response = "STATUS: REGISTER_SUCCESS\n";
            } else {
                response = "STATUS: REGISTER_FAILED (User might already exist)\n";
            }
        } 
        // 2. КОМАНДА АВТОРИЗАЦИИ: AUTH [логин] [пароль]
        else if (command == "AUTH") {
            std::string username, password;
            ss >> username >> password;

            if (Database::getInstance().authenticateUser(username, password)) {
                response = "STATUS: AUTH_SUCCESS\n";
            } else {
                response = "STATUS: AUTH_FAILED\n";
            }
        }
        // 3. ЗАГЛУШКА ШИФРОВАНИЯ: ENCRYPT [текст] [имя_аудио_файла]
        else if (command == "ENCRYPT") {
            std::string textToHide, audioFile;
            ss >> textToHide >> audioFile;
            
            // Вызываем заглушку бизнес-логики
            response = placeholderEncrypt(textToHide, audioFile) + "\n";
        }
        // 4. ЗАГЛУШКА РАСШИФРОВКИ: DECRYPT [имя_аудио_файла]
        else if (command == "DECRYPT") {
            std::string audioFile;
            ss >> audioFile;

            // Вызываем заглушку бизнес-логики
            response = placeholderDecrypt(audioFile) + "\n";
        }
        else {
            response = "STATUS: ERROR_UNKNOWN_COMMAND\n";
        }

        // Отправка ответа клиенту
        send(clientSocket, response.c_str(), response.length(), 0);
    }
    closesocket(clientSocket);
}

int main() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[Error] Winsock initialization failed." << std::endl;
        return 1;
    }

    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "[Error] Socket creation failed." << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in serverService;
    serverService.sin_family = AF_INET;
    serverService.sin_addr.s_addr = inet_addr("127.0.0.1");
    serverService.sin_port = htons(8080);

    if (bind(serverSocket, (SOCKADDR*)&serverService, sizeof(serverService)) == SOCKET_ERROR) {
        std::cerr << "[Error] Bind failed." << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    if (listen(serverSocket, 3) == SOCKET_ERROR) {
        std::cerr << "[Error] Listen failed." << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "[Server] Server is running on port 8080. Waiting for commands..." << std::endl;

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