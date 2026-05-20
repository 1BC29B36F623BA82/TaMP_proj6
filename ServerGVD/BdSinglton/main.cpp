#include <iostream>
#include <string>
#include <sstream>
#include <winsock2.h> // Нативные сокеты Windows
#include "Database.hpp"

// Указываем линкеру, что нам нужна библиотека сокетов
#pragma comment(lib, "ws2_32.lib")

void handleClient(SOCKET clientSocket) {
    char buffer[1024] = {0};
    int bytesReceived = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);
    
    if (bytesReceived > 0) {
        std::string request(buffer);
        std::cout << "[Сервер] Получен запрос:\n" << request << std::endl;

        std::stringstream ss(request);
        std::string command, username, key;
        
        // Ожидаем формат команды: REG имя_пользователя открытый_ключ
        // Или: GET имя_пользователя
        ss >> command >> username;

        std::string response;

        if (command == "REG") {
            ss >> key; // Читаем ключ
            // Использование СИНГЛТОНА БД:
            if (Database::getInstance().saveUser(username, key)) {
                response = "SUCCESS: User registered\n";
            } else {
                response = "ERROR: DB error\n";
            }
        } 
        else if (command == "GET") {
            // Использование СИНГЛТОНА БД:
            std::string userKey = Database::getInstance().getUserKey(username);
            response = "KEY: " + userKey + "\n";
        } 
        else {
            response = "ERROR: Unknown command. Use REG or GET\n";
        }

        // Отправляем ответ клиенту
        send(clientSocket, response.c_str(), response.length(), 0);
    }
    closesocket(clientSocket);
}

int main() {
    // Настройка русской локали для консоли Windows
    setlocale(LC_ALL, "Russian");

    WSADATA wsaData;
    // Инициализация Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "[Ошибка] Не удалось инициализировать Winsock" << std::endl;
        return 1;
    }

    // Создание сокета сервера
    SOCKET serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket == INVALID_SOCKET) {
        std::cerr << "[Ошибка] Не удалось создать сокет" << std::endl;
        WSACleanup();
        return 1;
    }

    sockaddr_in serverService;
    serverService.sin_family = AF_INET;
    serverService.sin_addr.s_addr = inet_addr("127.0.0.1"); // Локальный адрес
    serverService.sin_port = htons(8080);                  // Порт 8080

    // Привязка сокета
    if (bind(serverSocket, (SOCKADDR*)&serverService, sizeof(serverService)) == SOCKET_ERROR) {
        std::cerr << "[Ошибка] bind упал с ошибкой" << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    // Слушаем порт
    if (listen(serverSocket, 1) == SOCKET_ERROR) {
        std::cerr << "[Ошибка] listen: Ошибка прослушивания порта" << std::endl;
        closesocket(serverSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "[Сервер] Запущен на порту 8080. Ожидание подключений..." << std::endl;

    // Простейший бесконечный цикл обработки одного подключения
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
//Developer Command Prompt for VS