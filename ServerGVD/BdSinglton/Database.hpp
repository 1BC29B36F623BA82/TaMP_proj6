#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <mutex>

class Database {
private:
    std::string db_filename;
    std::mutex db_mutex; // Защита для потокобезопасности

    // 1. Закрываем конструктор и деструктор
    Database() {
        db_filename = "database.txt";
        std::cout << "[DB] База данных инициализирована. Файл: " << db_filename << std::endl;
    }
    
    ~Database() {
        std::cout << "[DB] Соединение с базой данных закрыто." << std::endl;
    }

    // 2. Запрещаем копирование и присваивание
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

public:
    // 3. Глобальная точка доступа (Синглтон Майерса)
    static Database& getInstance() {
        static Database instance;
        return instance;
    }

    // Метод для сохранения пользователя и его RSA ключа
    bool saveUser(const std::string& username, const std::string& rsaPublicKey) {
        // Захватываем мьютекс, чтобы одновременно пишущие потоки сервера не сломали файл
        std::lock_guard<std::mutex> lock(db_mutex);

        // Открываем файл в режиме добавления (ios::app)
        std::ofstream file(db_filename, std::ios::app);
        if (!file.is_open()) {
            std::cerr << "[DB Ошибка] Не удалось открыть файл базы данных!" << std::endl;
            return false;
        }

        // Записываем данные в формате: имя:ключ
        file << username << ":" << rsaPublicKey << "\n";
        file.close();
        
        std::cout << "[DB] Пользователь " << username << " успешно сохранен." << std::endl;
        return true;
    }

    // Метод для чтения ключа пользователя
    std::string getUserKey(const std::string& username) {
        std::lock_guard<std::mutex> lock(db_mutex);
        std::ifstream file(db_filename);
        if (!file.is_open()) return "";

        std::string line;
        while (std::getline(file, line)) {
            size_t delimiter = line.find(':');
            if (delimiter != std::string::npos) {
                std::string current_user = line.substr(0, delimiter);
                if (current_user == username) {
                    return line.substr(delimiter + 1); // Возвращаем ключ
                }
            }
        }
        return "Пользователь не найден";
    }
};