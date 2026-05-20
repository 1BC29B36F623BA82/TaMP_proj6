#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <mutex>
#include <sstream>

class Database {
private:
    std::string db_filename;
    std::mutex db_mutex;

    Database() {
        db_filename = "database.txt";
        std::cout << "[DB] Database initialized. File: " << db_filename << std::endl;
    }
    
    ~Database() {
        std::cout << "[DB] Database connection closed." << std::endl;
    }

    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    // Временная заглушка для хэширования пароля (потом заменишь на свой алгоритм SHA-1)
    std::string hashPassword(const std::string& password) {
        // Простейшая симуляция хэша для тестов
        return "HASH_" + password + "_SHA1";
    }

public:
    static Database& getInstance() {
        static Database instance;
        return instance;
    }

    // Проверка: существует ли уже пользователь с таким логином
    bool userExists(const std::string& username) {
        std::lock_guard<std::mutex> lock(db_mutex);
        std::ifstream file(db_filename);
        if (!file.is_open()) return false;

        std::string line;
        while (std::getline(file, line)) {
            size_t delim = line.find(':');
            if (delim != std::string::npos) {
                if (line.substr(0, delim) == username) {
                    return true; 
                }
            }
        }
        return false;
    }

    // РЕГИСТРАЦИЯ: сохраняем имя, хэш пароля и открытый ключ RSA
    bool registerUser(const std::string& username, const std::string& password, const std::string& rsaKey) {
        if (userExists(username)) {
            std::cout << "[DB] Registration failed: user " << username << " already exists." << std::endl;
            return false;
        }

        std::lock_guard<std::mutex> lock(db_mutex);
        std::ofstream file(db_filename, std::ios::app);
        if (!file.is_open()) return false;

        std::string passwordHash = hashPassword(password);

        // Формат хранения: login:password_hash:rsa_public_key
        file << username << ":" << passwordHash << ":" << rsaKey << "\n";
        file.close();
        
        std::cout << "[DB] User " << username << " successfully registered." << std::endl;
        return true;
    }

    // АВТОРИЗАЦИЯ: проверка логина и пароля
    bool authenticateUser(const std::string& username, const std::string& password) {
        std::lock_guard<std::mutex> lock(db_mutex);
        std::ifstream file(db_filename);
        if (!file.is_open()) return false;

        std::string expectedHash = hashPassword(password);
        std::string line;

        while (std::getline(file, line)) {
            std::stringstream ss(line);
            std::string u, h, k;
            if (std::getline(ss, u, ':') && std::getline(ss, h, ':') && std::getline(ss, k, ':')) {
                if (u == username && h == expectedHash) {
                    std::cout << "[DB] User " << username << " authenticated successfully." << std::endl;
                    return true;
                }
            }
        }
        std::cout << "[DB] Authentication failed for user " << username << std::endl;
        return false;
    }
};