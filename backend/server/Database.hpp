/**
 * @file Database.hpp
 * @brief Singleton-класс для работы с текстовой базой данных пользователей.
 *
 * Формат хранения (файл database.txt):
 *   login:sha1_hash_пароля:rsa_public_key
 *
 * Пароли хэшируются алгоритмом SHA-1 перед сохранением.
 * Потокобезопасность обеспечивается мьютексом.
 */
#pragma once
#include <iostream>
#include <fstream>
#include <string>
#include <mutex>
#include <sstream>
#include "sha1.h"

class Database {
private:
    std::string db_filename;  // путь к файлу базы данных
    std::mutex db_mutex;      // мьютекс для потокобезопасности

    /// Приватный конструктор (паттерн Singleton)
    Database() {
        db_filename = "database.txt";
        std::cout << "[DB] Database initialized. File: " << db_filename << std::endl;
    }

    ~Database() {
        std::cout << "[DB] Database connection closed." << std::endl;
    }

    // Запрет копирования и присваивания (Singleton)
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    /**
     * @brief Хэширование пароля алгоритмом SHA-1.
     *
     * Вычисляет SHA-1 хэш от строки пароля и возвращает его
     * в виде 40-символьной шестнадцатеричной строки.
     * Например: "password" → "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
     *
     * @param password Исходный пароль
     * @return 40-символьная hex-строка SHA-1 хэша
     */
    std::string hashPassword(const std::string& password) {
        std::vector<unsigned char> hash = sha1(password);
        const char* hex = "0123456789abcdef";
        std::string result;
        for (unsigned char byte : hash) {
            result.push_back(hex[byte >> 4]);   // старший полубайт
            result.push_back(hex[byte & 0xF]);  // младший полубайт
        }
        return result;
    }

public:
    /// Получение единственного экземпляра базы данных (Singleton)
    static Database& getInstance() {
        static Database instance;
        return instance;
    }

    /**
     * @brief Проверка существования пользователя по логину.
     *
     * Читает файл построчно и сравнивает поле до первого ':' с username.
     *
     * @param username Логин для проверки
     * @return true — пользователь найден, false — не найден
     */
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

    /**
     * @brief Регистрация нового пользователя.
     *
     * Проверяет уникальность логина, хэширует пароль через SHA-1
     * и записывает в файл в формате: login:sha1_hash:rsa_public_key
     *
     * @param username Логин
     * @param password Пароль (будет захэширован SHA-1)
     * @param rsaKey Открытый ключ RSA (строковое представление)
     * @return true — регистрация успешна, false — пользователь уже существует
     */
    bool registerUser(const std::string& username, const std::string& password, const std::string& rsaKey) {
        if (userExists(username)) {
            std::cout << "[DB] Registration failed: user " << username << " already exists." << std::endl;
            return false;
        }

        std::lock_guard<std::mutex> lock(db_mutex);
        std::ofstream file(db_filename, std::ios::app);
        if (!file.is_open()) return false;

        // Хэшируем пароль через SHA-1
        std::string passwordHash = hashPassword(password);

        // Формат: login:password_hash:rsa_public_key
        file << username << ":" << passwordHash << ":" << rsaKey << "\n";
        file.close();

        std::cout << "[DB] User " << username << " successfully registered." << std::endl;
        return true;
    }

    /**
     * @brief Авторизация пользователя.
     *
     * Хэширует введённый пароль SHA-1 и сравнивает с хэшем в базе.
     *
     * @param username Логин
     * @param password Пароль (будет захэширован и сравнён с хранимым хэшем)
     * @return true — авторизация успешна, false — неверный логин или пароль
     */
    bool authenticateUser(const std::string& username, const std::string& password) {
        std::lock_guard<std::mutex> lock(db_mutex);
        std::ifstream file(db_filename);
        if (!file.is_open()) return false;

        // Хэшируем введённый пароль для сравнения
        std::string expectedHash = hashPassword(password);
        std::string line;

        while (std::getline(file, line)) {
            std::stringstream ss(line);
            std::string u, h, k;
            // Разбираем строку: login:hash:rsa_key
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
