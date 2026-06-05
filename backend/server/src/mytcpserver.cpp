/**
 * @file mytcpserver.cpp
 * @brief Реализация TCP-сервера и команд-обработчиков.
 *
 * Обработчики команд (fn_*) — тонкая обёртка между Qt-строками и
 * C++ реализациями из rsa.cpp / sha1.cpp / steganography.cpp / wav_handler.cpp.
 *
 * Статические RSA-ключи (p=61, q=53 → n=3233) генерируются один раз
 * при загрузке модуля и переиспользуются всеми командами.
 */

#include "mytcpserver.h"
#include "rsa.h"
#include "sha1.h"
#include "steganography.h"
#include "wav_handler.h"

#include <QCoreApplication>
#include <QString>
#include <QStringList>

#include <vector>
#include <string>
#include <cstdint>
#include <filesystem>

// ─── RSA-ключи (генерируются один раз при запуске) ──────────────────────────

/// @cond INTERNAL
/// Статическая пара ключей RSA. p=61, q=53 → n=3233, e=17, d=2753.
static const RSAKeyPair g_rsa_keys = generate_keys(61, 53);

/// Фиксированный пароль для позиционирования бит в стеганографии (SHA-1 seed).
static const std::string g_steg_password = "my_secret_server_key";

/// Инициализирует и возвращает путь до папки с WAV-файлами
static std::string getWavDir()
{
    // Попытка найти папку src/wav относительно рабочей директории
    std::filesystem::path current = std::filesystem::current_path();
    
    // Попытка подняться на разные уровни и найти папку src/wav
    for (int i = 0; i < 5; ++i) {
        std::filesystem::path wavPath = current / "src" / "wav";
        if (std::filesystem::exists(wavPath)) {
            std::string pathStr = wavPath.string();
            for (char &c : pathStr) {
                if (c == '/') c = '\\';
            }
            pathStr += "\\";
            qDebug() << "[getWavDir] Found wav directory:" << QString::fromStdString(pathStr);
            return pathStr;
        }
        current = current.parent_path();
        if (current == current.parent_path()) break;  // достигли корня
    }
    
    qDebug() << "[getWavDir] WAV directory not found, using relative path";
    return "..\\..\\src\\wav\\";
}

static const std::string g_wav_dir = getWavDir();
/// @endcond

// ─── Вспомогательные функции ─────────────────────────────────────────────────

/**
 * @brief Конвертация вектора байт в hex-строку QString.
 *
 * Используется для представления бинарных данных (шифротекст, хэш)
 * в виде, пригодном для передачи по TCP как текст.
 *
 * @param bytes Бинарные данные
 * @return Hex-строка, по 2 символа на байт
 */
static QString bytesToHex(const std::string &bytes)
{
    static const char hex[] = "0123456789abcdef";
    QString result;
    result.reserve(static_cast<int>(bytes.size()) * 2);
    for (unsigned char b : bytes) {
        result.append(hex[b >> 4]);
        result.append(hex[b & 0xF]);
    }
    return result;
}

/**
 * @brief Конвертация hex-строки обратно в бинарные данные.
 *
 * @param hex Hex-строка (длина должна быть чётной)
 * @return Бинарная строка или пустая строка при ошибке формата
 */
static std::string hexToBytes(const QString &hex)
{
    std::string result;
    if (hex.size() % 2 != 0) return result;
    for (int i = 0; i < hex.size(); i += 2) {
        auto hexVal = [](QChar c) -> int {
            char ch = c.toLatin1();
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
            if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
            return -1;
        };
        int h = hexVal(hex[i]);
        int l = hexVal(hex[i + 1]);
        if (h < 0 || l < 0) return {};
        result.push_back(static_cast<char>((h << 4) | l));
    }
    return result;
}

// ─── Реализация команд-обработчиков ──────────────────────────────────────────

/**
 * @brief RSA-шифрование строки payload.
 *
 * Шаги:
 *   1. Конвертируем QString → std::string (UTF-8)
 *   2. Шифруем побайтово: c = m^e mod n
 *   3. Сериализуем вектор блоков в бинарную строку
 *   4. Кодируем hex для передачи по TCP
 *
 * @param payload Открытый текст (Qt строка)
 * @return Hex-строка шифротекста с префиксом "RSA_ENC: " или "RSA_ENC_ERR: ..."
 */
QString fn_rsa_encrypt(const QString &payload)
{
    if (payload.trimmed().isEmpty())
        return "RSA_ENC_ERR: empty payload\r\n";

    std::string plain = payload.toStdString();

    // Шифруем каждый байт: c = m^e mod n
    std::vector<uint64_t> cipher = rsa_encrypt(plain, g_rsa_keys.e, g_rsa_keys.n);

    // Сериализуем и кодируем в hex для текстовой передачи
    std::string serialized = serialize_ciphertext(cipher);
    QString hexResult = bytesToHex(serialized);

    qDebug() << "[fn_rsa_encrypt] plaintext len:" << plain.size()
             << "→ cipher blocks:" << cipher.size();

    return "RSA_ENC: " + hexResult + "\r\n";
}

/**
 * @brief RSA-расшифрование hex-строки payload.
 *
 * Шаги:
 *   1. Декодируем hex → бинарные данные
 *   2. Десериализуем в вектор блоков
 *   3. Расшифровываем: m = c^d mod n
 *
 * @param payload Hex-строка (результат fn_rsa_encrypt без префикса)
 * @return Расшифрованный текст с префиксом "RSA_DEC: " или "RSA_DEC_ERR: ..."
 */
QString fn_rsa_decrypt(const QString &payload)
{
    if (payload.trimmed().isEmpty())
        return "RSA_DEC_ERR: empty payload\r\n";

    std::string binData = hexToBytes(payload.trimmed());
    if (binData.empty())
        return "RSA_DEC_ERR: invalid hex data\r\n";

    std::vector<uint64_t> cipher = deserialize_ciphertext(binData);
    if (cipher.empty())
        return "RSA_DEC_ERR: deserialization failed\r\n";

    std::string plaintext = rsa_decrypt(cipher, g_rsa_keys.d, g_rsa_keys.n);

    qDebug() << "[fn_rsa_decrypt] cipher blocks:" << cipher.size()
             << "→ plaintext len:" << plaintext.size();

    return "RSA_DEC: " + QString::fromStdString(plaintext) + "\r\n";
}

/**
 * @brief SHA-1 хэширование строки payload.
 *
 * @param payload Входная строка
 * @return "SHA1: <40-символьный hex>" или "SHA1_ERR: ..."
 */
QString fn_sha1(const QString &payload)
{
    if (payload.trimmed().isEmpty())
        return "SHA1_ERR: empty payload\r\n";

    std::string input = payload.toStdString();
    std::vector<unsigned char> hash = sha1(input);

    // Переводим 20 байт в 40-символьный hex
    static const char hexChars[] = "0123456789abcdef";
    QString hexHash;
    hexHash.reserve(40);
    for (unsigned char b : hash) {
        hexHash.append(hexChars[b >> 4]);
        hexHash.append(hexChars[b & 0xF]);
    }

    qDebug() << "[fn_sha1] input:" << payload << "→" << hexHash;

    return "SHA1: " + hexHash + "\r\n";
}

/**
 * @brief Встраивание RSA-зашифрованного сообщения в WAV-файл.
 *
 * Формат команды: STEG <текст> <файл.wav>
 * Результат пишется в ./wav/encrypted_<файл.wav>.
 *
 * Цепочка обработки:
 *   Текст → RSA-шифрование → сериализация → LSB-стеганография
 *   (позиции бит определяются SHA-1 от g_steg_password)
 *
 * @param payload Строка "<текст> <файл.wav>"
 * @return "STEG: SUCCESS ..." или "STEG_ERR: ..."
 */
QString fn_steg(const QString &payload)
{
    // Разбиваем payload: первое слово — текст, второе — имя файла
    // Формат: "<текст_без_пробелов> <файл.wav>"
    QStringList parts = payload.trimmed().split(' ', Qt::SkipEmptyParts);
    if (parts.size() < 2)
        return "STEG_ERR: usage: STEG <text> <file.wav>\r\n";

    std::string text     = parts[0].toStdString();
    std::string filename = parts[1].toStdString();
    std::string inputFile  = g_wav_dir + filename;
    std::string outputFile = g_wav_dir + "encrypted_" + filename;

    qDebug() << "[fn_steg] Looking for:" << QString::fromStdString(inputFile);

    // 1. Читаем WAV
    WavHeader header;
    std::vector<int16_t> samples = read_wav(inputFile, header);
    if (samples.empty()) {
        qDebug() << "[fn_steg] ERROR: File not found or cannot read";
        return QString("STEG_ERR: cannot read %1\r\n").arg(QString::fromStdString(inputFile));
    }

    // 2. RSA-шифрование текста
    std::vector<uint64_t> cipher = rsa_encrypt(text, g_rsa_keys.e, g_rsa_keys.n);
    std::string cipherData = serialize_ciphertext(cipher);

    // 3. Встраиваем в сэмплы (метод Ньютона + SHA-1 для позиций)
    if (!embed_message(samples, cipherData, g_steg_password))
        return "STEG_ERR: file too small for this message\r\n";

    // 4. Сохраняем результат
    if (!write_wav(outputFile, samples, header))
        return QString("STEG_ERR: cannot write %1\r\n").arg(QString::fromStdString(outputFile));

    qDebug() << "[fn_steg] embedded" << text.size() << "bytes into" << QString::fromStdString(outputFile);

    return QString("STEG: SUCCESS -> %1\r\n").arg(QString::fromStdString(outputFile));
}

/**
 * @brief Извлечение и RSA-расшифрование сообщения из WAV-файла.
 *
 * Формат команды: deSTEG <файл.wav>
 * Файл ищется в каталоге ./wav/.
 *
 * Цепочка обработки:
 *   WAV → извлечение LSB (SHA-1 для позиций) → десериализация → RSA-расшифрование
 *
 * @param payload Имя WAV-файла
 * @return "DESTEG: <текст>" или "DESTEG_ERR: ..."
 */
QString fn_desteg(const QString &payload)
{
    std::string filename  = payload.trimmed().toStdString();
    std::string inputFile = g_wav_dir + filename;

    // 1. Читаем WAV
    WavHeader header;
    std::vector<int16_t> samples = read_wav(inputFile, header);
    if (samples.empty())
        return QString("DESTEG_ERR: cannot read %1\r\n").arg(QString::fromStdString(inputFile));

    // 2. Извлекаем встроенные данные
    std::string cipherData = extract_message(samples, g_steg_password);
    if (cipherData.empty())
        return "DESTEG_ERR: no message found (wrong file or password)\r\n";

    // 3. Десериализуем шифротекст
    std::vector<uint64_t> cipher = deserialize_ciphertext(cipherData);
    if (cipher.empty())
        return "DESTEG_ERR: deserialization failed\r\n";

    // 4. RSA-расшифрование
    std::string plaintext = rsa_decrypt(cipher, g_rsa_keys.d, g_rsa_keys.n);

    qDebug() << "[fn_desteg] extracted from" << QString::fromStdString(inputFile)
             << "→" << QString::fromStdString(plaintext);

    return "DESTEG: " + QString::fromStdString(plaintext) + "\r\n";
}

// Реализация MyTcpServer

/**
 * @brief Конструктор: запускает QTcpServer на порту 33333.
 *
 * Выводит в лог сгенерированные RSA-ключи и рабочую директорию для отладки.
 */
MyTcpServer::MyTcpServer(QObject *parent) : QObject(parent)
{
    qDebug() << "[Server] RSA keys: n=" << g_rsa_keys.n
             << "e=" << g_rsa_keys.e
             << "d=" << g_rsa_keys.d;

    qDebug() << "[Server] Working directory:" << QString::fromStdString(std::filesystem::current_path().string());

    // Создаем дефолтного админа при старте
    mUserDatabase["admin"] = "admin123";
    mAdmins.insert("admin");

    mTcpServer = new QTcpServer(this);

    connect(mTcpServer, &QTcpServer::newConnection,
            this, &MyTcpServer::slotNewConnection);

    if (!mTcpServer->listen(QHostAddress::Any, 33333)) {
        qDebug() << "[Server] Failed to start on port 33333";
    } else {
        qDebug() << "[Server] Started on port 33333";
    }
}

/**
 * @brief Деструктор: корректно завершает все соединения.
 *
 * Вызывает disconnectFromHost() для каждого клиента,
 * затем останавливает QTcpServer.
 */
MyTcpServer::~MyTcpServer()
{
    for (QTcpSocket *client : mClientsInfo.keys()) {
        client->disconnectFromHost();
    }
    mTcpServer->close();
}

/**
 * @brief Принимает все ожидающие подключения.
 *
 * Для каждого нового клиента:
 *   - добавляет сокет в mClients
 *   - отправляет приветствие и список команд
 *   - подключает сигналы readyRead и disconnected
 */
void MyTcpServer::slotNewConnection()
{
    while (mTcpServer->hasPendingConnections()) {
        QTcpSocket *clientSocket = mTcpServer->nextPendingConnection();
        QString clientIP = clientSocket->peerAddress().toString();

        // Проверка на бан по IP
        if (mBannedIPs.contains(clientIP)) {
            qDebug() << "[Server] B locked connection from banned IP:" << clientIP;
            clientSocket->write("ERR: Your IP is banned.\r\n");
            clientSocket->disconnectFromHost();
            clientSocket->deleteLater();
            continue;
        }

        // Регистрация нового гостя
        mClientsInfo.insert(clientSocket, ClientContext());

        qDebug() << "[Server] New connection:" << clientIP << ":" << clientSocket->peerPort()
                 << "| Total:" << mClientsInfo.size();

        clientSocket->write("Hello! I am RSA+SHA1+Steganography server.\r\n");
        clientSocket->write("You are GUEST. Type HELP for commands. Please REGISTER or LOGIN.\r\n");

        connect(clientSocket, &QTcpSocket::readyRead,
                this, &MyTcpServer::slotServerRead);
        connect(clientSocket, &QTcpSocket::disconnected,
                this, &MyTcpServer::slotClientDisconnected);
    }
}

/**
 * @brief Читает запрос от клиента и отправляет ответ.
 *
 * Поддерживаемые команды (регистронезависимо):
 * | Команда          | Обработчик      | Описание                         |
 * |------------------|-----------------|----------------------------------|
 * | RSA <текст>      | fn_rsa_encrypt  | RSA-шифрование, ответ в hex      |
 * | deRSA <hex>      | fn_rsa_decrypt  | RSA-расшифрование из hex         |
 * | SHA1 <текст>     | fn_sha1         | SHA-1 хэш в hex                  |
 * | STEG <t> <f>     | fn_steg         | Встроить в WAV (./wav/<f>)       |
 * | deSTEG <f>       | fn_desteg       | Извлечь из WAV (./wav/<f>)       |
 * | HELP             | —               | Список команд                    |
 * | (всё остальное)  | —               | Эхо                              |
 *
 * Байты с первым байтом 0xFF (Telnet IAC) игнорируются.
 */
void MyTcpServer::slotServerRead()
{
    QTcpSocket *clientSocket = qobject_cast<QTcpSocket*>(sender());
    if (!clientSocket) return;

    QByteArray rawData = clientSocket->readAll();

    // Фильрация Telnet
    if (!rawData.isEmpty() && static_cast<unsigned char>(rawData[0]) == 0xFF)
        return;

    QString request = QString::fromUtf8(rawData).trimmed();
    if (request.isEmpty()) return;

    qDebug() << "[Server] From" << clientSocket->peerAddress().toString()
             << ":" << clientSocket->peerPort()
             << "| Req:" << request;

    QString response;
    ClientContext &ctx = mClientsInfo[clientSocket];
    QStringList parts = request.split(' ', Qt::SkipEmptyParts);
    QString cmd = parts.isEmpty() ? "" : parts[0].toUpper();

    if (cmd == "REGISTER") {
        if (parts.size() < 3) {
            response = "ERR: Usage: REGISTER <username> <password>\r\n";
        } else {
            QString user = parts[1];
            QString pass = parts[2];
            if (mUserDatabase.contains(user)) {
                response = "ERR: User already exists.\r\n";
            } else {
                mUserDatabase[user] = pass;
                response = "SUCCESS: Registered successfully. Now LOGIN.\r\n";
            }
        }
    }
    else if (cmd == "LOGIN") {
        if (parts.size() < 3) {
            response = "ERR: Usage: LOGIN <username> <password>\r\n";
        } else {
            QString user = parts[1];
            QString pass = parts[2];

            if (mBannedUsers.contains(user)) {
                response = "ERR: This account is banned.\r\n";
                clientSocket->write(response.toUtf8());
                clientSocket->disconnectFromHost();
                return;
            }

            if (mUserDatabase.contains(user) && mUserDatabase[user] == pass) {
                ctx.username = user;
                ctx.role = mAdmins.contains(user) ? AppRole::Server : AppRole::Client;
                response = QString("SUCCESS: Logged in as %1. Role: %2\r\n")
                               .arg(user)
                               .arg(ctx.role == AppRole::Server ? "ADMIN" : "CLIENT");
            } else {
                response = "ERR: Invalid username or password.\r\n";
            }
        }
    }
    else if (cmd == "HELP") {
        if (ctx.role != AppRole::Server) {
        response =
            "Commands:\r\n"
            "  REGISTER <u> <p>  — Create account\r\n"
            "  LOGIN <u> <p>     — Log in\r\n"
            "  RSA <text>        — Encrypt\r\n"
            "  deRSA <hex>       — Decrypt\r\n"
            "  SHA1 <text>       — Hash\r\n";
        }
        else {
        response =
        "Commands:\r\n"
        "  REGISTER <u > <p>  — Create account\r\n"
        "  LOGIN <u> <p>      — Log in\r\n"
        "  RSA <text>         — Encrypt\r\n"
        "  deRSA <hex>        — Decrypt\r\n"
        "  SHA1 <text>        — Hash\r\n"
        "  STEG <text> <file> — Embed [ADMIN ONLY]\r\n"
        "  deSTEG <file>      — Extract [ADMIN ONLY]\r\n"
        "  LIST               — Show connected users [ADMIN ONLY]\r\n"
        "  KICK <username>    — Disconnect user [ADMIN ONLY]\r\n"
        "  BAN <username>     — Ban user [ADMIN ONLY]\r\n"
        "  BANIP <ip>         — Ban IP address [ADMIN ONLY]\r\n";
        }
    }
    // ─── Команды только для Администраторов (Server) ─────────────────────────
    else if (cmd == "LIST" || cmd == "KICK" || cmd == "BAN" || cmd == "BANIP" || cmd == "DESTEG" || cmd == "STEG")
    {
        if (ctx.role != AppRole::Server) {
            response = "ERR: Access denied. ADMIN (Server) role required.\r\n";
        }
        else if (cmd == "LIST") {
            response = "--- Connected Clients ---\r\n";
            for (auto it = mClientsInfo.begin(); it != mClientsInfo.end(); ++it) {
                QTcpSocket *sock = it.key();
                ClientContext c = it.value();
                QString roleStr = (c.role == AppRole::Server) ? "ADMIN" : (c.role == AppRole::Client ? "CLIENT" : "GUEST");
                response += QString("%1:%2 - %3 [%4]\r\n")
                                .arg(sock->peerAddress().toString())
                                .arg(sock->peerPort())
                                .arg(c.username)
                                .arg(roleStr);
            }
        }
        else if (cmd == "KICK" && parts.size() >= 2) {
            QString targetUser = parts[1];
            bool found = false;
            for (auto it = mClientsInfo.begin(); it != mClientsInfo.end(); ++it) {
                if (it.value().username == targetUser) {
                    it.key()->write("You have been kicked by an admin.\r\n");
                    it.key()->disconnectFromHost();
                    found = true;
                }
            }
            response = found ? "SUCCESS: User kicked.\r\n" : "ERR: User not found online.\r\n";
        }
        else if (cmd == "BAN" && parts.size() >= 2) {
            QString targetUser = parts[1];
            mBannedUsers.insert(targetUser);
            // Сразу кикаем, если он онлайн
            for (auto it = mClientsInfo.begin(); it != mClientsInfo.end(); ++it) {
                if (it.value().username == targetUser) {
                    it.key()->write("You have been BANNED.\r\n");
                    it.key()->disconnectFromHost();
                }
            }
            response = "SUCCESS: User banned.\r\n";
        }
        else if (cmd == "BANIP" && parts.size() >= 2) {
            QString targetIP = parts[1];
            mBannedIPs.insert(targetIP);
            // Кикаем всех с этого IP
            for (auto it = mClientsInfo.begin(); it != mClientsInfo.end(); ++it) {
                if (it.key()->peerAddress().toString() == targetIP) {
                    it.key()->write("Your IP has been BANNED.\r\n");
                    it.key()->disconnectFromHost();
                }
            }
            response = "SUCCESS: IP banned.\r\n";
        }
        // Крипто-команды админа
        else if (cmd == "DESTEG") response = fn_desteg(request.mid(7));
        else if (cmd == "STEG")   response = fn_steg(request.mid(5));
    }
    //Функции для всех
    else if (cmd == "RSA" || cmd == "SHA1" || cmd == "DERSA") {
        if (ctx.role == AppRole::Guest) {
            response = "ERR: Please LOGIN or REGISTER first.\r\n";
        } else {
            if (cmd == "DERSA")  response = fn_rsa_decrypt(request.mid(6));
            if (cmd == "RSA")  response = fn_rsa_encrypt(request.mid(4));
            if (cmd == "SHA1") response = fn_sha1(request.mid(5));
        }
    }
    // Эхо по умолчанию
    else {
        response = "Echo: " + request + "\r\n";
    }

    if (!response.isEmpty()) {
        clientSocket->write(response.toUtf8());
    }
}

/**
 * @brief Удаляет отключившегося клиента и освобождает сокет.
 */
void MyTcpServer::slotClientDisconnected()
{
    QTcpSocket *clientSocket = qobject_cast<QTcpSocket*>(sender());
    if (!clientSocket) return;

    qDebug() << "[Server] Client disconnected:" << clientSocket->peerAddress().toString()
             << "User:" << mClientsInfo[clientSocket].username
             << "| Remaining:" << (mClientsInfo.size() - 1);

    mClientsInfo.remove(clientSocket);
    clientSocket->deleteLater();
}