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

// RSA-ключи (генерируются один раз при запуске)

/// @cond INTERNAL
/// Статическая пара ключей RSA. p=61, q=53 → n=3233, e=17, d=2753.
static const RSAKeyPair g_rsa_keys = generate_keys(61, 53);

/// Фиксированный пароль для позиционирования бит в стеганографии (SHA-1 seed).
static const std::string g_steg_password = "my_secret_server_key";

static std::string getWavDir()
{
    std::filesystem::path current = std::filesystem::current_path();
    for (int i = 0; i < 5; ++i) {
        std::filesystem::path wavPath = current / "src" / "wav";
        if (std::filesystem::exists(wavPath)) {
            std::string pathStr = wavPath.string();
            for (char &c : pathStr)
                if (c == '/') c = '\\';
            pathStr += "\\";
            qDebug() << "[getWavDir] Found wav directory:" << QString::fromStdString(pathStr);
            return pathStr;
        }
        current = current.parent_path();
        if (current == current.parent_path()) break;
    }
    qDebug() << "[getWavDir] WAV directory not found, using relative path";
    return "..\\..\\src\\wav\\";
}

static const std::string g_wav_dir = getWavDir();
/// @endcond

// Вспомогательные функции

/**
 * @brief Конвертация бинарных данных в hex-строку QString.
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
 * @brief Конвертация hex-строки в бинарные данные.
 * @param hex Hex-строка (длина должна быть чётной)
 * @return Бинарная строка или пустая строка при ошибке формата
 */
static std::string hexToBytes(const QString &hex)
{
    std::string result;
    if (hex.size() % 2 != 0) return result;
    auto hexVal = [](QChar c) -> int {
        char ch = c.toLatin1();
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        return -1;
    };
    for (int i = 0; i < hex.size(); i += 2) {
        int h = hexVal(hex[i]);
        int l = hexVal(hex[i + 1]);
        if (h < 0 || l < 0) return {};
        result.push_back(static_cast<char>((h << 4) | l));
    }
    return result;
}

// Реализация команд-обработчиков

/**
 * @brief RSA-шифрование строки payload.
 *
 * Каждый байт шифруется: c = m^e mod n.
 * Шифротекст сериализуется и возвращается как hex-строка.
 *
 * @param payload Открытый текст
 * @return "RSA_ENC: <hex>" или "RSA_ENC_ERR: ..."
 */
QString fn_rsa_encrypt(const QString &payload)
{
    if (payload.trimmed().isEmpty())
        return "RSA_ENC_ERR: empty payload\r\n";

    std::string plain = payload.toStdString();
    std::vector<uint64_t> cipher = rsa_encrypt(plain, g_rsa_keys.e, g_rsa_keys.n);
    std::string serialized = serialize_ciphertext(cipher);
    QString hexResult = bytesToHex(serialized);

    qDebug() << "[fn_rsa_encrypt] plaintext len:" << plain.size()
             << "-> cipher blocks:" << cipher.size();

    return "RSA_ENC: " + hexResult + "\r\n";
}

/**
 * @brief RSA-расшифрование hex-строки payload.
 *
 * Декодирует hex, десериализует шифротекст, расшифровывает: m = c^d mod n.
 *
 * @param payload Hex-строка шифротекста
 * @return "RSA_DEC: <текст>" или "RSA_DEC_ERR: ..."
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
             << "-> plaintext len:" << plaintext.size();

    return "RSA_DEC: " + QString::fromStdString(plaintext) + "\r\n";
}

/**
 * @brief SHA-1 хэширование строки payload.
 * @param payload Входная строка
 * @return "SHA1: <40-символьный hex>" или "SHA1_ERR: ..."
 */
QString fn_sha1(const QString &payload)
{
    if (payload.trimmed().isEmpty())
        return "SHA1_ERR: empty payload\r\n";

    std::string input = payload.toStdString();
    std::vector<unsigned char> hash = sha1(input);

    static const char hexChars[] = "0123456789abcdef";
    QString hexHash;
    hexHash.reserve(40);
    for (unsigned char b : hash) {
        hexHash.append(hexChars[b >> 4]);
        hexHash.append(hexChars[b & 0xF]);
    }

    qDebug() << "[fn_sha1] input:" << payload << "->" << hexHash;
    return "SHA1: " + hexHash + "\r\n";
}

/**
 * @brief Встраивание RSA-зашифрованного сообщения в WAV-файл.
 *
 * Формат: STEG <текст> <файл.wav>
 * Цепочка: текст → RSA → сериализация → LSB-стеганография (Ньютон + SHA-1).
 * Результат: src/wav/encrypted_<файл.wav>
 *
 * @param payload Строка "<текст> <файл.wav>"
 * @return "STEG: SUCCESS ..." или "STEG_ERR: ..."
 */
QString fn_steg(const QString &payload)
{
    QStringList parts = payload.trimmed().split(' ', Qt::SkipEmptyParts);
    if (parts.size() < 2)
        return "STEG_ERR: usage: STEG <text> <file.wav>\r\n";

    std::string text       = parts[0].toStdString();
    std::string filename   = parts[1].toStdString();
    std::string inputFile  = g_wav_dir + filename;
    std::string outputFile = g_wav_dir + "encrypted_" + filename;

    qDebug() << "[fn_steg] Looking for:" << QString::fromStdString(inputFile);

    WavHeader header;
    std::vector<int16_t> samples = read_wav(inputFile, header);
    if (samples.empty()) {
        qDebug() << "[fn_steg] ERROR: File not found or cannot read";
        return QString("STEG_ERR: cannot read %1\r\n").arg(QString::fromStdString(inputFile));
    }

    std::vector<uint64_t> cipher = rsa_encrypt(text, g_rsa_keys.e, g_rsa_keys.n);
    std::string cipherData = serialize_ciphertext(cipher);

    if (!embed_message(samples, cipherData, g_steg_password))
        return "STEG_ERR: file too small for this message\r\n";

    if (!write_wav(outputFile, samples, header))
        return QString("STEG_ERR: cannot write %1\r\n").arg(QString::fromStdString(outputFile));

    qDebug() << "[fn_steg] embedded" << text.size() << "bytes into"
             << QString::fromStdString(outputFile);

    return QString("STEG: SUCCESS -> %1\r\n").arg(QString::fromStdString(outputFile));
}

/**
 * @brief Извлечение и RSA-расшифрование сообщения из WAV-файла.
 *
 * Формат: deSTEG <файл.wav>
 * Цепочка: WAV → LSB-извлечение (SHA-1) → десериализация → RSA.
 *
 * @param payload Имя WAV-файла
 * @return "DESTEG: <текст>" или "DESTEG_ERR: ..."
 */
QString fn_desteg(const QString &payload)
{
    std::string filename  = payload.trimmed().toStdString();
    std::string inputFile = g_wav_dir + filename;

    WavHeader header;
    std::vector<int16_t> samples = read_wav(inputFile, header);
    if (samples.empty())
        return QString("DESTEG_ERR: cannot read %1\r\n").arg(QString::fromStdString(inputFile));

    std::string cipherData = extract_message(samples, g_steg_password);
    if (cipherData.empty())
        return "DESTEG_ERR: no message found (wrong file or password)\r\n";

    std::vector<uint64_t> cipher = deserialize_ciphertext(cipherData);
    if (cipher.empty())
        return "DESTEG_ERR: deserialization failed\r\n";

    std::string plaintext = rsa_decrypt(cipher, g_rsa_keys.d, g_rsa_keys.n);

    qDebug() << "[fn_desteg] extracted from" << QString::fromStdString(inputFile)
             << "->" << QString::fromStdString(plaintext);

    return "DESTEG: " + QString::fromStdString(plaintext) + "\r\n";
}

// Реализация MyTcpServer 

/**
 * @brief Конструктор: инициализирует БД, запускает QTcpServer на порту 33333.
 */
MyTcpServer::MyTcpServer(QObject *parent) : QObject(parent)
{
    qDebug() << "[Server] RSA keys: n=" << g_rsa_keys.n
             << "e=" << g_rsa_keys.e
             << "d=" << g_rsa_keys.d;
    qDebug() << "[Server] Working directory:"
             << QString::fromStdString(std::filesystem::current_path().string());
    qDebug() << "[Server] WAV directory:"
             << QString::fromStdString(g_wav_dir);

    // Дефолтный администратор
    mUserDatabase["admin"] = "admin123";
    mAdmins.insert("admin");

    mTcpServer = new QTcpServer(this);
    connect(mTcpServer, &QTcpServer::newConnection,
            this, &MyTcpServer::slotNewConnection);

    if (!mTcpServer->listen(QHostAddress::Any, 33333))
        qDebug() << "[Server] Failed to start on port 33333";
    else
        qDebug() << "[Server] Started on port 33333";
}

/**
 * @brief Деструктор: отключает всех клиентов и останавливает сервер.
 */
MyTcpServer::~MyTcpServer()
{
    for (QTcpSocket *client : mClientsInfo.keys())
        client->disconnectFromHost();
    mTcpServer->close();
}

/**
 * @brief Принимает входящие подключения.
 *
 * Проверяет бан по IP, создаёт ClientContext (роль Guest),
 * отправляет приветствие, подключает сигналы сокета.
 */
void MyTcpServer::slotNewConnection()
{
    while (mTcpServer->hasPendingConnections()) {
        QTcpSocket *clientSocket = mTcpServer->nextPendingConnection();
        QString clientIP = clientSocket->peerAddress().toString();

        if (mBannedIPs.contains(clientIP)) {
            clientSocket->write("ERR: Your IP is banned.\r\n");
            clientSocket->disconnectFromHost();
            clientSocket->deleteLater();
            continue;
        }

        mClientsInfo.insert(clientSocket, ClientContext());

        qDebug() << "[Server] New connection:" << clientIP << ":" << clientSocket->peerPort()
                 << "| Total:" << mClientsInfo.size();

        clientSocket->write("Hello! I am RSA+SHA1+Steganography server.\r\n");
        clientSocket->write("You are GUEST. Type HELP for commands.\r\n");

        connect(clientSocket, &QTcpSocket::readyRead,
                this, &MyTcpServer::slotServerRead);
        connect(clientSocket, &QTcpSocket::disconnected,
                this, &MyTcpServer::slotClientDisconnected);
    }
}

/**
 * @brief Читает запрос от клиента, разбирает команду, отправляет ответ.
 *
 * Таблица команд:
 * | Команда           | Роль          | Описание                        |
 * |-------------------|---------------|---------------------------------|
 * | REGISTER <u> <p>  | Guest+        | Регистрация                     |
 * | LOGIN <u> <p>     | Guest+        | Авторизация                     |
 * | WHOAMI            | Client+       | Имя и роль пользователя         |
 * | HISTORY [N]       | Client+       | Последние N команд сессии       |
 * | RSA <text>        | Client+       | RSA-шифрование                  |
 * | deRSA <hex>       | Client+       | RSA-расшифрование               |
 * | SHA1 <text>       | Client+       | SHA-1 хэш                       |
 * | STEG <t> <f>      | Admin         | Встроить в WAV                  |
 * | deSTEG <f>        | Admin         | Извлечь из WAV                  |
 * | LIST              | Admin         | Список подключений              |
 * | KICK <u>          | Admin         | Отключить пользователя          |
 * | BAN <u>           | Admin         | Забанить пользователя           |
 * | BANIP <ip>        | Admin         | Забанить IP                     |
 */
void MyTcpServer::slotServerRead()
{
    QTcpSocket *clientSocket = qobject_cast<QTcpSocket*>(sender());
    if (!clientSocket) return;

    QByteArray rawData = clientSocket->readAll();

    // Фильтруем Telnet IAC (0xFF)
    if (!rawData.isEmpty() && static_cast<unsigned char>(rawData[0]) == 0xFF)
        return;

    QString request = QString::fromUtf8(rawData).trimmed();
    if (request.isEmpty()) return;

    qDebug() << "[Server] From" << clientSocket->peerAddress().toString()
             << ":" << clientSocket->peerPort()
             << "| Req:" << request;

    QString response;
    ClientContext &ctx = mClientsInfo[clientSocket];
    QStringList parts  = request.split(' ', Qt::SkipEmptyParts);
    QString cmd        = parts.isEmpty() ? "" : parts[0].toUpper();

    // Записываем команду в историю (кроме служебных)
    if (cmd != "WHOAMI" && cmd != "HISTORY") {
        ctx.history.append(request);
        if (ctx.history.size() > ClientContext::MAX_HISTORY)
            ctx.history.removeFirst();
    }

    // Команды доступные всем (включая Guest)

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
                response = "SUCCESS: Registered. Now LOGIN.\r\n";
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
                clientSocket->write("ERR: This account is banned.\r\n");
                clientSocket->disconnectFromHost();
                return;
            }

            if (mUserDatabase.contains(user) && mUserDatabase[user] == pass) {
                ctx.username = user;
                ctx.role     = mAdmins.contains(user) ? AppRole::Server : AppRole::Client;
                QString roleStr = (ctx.role == AppRole::Server) ? "ADMIN" : "CLIENT";
                response = QString("SUCCESS: Logged in as %1 [%2]\r\n").arg(user).arg(roleStr);
            } else {
                response = "ERR: Invalid username or password.\r\n";
            }
        }
    }
    else if (cmd == "HELP") {
        if (ctx.role == AppRole::Server) {
            response =
                "Commands (ADMIN):\r\n"
                "  REGISTER <u> <p>   — create account\r\n"
                "  LOGIN <u> <p>      — log in\r\n"
                "  WHOAMI             — show your name and role\r\n"
                "  HISTORY            — last 10 commands\r\n"
                "  RSA <text>         — RSA encrypt\r\n"
                "  deRSA <hex>        — RSA decrypt\r\n"
                "  SHA1 <text>        — SHA-1 hash\r\n"
                "  STEG <text> <file> — embed into WAV [ADMIN]\r\n"
                "  deSTEG <file>      — extract from WAV [ADMIN]\r\n"
                "  LIST               — connected users [ADMIN]\r\n"
                "  KICK <username>    — disconnect user [ADMIN]\r\n"
                "  BAN <username>     — ban user [ADMIN]\r\n"
                "  BANIP <ip>         — ban IP [ADMIN]\r\n";
        } else {
            response =
                "Commands:\r\n"
                "  REGISTER <u> <p>  — create account\r\n"
                "  LOGIN <u> <p>     — log in\r\n"
                "  WHOAMI            — show your name and role\r\n"
                "  HISTORY           — last 10 commands\r\n"
                "  RSA <text>        — RSA encrypt\r\n"
                "  deRSA <hex>       — RSA decrypt\r\n"
                "  SHA1 <text>       — SHA-1 hash\r\n";
        }
    }

    // Команды для авторизованных пользователей (Client+) 

    else if (cmd == "WHOAMI") {
        /**
         * Возвращает логин и роль текущего пользователя.
         * Доступна всем, включая Guest (покажет Anonymous [GUEST]).
         */
        QString roleStr;
        switch (ctx.role) {
            case AppRole::Server: roleStr = "ADMIN";  break;
            case AppRole::Client: roleStr = "CLIENT"; break;
            default:              roleStr = "GUEST";  break;
        }
        response = QString("You are: %1 [%2]\r\n").arg(ctx.username).arg(roleStr);
    }
    else if (cmd == "HISTORY") {
        /**
         * Выводит последние N команд сессии (WHOAMI и HISTORY не включаются).
         * Синтаксис: HISTORY [N], где N от 1 до MAX_HISTORY (по умолчанию 10).
         */
        int n = 10;
        if (parts.size() >= 2)
            n = qBound(1, parts[1].toInt(), ClientContext::MAX_HISTORY);

        if (ctx.history.isEmpty()) {
            response = "HISTORY: no commands yet.\r\n";
        } else {
            QList<QString> slice = ctx.history.mid(qMax(0, ctx.history.size() - n));
            response = QString("--- Last %1 commands ---\r\n").arg(slice.size());
            for (int i = 0; i < slice.size(); ++i)
                response += QString("%1. %2\r\n").arg(i + 1).arg(slice[i]);
        }
    }
    else if (cmd == "RSA" || cmd == "DERSA" || cmd == "SHA1") {
        if (ctx.role == AppRole::Guest) {
            response = "ERR: Please LOGIN or REGISTER first.\r\n";
        } else {
            if (cmd == "RSA")   response = fn_rsa_encrypt(request.mid(4));
            if (cmd == "DERSA") response = fn_rsa_decrypt(request.mid(6));
            if (cmd == "SHA1")  response = fn_sha1(request.mid(5));
        }
    }

    //  Команды только для администраторов 

    else if (cmd == "LIST" || cmd == "KICK" || cmd == "BAN" ||
             cmd == "BANIP" || cmd == "STEG" || cmd == "DESTEG")
    {
        if (ctx.role != AppRole::Server) {
            response = "ERR: Access denied. ADMIN role required.\r\n";
        }
        else if (cmd == "LIST") {
            response = "--- Connected clients ---\r\n";
            for (auto it = mClientsInfo.begin(); it != mClientsInfo.end(); ++it) {
                QTcpSocket *sock = it.key();
                const ClientContext &c = it.value();
                QString roleStr = (c.role == AppRole::Server) ? "ADMIN"
                                : (c.role == AppRole::Client)  ? "CLIENT" : "GUEST";
                response += QString("%1:%2 - %3 [%4]\r\n")
                                .arg(sock->peerAddress().toString())
                                .arg(sock->peerPort())
                                .arg(c.username)
                                .arg(roleStr);
            }
        }
        else if (cmd == "KICK" && parts.size() >= 2) {
            QString target = parts[1];
            bool found = false;
            for (auto it = mClientsInfo.begin(); it != mClientsInfo.end(); ++it) {
                if (it.value().username == target) {
                    it.key()->write("You have been kicked.\r\n");
                    it.key()->disconnectFromHost();
                    found = true;
                }
            }
            response = found ? "SUCCESS: User kicked.\r\n" : "ERR: User not found.\r\n";
        }
        else if (cmd == "BAN" && parts.size() >= 2) {
            QString target = parts[1];
            mBannedUsers.insert(target);
            for (auto it = mClientsInfo.begin(); it != mClientsInfo.end(); ++it) {
                if (it.value().username == target) {
                    it.key()->write("You have been BANNED.\r\n");
                    it.key()->disconnectFromHost();
                }
            }
            response = "SUCCESS: User banned.\r\n";
        }
        else if (cmd == "BANIP" && parts.size() >= 2) {
            QString target = parts[1];
            mBannedIPs.insert(target);
            for (auto it = mClientsInfo.begin(); it != mClientsInfo.end(); ++it) {
                if (it.key()->peerAddress().toString() == target) {
                    it.key()->write("Your IP has been BANNED.\r\n");
                    it.key()->disconnectFromHost();
                }
            }
            response = "SUCCESS: IP banned.\r\n";
        }
        else if (cmd == "STEG")   response = fn_steg(request.mid(5));
        else if (cmd == "DESTEG") response = fn_desteg(request.mid(7));
    }

    // Эхо по умолчанию 

    else {
        response = "Echo: " + request + "\r\n";
    }

    if (!response.isEmpty())
        clientSocket->write(response.toUtf8());
}

/**
 * @brief Удаляет отключившегося клиента из  и освобождает сокет.
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