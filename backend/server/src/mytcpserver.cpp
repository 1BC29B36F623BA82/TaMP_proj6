#include "mytcpserver.h"
#include "rsa.h"
#include "sha1.h"
#include "steganography.h"
#include "wav_handler.h"

#include <QCoreApplication>
#include <QString>
#include <QStringList>
#include <cmath>
#include <vector>
#include <string>

// Фиксированная пара RSA-ключей сервера: p=61, q=53 -> n=3233, e=17, d=2753.
static const RSAKeyPair gServerKeys = generate_keys(61, 53);

static QString toHex(const std::vector<unsigned char> &bytes) {
    static const char *hex = "0123456789abcdef";
    QString out;
    out.reserve(static_cast<int>(bytes.size()) * 2);
    for (unsigned char b : bytes) {
        out.append(hex[(b >> 4) & 0xF]);
        out.append(hex[b & 0xF]);
    }
    return out;
}

// SHA1 <текст> -> 40-символьный hex-дайджест
QString fn_sha1(const QString &payload) {
    const QString text = payload.trimmed();
    if (text.isEmpty())
        return "SHA1_ERR: empty input. Usage: SHA1 <text>\r\n";

    std::vector<unsigned char> digest = sha1(text.toStdString());
    return "SHA1: " + toHex(digest) + "\r\n";
}

// RSA <текст> -> зашифрованные блоки через пробел
QString fn_rsa_encrypt(const QString &payload) {
    const QString text = payload.trimmed();
    if (text.isEmpty())
        return "RSA_ERR: empty input. Usage: RSA <text>\r\n";

    std::vector<uint64_t> cipher =
        rsa_encrypt(text.toStdString(), gServerKeys.e, gServerKeys.n);

    QStringList blocks;
    for (uint64_t c : cipher)
        blocks << QString::number(c);

    return "RSA(n=" + QString::number(gServerKeys.n) +
           ",e=" + QString::number(gServerKeys.e) + "): " +
           blocks.join(' ') + "\r\n";
}

// deRSA <b1> <b2> ... -> расшифрованный текст
QString fn_rsa_decrypt(const QString &payload) {
    const QString text = payload.trimmed();
    if (text.isEmpty())
        return "deRSA_ERR: empty input. Usage: deRSA <block1> <block2> ...\r\n";

    const QStringList parts = text.split(QRegularExpression("[\\s,]+"),
                                         Qt::SkipEmptyParts);
    std::vector<uint64_t> cipher;
    cipher.reserve(parts.size());
    for (const QString &p : parts) {
        bool ok = false;
        qulonglong v = p.toULongLong(&ok);
        if (!ok)
            return "deRSA_ERR: '" + p + "' is not a number\r\n";
        cipher.push_back(static_cast<uint64_t>(v));
    }

    std::string plain = rsa_decrypt(cipher, gServerKeys.d, gServerKeys.n);
    return "deRSA: " + QString::fromStdString(plain) + "\r\n";
}

// NEWTON <sample> <bit> -> ближайший int16 c заданным LSB методом Ньютона.
QString fn_newton(const QString &payload) {
    const QStringList parts = payload.trimmed()
            .split(QRegularExpression("[\\s,]+"), Qt::SkipEmptyParts);
    if (parts.size() != 2)
        return "NEWTON_ERR: Usage: NEWTON <sample:-32768..32767> <bit:0|1>\r\n";

    bool ok1 = false, ok2 = false;
    int original = parts[0].toInt(&ok1);
    int target   = parts[1].toInt(&ok2);
    if (!ok1 || !ok2 || (target != 0 && target != 1))
        return "NEWTON_ERR: sample must be integer, bit must be 0 or 1\r\n";

    if ((original & 1) == target)
        return "NEWTON: " + QString::number(original) +
               " (LSB already = " + QString::number(target) + ")\r\n";

    const double PI = 3.14159265358979323846;
    double x = original + 0.5;
    for (int i = 0; i < 50; ++i) {
        double fx  = std::sin(PI * (x - target) / 2.0);
        double fpx = (PI / 2.0) * std::cos(PI * (x - target) / 2.0);
        if (std::abs(fpx) < 1e-12) break;
        double x_new = x - fx / fpx;
        if (std::abs(x_new - x) < 1e-10) { x = x_new; break; }
        x = x_new;
    }
    int candidate = static_cast<int>(std::lround(x));
    if ((candidate & 1) != target) {
        int down = candidate - 1, up = candidate + 1;
        candidate = (std::abs(down - original) <= std::abs(up - original)) ? down : up;
    }
    if (candidate < -32768) candidate = -32768;
    if (candidate >  32767) candidate =  32767;

    return "NEWTON: nearest sample with LSB " + QString::number(target) +
           " = " + QString::number(candidate) + "\r\n";
}

// STEG embed   <in.wav> <out.wav> <password> <message...>
// STEG extract <in.wav> <password>
QString fn_steg(const QString &payload) {
    const QString text = payload.trimmed();
    const QStringList parts = text.split(QRegularExpression("\\s+"),
                                         Qt::SkipEmptyParts);
    if (parts.isEmpty())
        return "STEG_ERR: Usage: STEG embed|extract ...\r\n";

    const QString mode = parts[0].toLower();

    if (mode == "embed") {
        if (parts.size() < 5)
            return "STEG_ERR: Usage: STEG embed <in.wav> <out.wav> <password> <message...>\r\n";

        const std::string inFile  = parts[1].toStdString();
        const std::string outFile = parts[2].toStdString();
        const std::string password = parts[3].toStdString();
        const QString message = parts.mid(4).join(' ');

        WavHeader header;
        std::vector<int16_t> samples = read_wav(inFile, header);
        if (samples.empty())
            return "STEG_ERR: cannot read WAV '" + parts[1] + "' (PCM/16-bit only)\r\n";

        std::vector<uint64_t> cipher =
            rsa_encrypt(message.toStdString(), gServerKeys.e, gServerKeys.n);
        std::string cipherData = serialize_ciphertext(cipher);

        if (!embed_message(samples, cipherData, password))
            return "STEG_ERR: audio too short to embed message\r\n";

        if (!write_wav(outFile, samples, header))
            return "STEG_ERR: cannot write WAV '" + parts[2] + "'\r\n";

        return "STEG: message embedded -> " + parts[2] +
               " (" + QString::number(samples.size()) + " samples)\r\n";
    }
    else if (mode == "extract") {
        if (parts.size() < 3)
            return "STEG_ERR: Usage: STEG extract <in.wav> <password>\r\n";

        const std::string inFile = parts[1].toStdString();
        const std::string password = parts[2].toStdString();

        WavHeader header;
        std::vector<int16_t> samples = read_wav(inFile, header);
        if (samples.empty())
            return "STEG_ERR: cannot read WAV '" + parts[1] + "'\r\n";

        std::string cipherData = extract_message(samples, password);
        if (cipherData.empty())
            return "STEG_ERR: no hidden message or wrong password\r\n";

        std::vector<uint64_t> cipher = deserialize_ciphertext(cipherData);
        if (cipher.empty())
            return "STEG_ERR: corrupted ciphertext\r\n";

        std::string plain = rsa_decrypt(cipher, gServerKeys.d, gServerKeys.n);
        return "STEG: extracted message: " + QString::fromStdString(plain) + "\r\n";
    }

    return "STEG_ERR: unknown mode '" + parts[0] + "'. Use embed|extract\r\n";
}

MyTcpServer::~MyTcpServer() {
    for (QTcpSocket *client : mClients)
        client->disconnectFromHost();
    mTcpServer->close();
}

MyTcpServer::MyTcpServer(QObject *parent) : QObject(parent) {
    mTcpServer = new QTcpServer(this);

    connect(mTcpServer, &QTcpServer::newConnection,
            this, &MyTcpServer::slotNewConnection);

    if (!mTcpServer->listen(QHostAddress::Any, 33333)) {
        qDebug() << "Server is not started";
    } else {
        qDebug() << "Server is started on port 33333";
        qDebug() << "RSA keys: n =" << gServerKeys.n
                 << " e =" << gServerKeys.e
                 << " d =" << gServerKeys.d;
    }
}

void MyTcpServer::slotNewConnection() {
    while (mTcpServer->hasPendingConnections()) {
        QTcpSocket *clientSocket = mTcpServer->nextPendingConnection();
        mClients.insert(clientSocket);

        qDebug() << "New client connected:" << clientSocket->peerAddress().toString()
                 << ":" << clientSocket->peerPort()
                 << "| Total clients:" << mClients.size();

        clientSocket->write("Hello! I am RSA + SHA-1 + Newton + Steganography server.\r\n");
        clientSocket->write("Type HELP for available commands.\r\n");

        connect(clientSocket, &QTcpSocket::readyRead,
                this, &MyTcpServer::slotServerRead);
        connect(clientSocket, &QTcpSocket::disconnected,
                this, &MyTcpServer::slotClientDisconnected);
    }
}

void MyTcpServer::slotServerRead() {
    QTcpSocket *clientSocket = qobject_cast<QTcpSocket*>(sender());
    if (!clientSocket) return;

    QByteArray rawData = clientSocket->readAll();

    if (!rawData.isEmpty() && static_cast<unsigned char>(rawData[0]) == 0xFF)
        return;

    QString request = QString::fromUtf8(rawData).trimmed();
    if (request.isEmpty()) return;

    qDebug() << "From" << clientSocket->peerAddress().toString()
             << ":" << clientSocket->peerPort()
             << "| Request:" << request;

    QString response;

    if (request.startsWith("deRSA", Qt::CaseInsensitive)) {
        response = fn_rsa_decrypt(request.mid(5));
    }
    else if (request.startsWith("RSA", Qt::CaseInsensitive)) {
        response = fn_rsa_encrypt(request.mid(3));
    }
    else if (request.startsWith("SHA1", Qt::CaseInsensitive)) {
        response = fn_sha1(request.mid(4));
    }
    else if (request.startsWith("NEWTON", Qt::CaseInsensitive)) {
        response = fn_newton(request.mid(6));
    }
    else if (request.startsWith("STEG", Qt::CaseInsensitive)) {
        response = fn_steg(request.mid(4));
    }
    else if (request.compare("HELP", Qt::CaseInsensitive) == 0) {
        response =
            "Available commands:\r\n"
            "  SHA1 <text>                              - SHA-1 hex digest\r\n"
            "  RSA <text>                               - encrypt with server public key\r\n"
            "  deRSA <b1> <b2> ...                      - decrypt RSA blocks\r\n"
            "  NEWTON <sample> <bit>                    - nearest int16 with given LSB\r\n"
            "  STEG embed <in.wav> <out.wav> <pwd> <msg>- hide RSA-encrypted message in WAV\r\n"
            "  STEG extract <in.wav> <pwd>              - recover hidden message from WAV\r\n";
    }
    else {
        response = "Echo: " + request + "\r\n";
    }

    clientSocket->write(response.toUtf8());
}

void MyTcpServer::slotClientDisconnected() {
    QTcpSocket *clientSocket = qobject_cast<QTcpSocket*>(sender());
    if (!clientSocket) return;

    qDebug() << "Client disconnected:" << clientSocket->peerAddress().toString()
             << ":" << clientSocket->peerPort()
             << "| Remaining clients:" << (mClients.size() - 1);

    mClients.remove(clientSocket);
    clientSocket->deleteLater();
}
