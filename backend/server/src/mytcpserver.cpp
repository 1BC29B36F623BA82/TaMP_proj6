#include "mytcpserver.h"
#include "newton.h"
#include "steg.h"
#include <QCoreApplication>
#include <QString>


QString fn_rsa_encrypt(const QString &payload) {
    qDebug() << "[fn_rsa_encrypt] STUB called with:" << payload;
    return "RSA_ENC_ERR: Not implemented yet (stub)\r\n";
}

QString fn_rsa_decrypt(const QString &payload) {
    qDebug() << "[fn_rsa_decrypt] STUB called with:" << payload;
    return "RSA_DEC_ERR: Not implemented yet (stub)\r\n";
}

QString fn_sha1(const QString &payload) {
    qDebug() << "[fn_sha1] STUB called with:" << payload;
    return "SHA1_ERR: Not implemented yet (stub)\r\n";
}

QString fn_newton(const QString &payload) {
    qDebug() << "[fn_newton] STUB called with:" << payload;
    return "NEWTON_ERR: Not implemented yet (stub)\r\n";
}

QString fn_steg(const QString &payload) {
    qDebug() << "[fn_steg] STUB called with:" << payload;
    return "STEG_ERR: Not implemented yet (stub)\r\n";
}

MyTcpServer::~MyTcpServer() {
    for (QTcpSocket *client : mClients) {
        client->disconnectFromHost();
    }
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
    }
}

void MyTcpServer::slotNewConnection() {
    while (mTcpServer->hasPendingConnections()) {
        QTcpSocket *clientSocket = mTcpServer->nextPendingConnection();
        mClients.insert(clientSocket);

        qDebug() << "New client connected:" << clientSocket->peerAddress().toString()
                 << ":" << clientSocket->peerPort()
                 << "| Total clients:" << mClients.size();

        clientSocket->write("Hello! I am echo + crypto server.\r\n");
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

    if (!rawData.isEmpty() && static_cast<unsigned char>(rawData[0]) == 0xFF) {
        return;
    }

    QString request = QString::fromUtf8(rawData).trimmed();
    if (request.isEmpty()) return;

    qDebug() << "From" << clientSocket->peerAddress().toString()
             << ":" << clientSocket->peerPort()
             << "| Request:" << request;

    QString response;

    if (request.startsWith("deRSA", Qt::CaseInsensitive)) {
        QString payload = request.mid(6);
        response = fn_rsa_decrypt(payload);
    }
    else if (request.startsWith("RSA", Qt::CaseInsensitive)) {
        QString payload = request.mid(4);
        response = fn_rsa_encrypt(payload);
    }
    else if (request.startsWith("SHA1", Qt::CaseInsensitive)) {
        QString payload = request.mid(5);
        response = fn_sha1(payload);
    }
    else if (request.startsWith("NEWTON", Qt::CaseInsensitive)) {
        QString payload = request.mid(7);
        response = fn_newton(payload);
    }
    else if (request.startsWith("STEG", Qt::CaseInsensitive)) {
        QString payload = request.mid(5);
        response = fn_steg(payload);
    }
    else if (request.compare("HELP", Qt::CaseInsensitive) == 0) {
        response = "Available commands: RSA, deRSA, SHA1, NEWTON, STEG\r\n";
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
