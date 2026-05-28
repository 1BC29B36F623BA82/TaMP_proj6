#ifndef MYTCPSERVER_H
#define MYTCPSERVER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QtNetwork>
#include <QByteArray>
#include <QDebug>
#include <QSet>

QString fn_rsa_encrypt(const QString &payload);
QString fn_rsa_decrypt(const QString &payload);
QString fn_sha1(const QString &payload);
QString fn_newton(const QString &payload);
QString fn_steg(const QString &payload);

class MyTcpServer : public QObject
{
    Q_OBJECT
public:
    explicit MyTcpServer(QObject *parent = nullptr);
    ~MyTcpServer();

public slots:
    void slotNewConnection();
    void slotClientDisconnected();
    void slotServerRead();

private:
    QTcpServer *mTcpServer;
    QSet<QTcpSocket*> mClients;
};

#endif // MYTCPSERVER_H