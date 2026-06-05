/**
 * @file main.cpp
 * @brief Точка входа Qt-приложения. Создаёт и запускает TCP-сервер.
 */

#include <QCoreApplication>
#include "mytcpserver.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    MyTcpServer myserv;
    return a.exec();
}