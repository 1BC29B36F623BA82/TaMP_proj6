/**
 * @file main.cpp
 * @brief Точка входа Qt TCP-сервера (RSA + SHA-1 + метод Ньютона + стеганография).
 *
 * Сервер слушает порт 33333, поддерживает несколько клиентов одновременно.
 * Протокол команд описан по команде HELP (см. mytcpserver.cpp).
 */

#include <QCoreApplication>
#include "mytcpserver.h"

int main(int argc, char *argv[])
{
    QCoreApplication a(argc, argv);
    MyTcpServer myserv;
    return a.exec();
}
