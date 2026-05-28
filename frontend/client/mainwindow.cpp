#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QMessageBox>
 
MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
    , mSocket(new QTcpSocket(this))
{
    ui->setupUi(this);

    connect(ui->btnConnect, &QPushButton::clicked, this, &MainWindow::onConnectClicked);
    connect(ui->btnDisconnect, &QPushButton::clicked, this, &MainWindow::onDisconnectClicked);
    connect(ui->btnSend, &QPushButton::clicked, this, &MainWindow::onSendClicked);
    connect(ui->lineCommand, &QLineEdit::returnPressed, this, &MainWindow::onSendClicked);

    connect(mSocket, &QTcpSocket::connected, this, &MainWindow::onConnected);
    connect(mSocket, &QTcpSocket::disconnected, this, &MainWindow::onDisconnected);
    connect(mSocket, &QTcpSocket::readyRead, this, &MainWindow::onReadyRead);
    connect(mSocket, QOverload<QAbstractSocket::SocketError>::of(&QAbstractSocket::errorOccurred),
            this, &MainWindow::onError);

    setConnectedState(false);
}

MainWindow::~MainWindow() {
    if (mSocket->state() == QAbstractSocket::ConnectedState) {
        mSocket->disconnectFromHost();
    }
    delete ui;
}

void MainWindow::onConnectClicked() {
    QString host = ui->lineHost->text().trimmed();
    quint16 port = static_cast<quint16>(ui->spinPort->value());

    if (host.isEmpty()) {
        QMessageBox::warning(this, "Error", "Enter the server address.");
        return;
    }

    ui->textLog->append("Connecting to " + host + ":" + QString::number(port) + "...");
    mSocket->connectToHost(host, port);
}

void MainWindow::onDisconnectClicked() {
    mSocket->disconnectFromHost();
}

void MainWindow::onSendClicked() {
    if (mSocket->state() != QAbstractSocket::ConnectedState) {
        QMessageBox::warning(this, "Error", "Not connected to server.");
        return;
    }

    QString command = ui->lineCommand->text().trimmed();
    if (command.isEmpty()) return;

    ui->textLog->append("> " + command);
    mSocket->write(command.toUtf8() + "\r\n");
    ui->lineCommand->clear();
}

void MainWindow::onConnected() {
    ui->textLog->append("Connected!");
    setConnectedState(true);
}

void MainWindow::onDisconnected() {
    ui->textLog->append("Disconnected.");
    setConnectedState(false);
}

void MainWindow::onReadyRead() {
    QByteArray data = mSocket->readAll();
    QString text = QString::fromUtf8(data).trimmed();
    if (!text.isEmpty()) {
        ui->textLog->append(text);
    }
}

void MainWindow::onError(QAbstractSocket::SocketError socketError) {
    Q_UNUSED(socketError);
    ui->textLog->append("Error: " + mSocket->errorString());
    setConnectedState(false);
}

void MainWindow::setConnectedState(bool connected) {
    ui->btnConnect->setEnabled(!connected);
    ui->lineHost->setEnabled(!connected);
    ui->spinPort->setEnabled(!connected);
    ui->btnDisconnect->setEnabled(connected);
    ui->btnSend->setEnabled(connected);
    ui->lineCommand->setEnabled(connected);

    ui->statusbar->showMessage(connected ? "Connected" : "Disconnected");
}
