/**
 * @file mytcpserver.h
 * @brief TCP-сервер на Qt с поддержкой команд RSA, SHA1, STEG.
 *
 * Поддерживаемые команды (протокол — plaintext по TCP, порт 33333):
 *   RSA    <текст>           — RSA-шифрование (побайтово, ключи p=61 q=53)
 *   deRSA  <hex-данные>      — RSA-расшифрование
 *   SHA1   <текст>           — SHA-1 хэш в hex
 *   STEG   <текст> <файл>    — встроить сообщение в WAV (стеганография) [ADMIN]
 *   deSTEG <файл>            — извлечь сообщение из WAV [ADMIN]
 *   WHOAMI                   — имя и роль текущего пользователя
 *   HISTORY [N]              — последние N команд сессии (по умолчанию 10)
 *   HELP                     — список команд
 */


#ifndef MYTCPSERVER_H
#define MYTCPSERVER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QtNetwork>
#include <QByteArray>
#include <QDebug>
#include <QMap>
#include <QList>

/**
 * @brief Роли подключённых пользователей.
 */
enum class AppRole {
    Guest,  ///< Неавторизованный — только REGISTER/LOGIN
    Client, ///< Обычный пользователь — RSA, SHA1, WHOAMI, HISTORY
    Server  ///< Администратор — все команды + STEG, KICK, BAN, LIST
};
 
/**
 * @brief Контекст одного подключения: роль, имя, история команд.
 *
 * История хранит не более MAX_HISTORY последних команд сессии.
 * Команды WHOAMI и HISTORY в историю не записываются.
 */
struct ClientContext {
    AppRole      role     = AppRole::Guest;     ///< Роль пользователя
    QString      username = "Anonymous";         ///< Логин (после LOGIN)
    QList<QString> history;                      ///< История команд текущей сессии
 
    static constexpr int MAX_HISTORY = 20;       ///< Максимальный размер истории
};


/**
 * @brief RSA-шифрование строки.
 *
 * Каждый байт открытого текста шифруется по формуле c = m^e mod n
 * (ключи генерируются из p=61, q=53 при старте сервера).
 * Шифротекст сериализуется и возвращается как hex-строка.
 *
 * @param payload Открытый текст
 * @return Hex-представление сериализованного шифротекста или сообщение об ошибке
 */
QString fn_rsa_encrypt(const QString &payload);

/**
 * @brief RSA-расшифрование строки.
 *
 * Принимает hex-строку, десериализует шифротекст и расшифровывает.
 *
 * @param payload Hex-строка шифротекста (результат fn_rsa_encrypt)
 * @return Расшифрованный открытый текст или сообщение об ошибке
 */
QString fn_rsa_decrypt(const QString &payload);

/**
 * @brief Вычисление SHA-1 хэша строки.
 *
 * @param payload Входная строка
 * @return 40-символьная hex-строка SHA-1 хэша
 */
QString fn_sha1(const QString &payload);

/**
 * @brief Встраивание сообщения в WAV-файл (стеганография).
 *
 * Ожидает payload вида: "<текст> <имя_wav_файла>"
 * Файл ищется в каталоге ./wav/ рядом с бинарником.
 * Результат сохраняется как ./wav/encrypted_<имя>.
 *
 * Цепочка: текст → RSA-шифрование → сериализация → LSB-стеганография (метод Ньютона + SHA-1).
 *
 * @param payload Строка "<текст> <файл.wav>"
 * @return Строка SUCCESS/ERROR с описанием результата
 */
QString fn_steg(const QString &payload);

/**
 * @brief Извлечение и расшифрование сообщения из WAV-файла.
 *
 * Ожидает payload вида: "<имя_wav_файла>"
 * Файл ищется в каталоге ./wav/.
 *
 * @param payload Имя WAV-файла
 * @return Расшифрованный текст или сообщение об ошибке
 */
QString fn_desteg(const QString &payload);


/**
 * @brief Qt TCP-сервер, обслуживающий несколько клиентов одновременно.
 *
 * Слушает порт 33333. Каждый входящий клиент добавляется в mClients;
 * при отключении удаляется. Команды разбираются в slotServerRead().
 */
class MyTcpServer : public QObject
{
    Q_OBJECT

public:
    /**
     * @brief Конструктор: создаёт QTcpServer, запускает прослушивание на порту 33333.
     * @param parent Родительский QObject (по умолчанию nullptr)
     */
    explicit MyTcpServer(QObject *parent = nullptr);

    /**
     * @brief Деструктор: отключает всех клиентов и останавливает сервер.
     */
    ~MyTcpServer();

public slots:
    /**
     * @brief Слот: принимает все ожидающие подключения, регистрирует сигналы сокета.
     */
    void slotNewConnection();

    /**
     * @brief Слот: удаляет отключившегося клиента из mClients.
     */
    void slotClientDisconnected();

    /**
     * @brief Слот: читает данные от клиента, разбирает команду, отправляет ответ.
     */
    void slotServerRead();

private:
    QTcpServer          *mTcpServer; ///< Основной сервер, принимает подключения

    // Карта текущих подключений: Сокет -> Контекст (роль, имя)
    QMap<QTcpSocket*, ClientContext> mClientsInfo;

    // "База данных" в оперативной памяти
    QMap<QString, QString> mUserDatabase; // логин -> пароль
    QSet<QString> mAdmins;                // список логинов-админов
    QSet<QString> mBannedUsers;           // забаненные по логину
    QSet<QString> mBannedIPs;             // забаненные по IP-адресу
};

#endif // MYTCPSERVER_H