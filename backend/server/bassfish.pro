QT -= gui
QT += network core

CONFIG += c++17 console
CONFIG -= app_bundle

# Указываем qmake, где искать хедеры
INCLUDEPATH += include

# Пути к исходникам
# encrypt.cpp НЕ включаем — это отдельная утилита со своим main()
SOURCES += \
    main.cpp \
    src/mytcpserver.cpp \
    src/rsa.cpp \
    src/sha1.cpp \
    src/steganography.cpp \
    src/wav_handler.cpp

# Пути к хедерам
HEADERS += \
    include/mytcpserver.h \
    include/rsa.h \
    include/sha1.h \
    include/steganography.h \
    include/wav_handler.h

qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target
