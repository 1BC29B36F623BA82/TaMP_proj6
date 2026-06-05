QT -= gui
QT += network core

CONFIG += c++17 console
CONFIG -= app_bundle

# Хедеры ищутся прямо в include/, без полного пути
INCLUDEPATH += include

# Исходники
SOURCES += \
    main.cpp \
    src/mytcpserver.cpp \
    src/rsa.cpp \
    src/sha1.cpp \
    src/steganography.cpp \
    src/wav_handler.cpp

# Хедеры
HEADERS += \
    include/mytcpserver.h \
    include/rsa.h \
    include/sha1.h \
    include/steganography.h \
    include/wav_handler.h

# Стандартные правила деплоя
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target