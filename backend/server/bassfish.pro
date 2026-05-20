QT -= gui
QT += network core

CONFIG += c++17 console
CONFIG -= app_bundle

# Указываем qmake, где искать хедеры, чтобы не писать в include "include/mytcpserver.h"
INCLUDEPATH += include

# Пути к исходникам
SOURCES += \
    main.cpp \
    src/mytcpserver.cpp

# Пути к хедерам
HEADERS += \
    include/mytcpserver.h \
    include/newton.h \
    include/steg.h

# Базовые правила деплоя (оставляем стандартные)
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target