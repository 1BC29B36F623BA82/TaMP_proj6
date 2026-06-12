QT += testlib
QT -= gui

CONFIG += c++17 console testcase
CONFIG -= app_bundle

TARGET = tst_functionality

INCLUDEPATH += $$PWD/../../backend/server/include

SOURCES += \
    tests.cpp \
    $$PWD/../../backend/server/src/rsa.cpp \
    $$PWD/../../backend/server/src/sha1.cpp \
    $$PWD/../../backend/server/src/steganography.cpp \
    $$PWD/../../backend/server/src/wav_handler.cpp
