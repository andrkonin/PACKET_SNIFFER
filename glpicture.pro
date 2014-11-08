# -------------------------------------------------
# Project created by QtCreator 2009-06-05T14:29:58
# -------------------------------------------------
QT += network \
    opengl
TARGET = glpicture
TEMPLATE = app
SOURCES += main.cpp \
    dialog.cpp \
    sniffer.cpp \
    preprocessor.cpp
HEADERS += dialog.h \
    sniffer.h \
    preprocessor.h
FORMS += dialog.ui
LIBS += -lpcap
LIBS += -lGeoIP
