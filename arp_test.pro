TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
LIBS += -lpcap
LIBS += -lpthread
LIBS += -lnet
SOURCES += arpspoof.cpp
