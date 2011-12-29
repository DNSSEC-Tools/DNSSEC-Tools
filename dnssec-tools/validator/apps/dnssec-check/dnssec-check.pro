# Add files and directories to ship with the application 
# by adapting the examples below.
# file1.source = myfile
# dir1.source = mydir
DEPLOYMENTFOLDERS = # file1 dir1

# Avoid auto screen rotation
#DEFINES += ORIENTATIONLOCK

# Needs to be defined for Symbian
DEFINES += NETWORKACCESS
INCLUDEPATH += /opt/maemo/usr/include/
LIBS        += -lval-threads -lsres -lnsl -lcrypto -lpthread

QT += network

include(deployment.pri)
qtcAddDeployment()

BINDIR = $$PREFIX/bin
DATADIR =$$PREFIX/share

INSTALLS += target

symbian:TARGET.UID3 = 0xECD7BC68

unix:!symbian {
    maemo5 {
        target.path = /opt/usr/bin
    } else {
        target.path = $$PREFIX/bin
    }
}

# If your application uses the Qt Mobility libraries, uncomment
# the following lines and add the respective components to the 
# MOBILITY variable. 
# CONFIG += mobility
# MOBILITY +=

SOURCES += main.cpp mainwindow.cpp \
    dnssec_checks.cpp \
    QStatusLight.cpp \
    SubmitDialog.cpp \
    DNSSECTest.cpp
HEADERS += mainwindow.h \
    QStatusLight.h \
    dnssec_checks.h \
    SubmitDialog.h \
    DNSSECTest.h

#    DataSubmitter.h \
#    DataSubmitter.cpp \
RESOURCES += \
    dnssec-check.qrc




