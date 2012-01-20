# Add files and directories to ship with the application 
# by adapting the examples below.
# file1.source = myfile
# dir1.source = mydir
DEPLOYMENTFOLDERS = # file1 dir1

# Avoid auto screen rotation
#DEFINES += ORIENTATIONLOCK

# path to the harmattan libraries
contains(MEEGO_EDITION,harmattan): {
    LIBS += -L/scratchbox/users/hardaker/targets/HARMATTAN_ARMEL/usr/lib
} else {
    LIBS += -L/usr/local/lib
}

# Needs to be defined for Symbian
DEFINES += NETWORKACCESS
INCLUDEPATH += /opt/maemo/usr/include/ ../../include
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
    DNSSECTest.cpp \
    TestManager.cpp
HEADERS += mainwindow.h \
    QStatusLight.h \
    dnssec_checks.h \
    SubmitDialog.h \
    DNSSECTest.h \
    TestManager.h

#    DataSubmitter.h \
#    DataSubmitter.cpp \
RESOURCES += \
    dnssec-check.qrc

OTHER_FILES += \
    qml/DnssecCheck.qml \
    qml/Result.qml \
    qml/HostLabel.qml \
    qml/DNSSECCheck.js \
    qml/NewServerBox.qml \
    qml/Button.qml \
    qtc_packaging/debian_harmattan/rules \
    qtc_packaging/debian_harmattan/README \
    qtc_packaging/debian_harmattan/manifest.aegis \
    qtc_packaging/debian_harmattan/copyright \
    qtc_packaging/debian_harmattan/control \
    qtc_packaging/debian_harmattan/compat \
    qtc_packaging/debian_harmattan/changelog

# Please do not modify the following two lines. Required for deployment.
include(deployment.pri)
qtcAddDeployment()

# Please do not modify the following two lines. Required for deployment.
include(qmlapplicationviewer/qmlapplicationviewer.pri)
qtcAddDeployment()


















