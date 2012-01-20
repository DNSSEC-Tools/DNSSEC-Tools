# Add files and directories to ship with the application 
# by adapting the examples below.
# file1.source = myfile
# dir1.source = mydir
DEPLOYMENTFOLDERS = # file1 dir1

# Avoid auto screen rotation
#DEFINES += ORIENTATIONLOCK

# for android
INCLUDEPATH += ../../include
isEmpty(ANDROID_PLATFORM) {
    LIBS        += -lval-threads -lsres -lnsl -lcrypto -lpthread
    maemo5 {
        INCLUDEPATH += /opt/maemo/usr/include/
    }
} else {
    LIBS        += -L/root/necessitas/android-ndk-r5c/platforms/android-4/arch-arm/usr/lib/
    LIBS        += -L/home/hardaker/src/dnssec/dt.android/dnssec-tools/validator/libval/.libs -L/home/hardaker/src/dnssec/dt.android/dnssec-tools/validator/libsres/.libs
    INCLUDEPATH += /home/hardaker/src/dnssec/dt.android/dnssec-tools/validator/include
    LIBS        += -lval -lsres -lcrypto
}

# path to the harmattan libraries
contains(MEEGO_EDITION,harmattan): {
    LIBS += -L/scratchbox/users/hardaker/targets/HARMATTAN_ARMEL/usr/lib
} else {
    LIBS += -L/usr/local/lib
}

# Needs to be defined for Symbian
DEFINES += NETWORKACCESS

QT += network declarative

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
    qtc_packaging/debian_harmattan/changelog \
    android/src/org/kde/necessitas/origo/QtActivity.java \
    android/src/org/kde/necessitas/origo/QtApplication.java \
    android/src/org/kde/necessitas/ministro/IMinistroCallback.aidl \
    android/src/org/kde/necessitas/ministro/IMinistro.aidl \
    android/AndroidManifest.xml \
    android/res/values-de/strings.xml \
    android/res/values-pt-rBR/strings.xml \
    android/res/values/strings.xml \
    android/res/values/libs.xml \
    android/res/layout/splash.xml \
    android/res/drawable-hdpi/icon.png \
    android/res/drawable-mdpi/icon.png \
    android/res/values-et/strings.xml \
    android/res/drawable/logo.png \
    android/res/drawable/icon.png \
    android/res/values-ru/strings.xml \
    android/res/values-zh-rCN/strings.xml \
    android/res/values-it/strings.xml \
    android/res/values-nl/strings.xml \
    android/res/values-pl/strings.xml \
    android/res/drawable-ldpi/icon.png \
    android/res/values-fr/strings.xml \
    android/res/values-ms/strings.xml \
    android/res/values-ja/strings.xml \
    android/res/values-ro/strings.xml \
    android/res/values-el/strings.xml \
    android/res/values-rs/strings.xml \
    android/res/values-nb/strings.xml \
    android/res/values-es/strings.xml \
    android/res/values-zh-rTW/strings.xml \
    android/res/values-id/strings.xml \
    android/res/values-fa/strings.xml

# Please do not modify the following two lines. Required for deployment.
include(deployment.pri)
qtcAddDeployment()

# Please do not modify the following two lines. Required for deployment.
include(qmlapplicationviewer/qmlapplicationviewer.pri)
qtcAddDeployment()

