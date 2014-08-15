# Add files and directories to ship with the application 
# by adapting the examples below.
# file1.source = myfile
# dir1.source = mydir
DEPLOYMENTFOLDERS = # file1 dir1

TEMPLATE = app

# Avoid auto screen rotation
#DEFINES += ORIENTATIONLOCK

# define to have syncronous only queries
# DEFINES += VAL_NO_ASYNC

# for android
INCLUDEPATH += ../../include
INCLUDEPATH += .
isEmpty(ANDROID_PLATFORM) {
    # NOT Android
    QMAKE_LIBDIR     += ../../libval/.libs
    QMAKE_LIBDIR     += ../../libsres/.libs

    contains(MEEGO_EDITION,harmattan): {
        QMAKE_LIBDIR += /scratchbox/users/hardaker/targets/HARMATTAN_ARMEL/usr/lib
    } else:macx {
        LIBS        += -lval-threads -lsres -lssl -lcrypto -lpthread
        INCLUDEPATH += /opt/dnssec-tools/include
        QMAKE_LIBDIR += /opt/dnssec-tools/lib
    } else:maemo5 {
        INCLUDEPATH += /opt/maemo/usr/include/
    } else:win32 {
        QMAKE_LIBDIR += /OpenSSL-Win32/bin/
        LIBS += -lval-threads -lsres -leay32 -lpthread -lws2_32
        INCLUDEPATH += pcap
    } else {
        LIBS        += -lval-threads -lsres -lssl -lcrypto -lpthread
    }
} else {
    QMAKE_LIBDIR += /opt/android-external-openssl/lib/
    QMAKE_LIBDIR += /root/necessitas/android-ndk-r5c/platforms/android-4/arch-arm/usr/lib/
    QMAKE_LIBDIR     += ../../libval/.libs
    QMAKE_LIBDIR     += ../../libsres/.libs
    LIBS        += -lval -lsres -lssl -lcrypto
}

# Needs to be defined for Symbian
DEFINES += NETWORKACCESS

QT += network qml quick declarative gui core widgets
#QT += network declarative gui core widgets

# OS X icon
ICON=images/dnssec-check.icns

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

# Please do not modify the following two lines. Required for deployment.
include(qtquick2applicationviewer/qtquick2applicationviewer.pri)
qtcAddDeployment()

# If your application uses the Qt Mobility libraries, uncomment
# the following lines and add the respective components to the 
# MOBILITY variable. 
# CONFIG += mobility
# MOBILITY +=

# not on qt5 with qml: mainwindow.cpp
SOURCES += main.cpp  \
    dnssec_checks.cpp \
    QStatusLight.cpp \
    SubmitDialog.cpp \
    DNSSECTest.cpp \
    TestManager.cpp \
    DNSSECCheckThread.cpp \
    DNSSECCheckThreadHandler.cpp

# not on qt5 with qml: mainwindow.h
HEADERS +=  \
    QStatusLight.h \
    dnssec_checks.h \
    SubmitDialog.h \
    DNSSECTest.h \
    TestManager.h \
    DNSSECCheckThread.h \
    DnssecCheckVersion.h \
    DNSSECCheckThreadHandler.h

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
    qml/SubmitResults.qml \
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
    android/res/values-fa/strings.xml \
    qml/WantToSubmitInfo.qml \
    qml/InfoBox.qml \
    qml/Help.qml \
    qml/HostMenu.qml \
    qml/WaitCursor.qml \
    qml/ResolverMenu.qml \
    qml/Header.qml \
    qml/ResultInfo.qml \
    qml/Grade.qml \
    qml/Wrapper.qml

OTHER_FILES += \
    android/src/eu/licentia/necessitas/industrius/QtActivity.java \
    android/src/eu/licentia/necessitas/industrius/QtApplication.java \
    android/src/eu/licentia/necessitas/industrius/QtLayout.java \
    android/src/eu/licentia/necessitas/industrius/QtSurface.java \
    android/src/eu/licentia/necessitas/ministro/IMinistroCallback.aidl \
    android/src/eu/licentia/necessitas/ministro/IMinistro.aidl \
    android/src/eu/licentia/necessitas/mobile/QtSystemInfo.java \
    android/src/eu/licentia/necessitas/mobile/QtAndroidContacts.java \
    android/src/eu/licentia/necessitas/mobile/QtFeedback.java \
    android/src/eu/licentia/necessitas/mobile/QtLocation.java \
    android/src/eu/licentia/necessitas/mobile/QtMediaPlayer.java \
    android/src/eu/licentia/necessitas/mobile/QtSensors.java \
    android/src/eu/licentia/necessitas/mobile/QtCamera.java \
    android/AndroidManifest.xml \
    android/res/values/strings.xml \
    android/res/values/libs.xml \
    android/res/drawable-hdpi/icon.png \
    android/res/drawable-mdpi/icon.png \
    android/res/drawable-ldpi/icon.png







