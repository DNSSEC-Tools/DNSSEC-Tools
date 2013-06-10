HEADERS += \
        edge.h \
        node.h \
        graphwidget.h \
    DNSData.h \
    LogWatcher.h \
    NodeList.h \
    NodesPreferences.h \
    DelayedDelete.h \
    DetailsViewer.h \
    Effects/Effect.h \
    Effects/SetAlphaEffect.h \
    Effects/SetZValue.h \
    Filters/Filter.h \
    Filters/DNSSECStatusFilter.h \
    Filters/NameFilter.h \
    Filters/NotFilter.h \
    Effects/MultiEffect.h \
    Filters/TypeFilter.h \
    TypeMenu.h \
    LogFilePicker.h \
    Legend.h \
    Effects/SetNodeColoring.h \
    ValidateViewWidget.h \
    MainWindow.h \
    qtauto_properties.h \
    DNSResources.h \
    ValidateViewWidgetHolder.h \
    ValidateViewBox.h \
    FilterEditorWindow.h \
    filtersAndEffects.h \
    Filters/LogicalAndOr.h \
    Effects/SetSize.h

SOURCES += \
        edge.cpp \
        main.cpp \
        node.cpp \
        graphwidget.cpp \
    DNSData.cpp \
    LogWatcher.cpp \
    NodeList.cpp \
    NodesPreferences.cpp \
    DetailsViewer.cpp \
    Effects/Effect.cpp \
    Effects/SetAlphaEffect.cpp \
    Effects/SetZValue.cpp \
    Filters/Filter.cpp \
    Filters/DNSSECStatusFilter.cpp \
    Filters/NameFilter.cpp \
    Filters/NotFilter.cpp \
    Effects/MultiEffect.cpp \
    Filters/TypeFilter.cpp \
    TypeMenu.cpp \
    LogFilePicker.cpp \
    Legend.cpp \
    Effects/SetNodeColoring.cpp \
    ValidateViewWidget.cpp \
    MainWindow.cpp \
    DNSResources.cpp \
    ValidateViewWidgetHolder.cpp \
    ValidateViewBox.cpp \
    FilterEditorWindow.cpp \
    Filters/LogicalAndOr.cpp \
    Effects/SetSize.cpp

BINDIR = $$PREFIX/bin
DATADIR =$$PREFIX/share
INCLUDEPATH += ../../include
isEmpty(ANDROID_PLATFORM) {
    QMAKE_LIBDIR     += ../../libval/.libs
    QMAKE_LIBDIR     += ../../libsres/.libs
    LIBS        += -lval-threads -lsres -lnsl -lcrypto -lpthread
    contains(MEEGO_EDITION,harmattan): {
        QMAKE_LIBDIR += /scratchbox/users/hardaker/targets/HARMATTAN_ARMEL/usr/lib
    } else:osx {
        LIBS        += -lval-threads -lsres -lcrypto -lpthread
    } else:maemo5 {
        INCLUDEPATH += /opt/maemo/usr/include/
    } else:win32 {
        QMAKE_LIBDIR += /OpenSSL-Win32/bin/
        LIBS += -lval-threads -lsres -leay32 -lpthread -lws2_32
    } else {
        LIBS        += -lval-threads -lsres -lcrypto -lpthread
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

QT += network
# this is needed for symbian
DEFINES += NETWORKACCESS

TARGET.EPOCHEAPSIZE = 0x200000 0xA00000

include(deployment.pri)
qtcAddDeployment()

RESOURCES += dnssec-nodes.qrc

INCLUDEPATH += ../../include

unix:!symbian {
    maemo5 {
        target.path = /opt/usr/bin
    } else {
        target.path = $$PREFIX/bin
    }
}

symbian {
    TARGET.UID3 = 0xA000A642
    include($$PWD/../../symbianpkgrules.pri)
}

simulator: warning(This example might not fully work on Simulator platform)

# optional pcap development
# (comment these lines out if not desired)
SOURCES += PcapWatcher.cpp
HEADERS += PcapWatcher.h
QMAKE_LIBDIR += c:/windows/system32
LIBS    += -lwpcap
DEFINES += WITH_PCAP

OTHER_FILES += \
    qtc_packaging/debian_fremantle/rules \
    qtc_packaging/debian_fremantle/README \
    qtc_packaging/debian_fremantle/copyright \
    qtc_packaging/debian_fremantle/control \
    qtc_packaging/debian_fremantle/compat \
    qtc_packaging/debian_fremantle/changelog \
    qtc_packaging/debian_harmattan/rules \
    qtc_packaging/debian_harmattan/README \
    qtc_packaging/debian_harmattan/copyright \
    qtc_packaging/debian_harmattan/control \
    qtc_packaging/debian_harmattan/compat \
    qtc_packaging/debian_harmattan/changelog \
    android/AndroidManifest.xml \
    android/res/values/strings.xml \
    android/res/values/libs.xml \
    android/res/drawable-hdpi/icon.png \
    android/res/drawable-mdpi/icon.png \
    android/res/drawable-ldpi/icon.png \
    android/src/org/kde/necessitas/origo/QtActivity.java \
    android/src/org/kde/necessitas/origo/QtApplication.java \
    android/src/org/kde/necessitas/ministro/IMinistroCallback.aidl \
    android/src/org/kde/necessitas/ministro/IMinistro.aidl \
    android/res/values-de/strings.xml \
    android/res/values-pt-rBR/strings.xml \
    android/res/layout/splash.xml \
    android/res/values-et/strings.xml \
    android/res/drawable/logo.png \
    android/res/drawable/icon.png \
    android/res/values-ru/strings.xml \
    android/res/values-zh-rCN/strings.xml \
    android/res/values-it/strings.xml \
    android/res/values-nl/strings.xml \
    android/res/values-pl/strings.xml \
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
    android/res/drawable-ldpi/icon.png
