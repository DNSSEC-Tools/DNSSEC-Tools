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
    Legend.h

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
    Legend.cpp

BINDIR = $$PREFIX/bin
DATADIR =$$PREFIX/share
INCLUDEPATH += ../../include

DEFINES += NETWORKACCESS

LIBS        += -lval -lsres -lcrypto

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
