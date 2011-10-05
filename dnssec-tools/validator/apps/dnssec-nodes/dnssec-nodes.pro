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
    Effects/MultiEffect.h

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
    Effects/MultiEffect.cpp

DEFINES += NETWORKACCESS

LIBS        += -lval-threads -lsres -lnsl -lcrypto -lpthread

TARGET.EPOCHEAPSIZE = 0x200000 0xA00000

include(deployment.pri)
qtcAddDeployment()

RESOURCES += dnssec-nodes.qrc

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
    qtc_packaging/debian_harmattan/changelog






























