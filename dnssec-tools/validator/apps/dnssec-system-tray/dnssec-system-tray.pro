TARGET=dnssec-system-tray

HEADERS       = dnssec-system-tray.h \
    DnssecSystemTrayPrefs.h
SOURCES       = main.cpp \
                dnssec-system-tray.cpp \
    DnssecSystemTrayPrefs.cpp
RESOURCES     = dnssec-system-tray.qrc
QT           += xml svg core widgets

#include(deployment.pri)
#include(qtquick2applicationviewer/qtquick2applicationviewer.pri)
#qtcAddDeployment()

BINDIR = $$PREFIX/bin
DATADIR =$$PREFIX/share

INSTALLS += target

# install
target.path = $$BINDIR
INSTALLS += target

symbian: include($$QT_SOURCE_TREE/examples/symbianpkgrules.pri)

wince* {
	CONFIG(debug, release|debug) {
		addPlugins.sources = $$QT_BUILD_TREE/plugins/imageformats/qsvgd4.dll
	}
	CONFIG(release, release|debug) {
		addPlugins.sources = $$QT_BUILD_TREE/plugins/imageformats/qsvg4.dll
	}
	addPlugins.path = imageformats
	DEPLOYMENT += addPlugins
}

OTHER_FILES += \
    qtc_packaging/debian_fremantle/rules \
    qtc_packaging/debian_fremantle/README \
    qtc_packaging/debian_fremantle/copyright \
    qtc_packaging/debian_fremantle/control \
    qtc_packaging/debian_fremantle/compat \
    qtc_packaging/debian_fremantle/changelog
