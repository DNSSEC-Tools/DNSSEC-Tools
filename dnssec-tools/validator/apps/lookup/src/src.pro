TARGET      = lookup
HEADERS     +=  lookup.h QDNSItemModel.h \
    LookupPrefs.h
SOURCES     +=  qtmain.cpp lookup.cpp QDNSItemModel.cpp \
    LookupPrefs.cpp
FORMS       += 
LEXSOURCES  += #LEXS#
YACCSOURCES += #YACCS#

INCLUDEPATH += ../../../include
INCLUDEPATH += /home/hardaker/src/dnssec/dnssec-tools.git/dnssec-tools/validator/include

isEmpty(ANDROID_PLATFORM) {
    LIBS        += -lval-threads -lsres -lnsl -lssl -lcrypto -lpthread
} else {
    LIBS        += -L/opt/android-external-openssl/lib/
    LIBS        += -L/root/necessitas/android-ndk-r5c/platforms/android-4/arch-arm/usr/lib/
    LIBS        += -L/home/hardaker/src/dnssec/dt.android/dnssec-tools/validator/libval/.libs -L/home/hardaker/src/dnssec/dt.android/dnssec-tools/validator/libsres/.libs
    INCLUDEPATH += /home/hardaker/src/dnssec/dt.android/dnssec-tools/validator/include
    LIBS        += -lval -lsres -lcrypto
}

DEFINES     +=

# All generated files goes same directory
OBJECTS_DIR = build
MOC_DIR     = build
UI_DIR      = build

RESOURCES = lookup.qrc

DESTDIR     = build
TEMPLATE    = app
DEPENDPATH  +=
VPATH       += src uis
CONFIG      -= 
CONFIG      += debug
QT=core gui widgets network



MY_BIN_PATH = /usr/bin/
# Default installation overwritten because qmake and debian both
# uses DESTDIR in different purposes

install.commands = -$(INSTALL_PROGRAM) $(TARGET) \"$(DESTDIR)\"$$MY_BIN_PATH$(QMAKE_TARGET)
install.depends = $(TARGET)

#
# Targets for debian source and binary package creation
#
debian-src.commands = dpkg-buildpackage -S -r -us -uc -d
debian-bin.commands = dpkg-buildpackage -b -r -uc -d
debian-all.depends = debian-src debian-bin

#
# Clean all but Makefile
#
compiler_clean.commands = -$(DEL_FILE) $(TARGET)

QMAKE_EXTRA_TARGETS += debian-all debian-src debian-bin install compiler_clean

unix {
    #VARIABLES
    isEmpty(PREFIX) {
        PREFIX = /usr/local
    }

BINDIR = $$PREFIX/bin
DATADIR =$$PREFIX/share

DEFINES += DATADIR=\\\"$$DATADIR\\\" PKGDATADIR=\\\"$$PKGDATADIR\\\"

#MAKE INSTALL

INSTALLS += target desktop service iconxpm icon26 icon48 icon64

  target.path =$$BINDIR

  desktop.path = $$DATADIR/applications/hildon
  desktop.files += $${TARGET}.desktop

  service.path = $$DATADIR/dbus-1/services
  service.files += $${TARGET}.service

  iconxpm.path = $$DATADIR/pixmap
  iconxpm.files += ../data/maemo/$${TARGET}.xpm

  icon26.path = $$DATADIR/icons/hicolor/26x26/apps
  icon26.files += ../data/26x26/$${TARGET}.png

  icon48.path = $$DATADIR/icons/hicolor/48x48/apps
  icon48.files += ../data/48x48/$${TARGET}.png

#  icon64.path = $$DATADIR/icons/hicolor/64x64/apps
#  icon64.files += ../data/64x64/$${TARGET}.png
}
