#include "mainwindow.h"
#include "whatami.h"
#include "qmlapplicationviewer.h"
#include "TestManager.h"

#include <QtGui/QApplication>
#include <QDeclarativeContext>
#include <QDeclarativeEngine>
#include <QDeclarativeComponent>

// #define to force QML usage
#define USE_QML

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

#ifdef USE_QML
    qmlRegisterType<DNSSECTest, 1>("DNSSECTools", 1, 0, "DNSSECTest");
    qmlRegisterType<TestManager, 1>("DNSSECTools", 1, 0, "TestManager");

    QmlApplicationViewer viewer;
    QDeclarativeContext *context;
    viewer.addImportPath(":/qml");

    TestManager manager;
    context = viewer.rootContext();
    context->setContextProperty("testManager", &manager);

#ifdef IS_MEEGO
    viewer.setSource(QUrl("qrc:/qml/MeegoDnssecCheck.qml"));
#else
    viewer.setSource(QUrl("qrc:/qml/DnssecCheck.qml"));
#endif


#ifdef IS_MEEGO
    viewer.setOrientation(QmlApplicationViewer::ScreenOrientationAuto);
    viewer.showFullScreen();
#else
    viewer.show();
#endif

#else /* ! USE_QML */

    MainWindow mainWindow;
    mainWindow.setOrientation(MainWindow::Auto);

#ifdef Q_OS_SYMBIAN
    mainWindow.showFullScreen();
#elif defined(Q_WS_MAEMO_5)
    mainWindow.showMaximized();
#else
    mainWindow.show();
#endif

#endif /* ! USE_QML */

    return app.exec();
}
