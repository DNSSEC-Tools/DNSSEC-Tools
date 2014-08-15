#include "mainwindow.h"
#include "whatami.h"
#include <QtQml>
#include <QtGui/QGuiApplication>
#include "qtquick2applicationviewer.h"
#include "TestManager.h"

#include <qdebug.h>

#include <QtGui/QApplication>
//#include <QtDeclarative/QDeclarativeContext>
#include <QtDeclarative/QDeclarativeEngine>
//#include <QtDeclarative/QDeclarativeComponent>
#include <QQmlContext>

#define USE_QML 1

extern "C" {
void val_freeaddrinfo(addrinfo *foo) { Q_UNUSED(foo);}
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    bool use_qml;
#ifdef USE_QML
    use_qml = true;
#else 
    use_qml = false;
#endif

    QStringList options = app.arguments();
    if (options.contains("--use-qml"))
        use_qml = true;
    if (options.contains("--dont-use-qml"))
        use_qml = false;

    if (use_qml) {
        qDebug() << "here...  registering";
        qRegisterMetaType<DNSSECTest>("DNSSECTest");

        int ret = 0;
        ret = qmlRegisterType<DNSSECTest, 1>("DNSSECTools", 1, 0, "DNSSECTest");
        qDebug() << "registration status 1: " << ret;
        ret = qmlRegisterType<TestManager, 1>("DNSSECTools", 1, 0, "TestManager");
        qDebug() << "registration status 2: " << ret;
        ret = qmlRegisterType<DNSSECTest, 1>("DNSSECTools", 1, 0, "DNSSECTest");
        qDebug() << "registration status 1: " << ret;

        QtQuick2ApplicationViewer viewer;
        QQmlContext *context;
        viewer.addImportPath(":/qml");
        viewer.setIcon(QIcon(":/images/dnssec-check-64x64.png"));
        viewer.setTitle("DNSSEC-Check");

        TestManager manager;
        context = viewer.rootContext();
        context->setContextProperty("testManager", &manager);

        #ifdef IS_MEEGO
        viewer.setSource(QUrl("qrc:/qml/MeegoDnssecCheck.qml"));
        #else
        viewer.setSource(QUrl("qrc:/qml/DnssecCheck.qml"));
        #endif

        //viewer.setOrientation(QmlApplicationViewer::ScreenOrientationLockLandscape);
        #ifdef IS_MEEGO
        viewer.showFullScreen();
        #else
        viewer.show();
        #endif

        return app.exec();
    } else { // don't use QML
#ifdef NOT_ON_QT5
        MainWindow mainWindow;
        mainWindow.setOrientation(MainWindow::Auto);

        #ifdef Q_OS_SYMBIAN
        mainWindow.showFullScreen();
        #elif defined(Q_WS_MAEMO_5)
        mainWindow.showMaximized();
        #else
        mainWindow.show();
        #endif

        return app.exec();
#endif
    }
}
