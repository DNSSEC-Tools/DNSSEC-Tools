#include "mainwindow.h"
#include "whatami.h"
#include "qmlapplicationviewer.h"
#include "TestManager.h"

#include <qdebug.h>

#include <QtGui/QApplication>
#include <QtDeclarative/QDeclarativeContext>
#include <QtDeclarative/QDeclarativeEngine>
#include <QtDeclarative/QDeclarativeComponent>

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

        return app.exec();
    } else { // don't use QML
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
    }
}
