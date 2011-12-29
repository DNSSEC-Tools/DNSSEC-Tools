#include "mainwindow.h"
#include "whatami.h"

#include <QtGui/QApplication>

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    MainWindow mainWindow;

#ifdef USE_QML
    QmlApplicationViewer viewer;
    viewer.addImportPath(":/qml");
#ifdef IS_MEEGO
    viewer.setSource(QUrl("qrc:/qml/MeegoMain.qml"));
#else
    viewer.setSource(QUrl("qrc:/qml/MythMain.qml"));
#endif

    context = viewer.rootContext();
    context->setContextProperty("socketHandler", &mainWindow);

#ifdef IS_MEEGO
    viewer.setOrientation(QmlApplicationViewer::ScreenOrientationAuto);
    viewer.showFullScreen();
#else
    viewer.show();
#endif

#else /* ! USE_QML */

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
