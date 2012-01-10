#include <QtGui/QApplication>
#include "MainWindow.h"

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    MainWindow w;

    if (argc > 1)
        w.LoadFile(argv[1]);

    w.show();
    return a.exec();
}
