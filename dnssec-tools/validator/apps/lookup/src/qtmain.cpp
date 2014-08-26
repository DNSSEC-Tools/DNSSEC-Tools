/*
 * Created: 01/31/10-22:48:31
 * Author: hardaker
 */
#include <QWidget>
#include <QtGui/QApplication>
#include <QtGui/QPushButton>

#include "lookup.h"

int main(int argc, char *argv[])
{
	QApplication app(argc, argv);

        Lookup lookup;
        lookup.show();
        return app.exec();
}
