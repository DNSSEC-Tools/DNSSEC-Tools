/****************************************************************************
**
** Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
** All rights reserved.
** Contact: Nokia Corporation (qt-info@nokia.com)
**
** This file is part of the examples of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:BSD$
** You may use this file under the terms of the BSD license as follows:
**
** "Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are
** met:
**   * Redistributions of source code must retain the above copyright
**     notice, this list of conditions and the following disclaimer.
**   * Redistributions in binary form must reproduce the above copyright
**     notice, this list of conditions and the following disclaimer in
**     the documentation and/or other materials provided with the
**     distribution.
**   * Neither the name of Nokia Corporation and its Subsidiary(-ies) nor
**     the names of its contributors may be used to endorse or promote
**     products derived from this software without specific prior written
**     permission.
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
** "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
** LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
** A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
** OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
** OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
** $QT_END_LICENSE$
**
****************************************************************************/

#include <QtGui>
#include <QApplication>

#include "graphwidget.h"
#include "TypeMenu.h"
#include "MainWindow.h"
#include "DNSData.h"
#include "PcapWatcher.h"

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    QString argument;
    QStringList startNames;
    QStringList startLogs;
    QStringList startDumps;
    QStringList arguments = app.arguments();

    QString helpText =
            "dnssec-debug [--pcapfile file] [--logfile file] [--help] [--style qtstyle] [domainnames...]";

    qsrand(QTime(0,0,0).secsTo(QTime::currentTime()));

    while (arguments.count() > 0) {
        argument = arguments.takeFirst();
        if (argument == "--pcapfile") {
            startDumps.push_back(arguments.takeFirst());
        } else if (argument == "--logfile") {
            startLogs.push_back(arguments.takeFirst());
        } else if (argument == "--help") {
            qWarning() << helpText;
            exit(0);
        } else if (argument == "--style") {
            app.setStyle(arguments.takeFirst());
        } else if (argument == "--styles") {
            qDebug() << QApplication::style();
            exit(0);
        } else {
            // must be a domainname to start with
            startNames.push_back(argument);
        }
    }

    qRegisterMetaType<DNSData>("DNSData");

    MainWindow w;
    w.show();
    w.setCursor(Qt::WaitCursor);
    w.repaint();

    GraphWidget *graph = w.graphWidget();
    if (startNames.count() > 0) {
        foreach(QString name, startNames) {
            graph->doLookup(name);
            graph->repaint();
            w.repaint();
        }
    }

    if (startLogs.count() > 0) {
        foreach(QString name, startLogs) {
            graph->openThisLogFile(name);
            w.repaint();
        }
    }

    if (startDumps.count() > 0) {
        foreach(QString name, startDumps) {
            graph->pcapWatcher()->openFile(name);
            w.repaint();
        }
    }

    w.setCursor(Qt::ArrowCursor);

    return app.exec();
}

