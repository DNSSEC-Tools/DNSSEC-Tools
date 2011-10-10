/****************************************************************************
**
** Copyright (C) 2011 Nokia Corporation and/or its subsidiary(-ies).
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

#ifndef WINDOW_H
#define WINDOW_H

#include <QSystemTrayIcon>
#include <QDialog>
#include <QtGui/QVBoxLayout>
#include <QtGui/QLabel>
#include <QtGui/QIcon>
#include <QtGui/QTableWidget>
#include <QtCore/QFile>
#include <QtCore/QTextStream>
#include <QtCore/QRegExp>
#include <QtCore/QFileSystemWatcher>
#include <QtGui/QIcon>
#include <QtCore/QMap>
#include <QtCore/QDateTime>

class DNSTrayData {
public:
    DNSTrayData(QString n = "", QDateTime d = QDateTime::currentDateTime(), int c = 0) : name(n), lastHit(d), count(c) { }
    QString    name;
    QDateTime  lastHit;
    int        count;
};

class Window : public QDialog
{
    Q_OBJECT

public:
    Window();

    void setVisible(bool visible);

    void openLogFile(bool seekToEnd = false);
    QSize sizeHint() const;
    void fillTable();
    void dropOldest();

protected:
    void closeEvent(QCloseEvent *event);

private slots:
    void iconActivated(QSystemTrayIcon::ActivationReason reason);
    void showMessage(const QString &message);
    void messageClicked();
    void parseTillEnd();
    void showPreferences();
    void loadPreferences(bool seekToEnd = false);

private:
    void createLogWidgets();
    void createMessageGroupBox();
    void createActions();
    void createTrayIcon();
    void createRegexps();
    void parseLogMessage(const QString logMessage);

    QVBoxLayout *m_topLayout;
    QLabel *m_topTitle;
    QTableWidget *m_log;

    QIcon m_icon;

    QAction *hideAction;
    QAction *showAction;
    QAction *quitAction;
    QAction *prefsAction;

    QSystemTrayIcon *trayIcon;
    QMenu *trayIconMenu;

    QString      m_fileName;
    QFile       *m_logFile;
    QFileSystemWatcher *m_fileWatcher;
    QTextStream *m_logStream;

    QRegExp    m_bogusRegexp;
    QRegExp    m_bindBogusRegexp;
    int        m_maxRows, m_rowCount;
    bool       m_showStillRunningWarning;
    QIcon      m_warningIcon;

    QMap<QString, DNSTrayData> m_trayData;
};

#endif
