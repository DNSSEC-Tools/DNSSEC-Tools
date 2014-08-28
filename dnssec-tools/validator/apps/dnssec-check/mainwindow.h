// checksum 0x18ae version 0x10001
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include <sys/types.h>
#ifdef NEED_SYS_SELECT_H
#include <sys/select.h>
#endif

#include <validator/resolver.h>
#include <validator/validator.h>

#include <QGridLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QLineEdit>

#include <QtNetwork/QNetworkAccessManager>

#include "QStatusLight.h"
#include "TestManager.h"

#if (defined(Q_WS_MAEMO_5) || defined(MAEMO_CHANGES))
#define SMALL_DEVICE 1
#endif

#include "DnssecCheckVersion.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    enum Orientation {
        LockPortrait,
        LockLandscape,
        Auto
    };

    MainWindow(QWidget *parent = 0);
    ~MainWindow();

    void setOrientation(Orientation orientation);

    bool doLookupTest(const QString lookupName = QString("dnssec-tools.org"), int queryType = 48, char *resolv_conf = NULL);  // type = DNSKEY
    void busy();
    void unbusy();
    void setupWidgets();
    void setupMenus();
    void loadResolvConf();
    void addAddress(QString address, int row = -1);

public slots:
    void startGetAnswers();
    void getAnswers();
    void getSubAnswers();
    void showAbout();
    void showResultDetails();
    void maybeSubmitResults();
    void submitResults(QString locationDescription = "");
    void addLineAddress();
    void responseReceived(QNetworkReply *response);

private:
    TestManager  m_testManager;
    QStringList  m_serverAddresses;

    QWidget     *m_mainWidget;
    QLabel      *m_titleLabel;
    QGridLayout *m_results;
    QVBoxLayout *m_mainLayout;

    QPushButton *m_testButton;

    QStatusLight *m_resolverResult;
    QStatusLight *m_bypassResult;

    QList<QStatusLight *> m_tests;

    QStatusLight *m_testResult;
    QLineEdit    *m_lineEdit;

    int m_rows;
    QNetworkAccessManager *m_manager;
    QAction *m_detailedResults;
    QAction *m_submitResults;
};

#endif // MAINWINDOW_H
