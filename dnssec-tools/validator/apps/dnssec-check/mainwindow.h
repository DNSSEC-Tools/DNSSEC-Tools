// checksum 0x18ae version 0x10001
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QtGui/QMainWindow>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <validator/resolver.h>
#include <validator/validator.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include <QtGui/QGridLayout>
#include <QtGui/QVBoxLayout>
#include <QtGui/QLabel>
#include <QtGui/QPushButton>
#include <QtGui/QLineEdit>

#include <QtNetwork/QNetworkAccessManager>

#include "QStatusLight.h"

#if (defined(Q_WS_MAEMO_5) || defined(MAEMO_CHANGES))
#define SMALL_DEVICE 1
#endif

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

    bool doLookupTest(QString lookupName = QString("dnssec-tools.org"), int queryType = 48, char *resolv_conf = NULL);  // type = DNSKEY
    void busy();
    void unbusy();
    void setupWidgets();
    void setupMenus();
    void loadResolvConf();
    void addAddress(QString address, int row = -1);

public slots:
    void getAnswers();
    void getSubAnswers();
    void showAbout();
    void showResultDetails();
    void maybeSubmitResults();
    void submitResults();
    void addLineAddress();
    void respnonseReceived(QNetworkReply *response);

private:
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

    QNetworkAccessManager *m_manager;

    int m_rows;
};

#endif // MAINWINDOW_H
