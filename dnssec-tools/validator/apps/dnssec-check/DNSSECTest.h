#ifndef DNSSECTEST_H
#define DNSSECTEST_H

#include <QObject>
#include "DNSSECCheckThread.h"

class DNSSECCheckThread;

typedef int (CheckFunction) (char *serveraddr, char *returnString, size_t returnStringSize, int *returnStatus);

class DNSSECTest : public QObject
{
    Q_OBJECT

public:
    Q_ENUMS(lightStatus)
    enum lightStatus { UNKNOWN, GOOD, WARNING, BAD, TESTINGNOW };

    Q_PROPERTY(lightStatus status     READ status        WRITE setStatus   NOTIFY statusChanged)
    Q_PROPERTY(QString message        READ message       WRITE setMessage  NOTIFY messageChanged)
    Q_PROPERTY(QString name           READ name                            NOTIFY nameChanged)
    Q_PROPERTY(QString serverAddress  READ serverAddress                   NOTIFY serverAddressChanged)
    Q_PROPERTY(bool    async          READ async         WRITE setAsync    NOTIFY asyncChanged)


    DNSSECTest(QObject *parent = 0, CheckFunction *check_function = 0, const char *serverAddress = 0, const QString &checkName = "", bool isAsync = false, DNSSECCheckThread *otherThread = 0);
    DNSSECTest(const DNSSECTest &copyFrom);

    lightStatus status();
    QString statusString();
    void setStatus(lightStatus newStatus);
    void setStatus(int checkStatus);

    const QString message() const;
    void setMessage(const QString &message);

    const QString name() const;

    const QString serverAddress() const;

    bool async() const;
    void setAsync(bool async);

    void update();

    static lightStatus rcToStatus(int rc);
    int statusToRc(DNSSECTest::lightStatus status);

signals:
    void statusChanged();
    void messageChanged();
    void messageChanged(QString message);
    void nameChanged();
    void serverAddressChanged();
    void asyncChanged();
    void asyncTestSubmitted();
    void startTest(CheckFunction*,char*,bool);

public slots:
    void check();
    void onTestResult(CheckFunction *check_function, char *server, int status, QString resultString);

private:
    lightStatus    m_status;
    CheckFunction *m_checkFunction;
    char           m_msgBuffer[4096];
    char          *m_serverAddress;
    QString        m_checkName;
    QList<QString> m_statusStrings;
    bool           m_async;
    bool           m_runInOtherThread;
    int            m_result_status;
    DNSSECCheckThread *m_otherThread;
};

#endif // DNSSECTEST_H
