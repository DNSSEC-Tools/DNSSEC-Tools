#ifndef DNSSECCHECKTHREADHANDLER_H
#define DNSSECCHECKTHREADHANDLER_H

#include <QObject>
#include <QHash>
#include <QAbstractSocket>

#include "DNSSECTest.h"

class DNSSECTest;

typedef int (CheckFunction) (char *serveraddr, char *returnString, size_t returnStringSize, int *returnStatus);

class DNSSECCheckThreadData : public QObject
{
    Q_OBJECT

public:
    int            m_result_status;
    CheckFunction *m_checkFunction;
    char          *m_serverAddress;
    char           m_msgBuffer[4096];
};

class DNSSECCheckThreadHandler : public QObject
{
    Q_OBJECT
public:
    explicit DNSSECCheckThreadHandler(QObject *parent = 0);

    void run();
signals:
    void asyncTestSubmitted();
    void testResult(CheckFunction *m_checkFunction, char *serverAddress, int testResult, QString resultMessage);

public slots:
    void startTest(CheckFunction *m_checkFunction, char *m_serverAddress, bool async);
    void checkStatus();
    void dataAvailable();
    void checkAvailableUpdates();
    void startQueuedTransactions();
    void updateWatchedSockets();
    void addTest(DNSSECTest *newtest);
    void inTestLoopChanged(bool val);

signals:
    void submissionMessageChanged();
    void aResultMessageChanged(QString message);
    void lastResultMessageChanged();
    void inTestLoopChanged();
    void updatesMaybeAvailable();

private:
    QList<DNSSECCheckThreadData *> m_dataList;
    QList<DNSSECTest *> m_tests;
    QHash<int, QAbstractSocket *> m_socketWatchers;

    struct timeval  m_timeout;
    fd_set          m_fds, m_tcp_fds;
    int             m_num_fds, m_num_tcp_fds;
};

#endif // DNSSECCHECKTHREADHANDLER_H
