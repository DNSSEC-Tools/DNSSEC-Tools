#ifndef DNSSECCHECKTHREAD_H
#define DNSSECCHECKTHREAD_H

#include <QThread>
#include <QtCore/QList>
#include "DNSSECTest.h"

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

private:
    QList<DNSSECCheckThreadData *> m_dataList;
};

class DNSSECCheckThread : public QThread
{
    Q_OBJECT
public:
    explicit DNSSECCheckThread() : m_handler(0) { }
    void run();
    DNSSECCheckThreadHandler *handler() { return m_handler; }

signals:
    void handlerReady(DNSSECCheckThreadHandler *);

private:
    DNSSECCheckThreadHandler *m_handler;
};

#endif // DNSSECCHECKTHREAD_H
