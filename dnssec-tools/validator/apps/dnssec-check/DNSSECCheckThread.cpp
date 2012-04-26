#include "DNSSECCheckThread.h"

#include <qdebug.h>

DNSSECCheckThread::DNSSECCheckThread(QObject *parent) :
    QThread(parent)
{
}

void DNSSECCheckThread::run()
{
    qDebug() << "other thread started (current=" << QThread::currentThread() << ") && tid=" << QThread::currentThreadId();
    exec();
}

void DNSSECCheckThread::startTest(CheckFunction *checkFunction, char *serverAddress, bool async)
{
    int rc;
    qDebug() << "testing in other thread (" << QThread::currentThread() << "): && tid=" << QThread::currentThreadId() << " -- " << serverAddress;

    if (!checkFunction || !serverAddress)
        return;

    DNSSECCheckThreadData *data = new DNSSECCheckThreadData();

    data->m_serverAddress = serverAddress;
    data->m_checkFunction = checkFunction;
    data->m_result_status = DNSSECTest::TESTINGNOW;
    rc = (*checkFunction)(data->m_serverAddress, data->m_msgBuffer, sizeof(data->m_msgBuffer), &data->m_result_status);
    if (async) {
        m_dataList.push_back(data);
        emit asyncTestSubmitted();
        return;
    }
    emit testResult(checkFunction, serverAddress, data->m_result_status, QString(data->m_msgBuffer));
    delete data;
}

void DNSSECCheckThread::checkStatus()
{
    if (m_dataList.count() > 0)
        qDebug() << "checking list: " << m_dataList.count();
    foreach(DNSSECCheckThreadData *data, m_dataList) {
        if (DNSSECTest::rcToStatus(data->m_result_status) != DNSSECTest::TESTINGNOW) {
            qDebug() << "got result for " << data->m_serverAddress;
            emit testResult(data->m_checkFunction, data->m_serverAddress, data->m_result_status, QString(data->m_msgBuffer));
            m_dataList.removeOne(data);
        }
    }
}
