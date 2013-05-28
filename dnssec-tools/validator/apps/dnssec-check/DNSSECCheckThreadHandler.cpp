#include <validator/validator-config.h>
#include <validator/validator.h>

#include "DNSSECCheckThreadHandler.h"
#include "dnssec_checks.h"

DNSSECCheckThreadHandler::DNSSECCheckThreadHandler(QObject *parent) :
    QObject(parent), m_dataList(), m_tests(), m_socketWatchers(), m_num_fds(0), m_inTestLoop(false)
{
    FD_ZERO(&m_fds);
    m_timeout.tv_sec = 0;
    m_timeout.tv_usec = 0;
    connect(this, SIGNAL(asyncTestSubmitted()), this, SLOT(updateWatchedSockets()));
    connect(this, SIGNAL(updatesMaybeAvailable()), this, SLOT(checkStatus()));

}

void DNSSECCheckThreadHandler::startTest(CheckFunction *checkFunction, char *serverAddress, bool async)
{
    int rc;

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

void DNSSECCheckThreadHandler::checkStatus()
{
    foreach(DNSSECCheckThreadData *data, m_dataList) {
        if (DNSSECTest::rcToStatus(data->m_result_status) != DNSSECTest::TESTINGNOW && DNSSECTest::rcToStatus(data->m_result_status) != DNSSECTest::UNKNOWN) {
            emit testResult(data->m_checkFunction, data->m_serverAddress, data->m_result_status, QString(data->m_msgBuffer));
            m_dataList.removeOne(data);
        }
    }
}


void
DNSSECCheckThreadHandler::dataAvailable()
{
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 1;

    // loop through everything we have now
#ifndef VAL_NO_ASYNC
    while (val_async_check_wait(NULL, NULL, NULL, &tv, 0) > 0) {
        //qDebug() << " hit";
    }
#endif

    check_outstanding_async();

    checkAvailableUpdates();
}

void
DNSSECCheckThreadHandler::checkAvailableUpdates()
{
    // tell the tests to check and emit as necessary
    foreach(DNSSECTest *test, m_tests) {
        test->update();
    }
    emit updatesMaybeAvailable();
}

void DNSSECCheckThreadHandler::startQueuedTransactions()
{
    updateWatchedSockets();
}

void
DNSSECCheckThreadHandler::updateWatchedSockets()
{
#ifndef VAL_NO_ASYNC
    if (!m_inTestLoop)
        check_queued_sends();

    // process any buffered or cache data first
    dataAvailable();

    m_num_fds = 0;
    FD_ZERO(&m_fds);
    val_async_select_info(0, &m_fds, &m_num_fds, &m_timeout);
    //qDebug() << "val sockets: " << m_num_fds;
    for(int i = 0; i < m_num_fds; i++) {
        if (FD_ISSET(i, &m_fds) && !m_socketWatchers.contains(i)) {
            //qDebug() << "watching val socket #" << i;
            QAbstractSocket *socketToWatch = new QAbstractSocket(QAbstractSocket::UdpSocket, 0);
            m_socketWatchers[i] = socketToWatch;
            socketToWatch->setSocketDescriptor(i, QAbstractSocket::ConnectedState);
            connect(socketToWatch, SIGNAL(readyRead()), this, SLOT(dataAvailable()));
        } else if (!FD_ISSET(i, &m_fds) && m_socketWatchers.contains(i)) {
            QAbstractSocket *removeThis = m_socketWatchers.take(i);
            delete removeThis;
        }
    }

    m_num_fds = 0;
    m_num_tcp_fds = 0;
    FD_ZERO(&m_fds);
    FD_ZERO(&m_tcp_fds);
    collect_async_query_select_info(&m_fds, &m_num_fds, &m_tcp_fds, &m_num_tcp_fds);
    //qDebug() << "sres sockets: " << m_num_fds;
    for(int i = 0; i < m_num_fds; i++) {
        if (FD_ISSET(i, &m_fds) && !m_socketWatchers.contains(i)) {
            //qDebug() << "watching sres socket #" << i;
            QAbstractSocket *socketToWatch = new QAbstractSocket(QAbstractSocket::UdpSocket, 0);
            m_socketWatchers[i] = socketToWatch;
            socketToWatch->setSocketDescriptor(i, QAbstractSocket::ConnectedState);
            connect(socketToWatch, SIGNAL(readyRead()), this, SLOT(dataAvailable()));
        } else if (!FD_ISSET(i, &m_fds) && m_socketWatchers.contains(i)) {
            QAbstractSocket *removeThis = m_socketWatchers.take(i);
            delete removeThis;
        }
    }
    for(int i = 0; i < m_num_tcp_fds; i++) {
        if (FD_ISSET(i, &m_tcp_fds) && !m_socketWatchers.contains(i)) {
            //qDebug() << "watching sres tcp socket #" << i;
            QAbstractSocket *socketToWatch = new QAbstractSocket(QAbstractSocket::TcpSocket, 0);
            m_socketWatchers[i] = socketToWatch;
            socketToWatch->setSocketDescriptor(i, QAbstractSocket::ConnectedState);
            connect(socketToWatch, SIGNAL(readyRead()), this, SLOT(dataAvailable()));
        } else if (!FD_ISSET(i, &m_tcp_fds) && m_socketWatchers.contains(i)) {
            QAbstractSocket *removeThis = m_socketWatchers.take(i);
            delete removeThis;
        }
    }
#endif
}

void DNSSECCheckThreadHandler::addTest(DNSSECTest *newtest)
{
    m_tests.push_back(newtest);
    if (newtest->async()) {
        connect(newtest, SIGNAL(asyncTestSubmitted()), this, SLOT(updateWatchedSockets()));
    }
}

void DNSSECCheckThreadHandler::inTestLoopChanged(bool val) {
    if (!val)
        m_socketWatchers.clear();
    m_inTestLoop = val;
}
