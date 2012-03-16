#include "DNSSECTest.h"

#include <qdebug.h>

DNSSECTest::DNSSECTest(QObject *parent, CheckFunction *check_function, const char *serverAddress, const QString &checkName, bool isAsync) :
    QObject(parent), m_status(UNKNOWN), m_checkFunction(check_function), m_serverAddress(0), m_checkName(checkName), m_statusStrings(),
    m_async(isAsync), m_result_status(-1)
{
    if (serverAddress)
        m_serverAddress = strdup(serverAddress);

    m_msgBuffer[0] = 0;
    m_msgBuffer[sizeof(m_msgBuffer)-1] = 0;
    strcpy(m_msgBuffer, "Unknown");

    m_statusStrings.insert(UNKNOWN, "unknown");
    m_statusStrings.insert(GOOD, "good");
    m_statusStrings.insert(BAD, "bad");
    m_statusStrings.insert(WARNING, "warning");
    m_statusStrings.insert(TESTINGNOW, "testing");
}

DNSSECTest::DNSSECTest(const DNSSECTest &copyFrom) :
    m_status(copyFrom.m_status), m_checkFunction(copyFrom.m_checkFunction),
    m_serverAddress(0), m_checkName(copyFrom.m_checkName), m_statusStrings(copyFrom.m_statusStrings)
{
    if (copyFrom.m_serverAddress) {
        m_serverAddress = strdup(copyFrom.m_serverAddress);
    }
    m_msgBuffer[0] = 0;
    if (copyFrom.m_msgBuffer[0]) {
        strncpy(m_msgBuffer, copyFrom.m_msgBuffer, qMax(strlen(copyFrom.m_msgBuffer), sizeof(m_msgBuffer)-1));
    }
}


DNSSECTest::lightStatus DNSSECTest::status()
{
    return m_status;
}

void DNSSECTest::setStatus(DNSSECTest::lightStatus newStatus)
{
    if (newStatus != m_status) {
        m_status = newStatus;
        m_result_status = statusToRc(m_status);
        emit statusChanged();
        if (m_status == UNKNOWN)
            setMessage("Unknown");
    }
}

void DNSSECTest::check()
{
    if (!m_checkFunction || !m_serverAddress)
        return;
    m_result_status = TESTINGNOW;
    int rc = (*m_checkFunction)(m_serverAddress, m_msgBuffer, sizeof(m_msgBuffer), &m_result_status);
    if (m_async) {
        emit asyncTestSubmitted();
        setStatus(TESTINGNOW);
        return;
    }
    setStatus(rcToStatus(rc));
    setMessage(QString(m_msgBuffer));
}

DNSSECTest::lightStatus DNSSECTest::rcToStatus(int rc) {
    if (rc == 0)
        return GOOD;
    if (rc == 1)
        return BAD;
    if (rc == 2)
        return WARNING;
    return UNKNOWN;
}

int DNSSECTest::statusToRc(DNSSECTest::lightStatus status) {
    switch (status) {
    case GOOD:
        return 0;
    case BAD:
        return 1;
    case WARNING:
        return 2;
    default:
        return -1;
    }
}

void DNSSECTest::setMessage(const QString &message)
{
    strncpy(m_msgBuffer, message.toAscii().data(), sizeof(m_msgBuffer)-1);
    emit messageChanged();
    emit messageChanged(message);
}

const QString DNSSECTest::message() const
{
    return QString(m_msgBuffer);
}

const QString DNSSECTest::serverAddress() const
{
    return QString(m_serverAddress);
}

bool DNSSECTest::async() const
{
    return m_async;
}

void DNSSECTest::setAsync(bool async)
{
    m_async = async;
    emit asyncChanged();
}

void DNSSECTest::update()
{
    if (m_async && statusToRc(m_status) != m_result_status) {
        //qDebug() << "Updating: (" << this << ") "<< m_status << " -> " << m_result_status;
        setStatus(rcToStatus(m_result_status));
    }
}

const QString DNSSECTest::name() const
{
    return m_checkName;
}

QString DNSSECTest::statusString()
{
    return m_statusStrings[m_status];
}
