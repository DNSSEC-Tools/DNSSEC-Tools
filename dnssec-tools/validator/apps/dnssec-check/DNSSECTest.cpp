#include "DNSSECTest.h"

#include <qdebug.h>

DNSSECTest::DNSSECTest(QObject *parent, CheckFunction *check_function, const char *serverAddress, const QString &checkName) :
    QObject(parent), m_status(UNKNOWN), m_checkFunction(check_function), m_serverAddress(0), m_checkName(checkName), m_statusStrings()
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
        emit statusChanged();
        if (m_status == UNKNOWN)
            setMessage("Unknown");
    }
}

void DNSSECTest::check()
{
    if (!m_checkFunction || !m_serverAddress)
        return;
    int rc = (*m_checkFunction)(m_serverAddress, m_msgBuffer, sizeof(m_msgBuffer));
    if (rc == 0)
        setStatus(GOOD);
    if (rc == 1)
        setStatus(BAD);
    if (rc == 2)
        setStatus(WARNING);
    setMessage(QString(m_msgBuffer));
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

const QString DNSSECTest::name() const
{
    return m_checkName;
}

QString DNSSECTest::statusString()
{
    return m_statusStrings[m_status];
}
