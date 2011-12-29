#include "DNSSECTest.h"

DNSSECTest::DNSSECTest(QObject *parent, CheckFunction *check_function, const char *serverAddress, const QString &checkName) :
    QObject(parent), m_status(UNKNOWN), m_checkFunction(check_function), m_serverAddress(0), m_checkName(checkName), m_statusStrings()
{
    if (serverAddress)
        m_serverAddress = strdup(serverAddress);

    m_msgBuffer[0] = 0;
    m_msgBuffer[sizeof(m_msgBuffer)-1] = 0;

    m_statusStrings.insert(UNKNOWN, "unknown");
    m_statusStrings.insert(GOOD, "good");
    m_statusStrings.insert(BAD, "bad");
    m_statusStrings.insert(WARNING, "warning");
}

DNSSECTest::lightStatus DNSSECTest::status()
{
    return m_status;
}

void DNSSECTest::setStatus(DNSSECTest::lightStatus newStatus)
{
    m_status = newStatus;
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
}

void DNSSECTest::setMessage(const QString &message)
{
    strncpy(m_msgBuffer, message.toAscii().data(), sizeof(m_msgBuffer)-1);
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
