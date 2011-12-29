#ifndef DNSSECTEST_H
#define DNSSECTEST_H

#include <QObject>

typedef int (CheckFunction) (char *serveraddr, char *returnString, size_t returnStringSize);

class DNSSECTest : public QObject
{
    Q_OBJECT

public:
    Q_ENUMS(lightStatus)
    enum lightStatus { UNKNOWN, GOOD, WARNING, BAD };

    Q_PROPERTY(lightStatus status     READ status        WRITE setStatus   NOTIFY statusChanged)
    Q_PROPERTY(QString message        READ message       WRITE setMessage  NOTIFY messageChanged)
    Q_PROPERTY(QString name           READ name                            NOTIFY nameChanged)
    Q_PROPERTY(QString serverAddress  READ serverAddress                   NOTIFY serverAddressChanged)

    DNSSECTest(QObject *parent = 0, CheckFunction *check_function = 0, const char *serverAddress = 0, const QString &checkName = "");
    DNSSECTest(const DNSSECTest &copyFrom);

    lightStatus status();
    QString statusString();
    void setStatus(lightStatus newStatus);

    const QString message() const;
    void setMessage(const QString &message);

    const QString name() const;

    const QString serverAddress() const;

signals:
    void statusChanged();
    void messageChanged();
    void nameChanged();
    void serverAddressChanged();

public slots:
    void check();

private:
    lightStatus    m_status;
    CheckFunction *m_checkFunction;
    char           m_msgBuffer[4096];
    char          *m_serverAddress;
    QString        m_checkName;
    QList<QString> m_statusStrings;
};

#endif // DNSSECTEST_H
