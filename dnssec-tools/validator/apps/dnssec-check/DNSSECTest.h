#ifndef DNSSECTEST_H
#define DNSSECTEST_H

#include <QObject>

typedef int (CheckFunction) (char *serveraddr, char *returnString, size_t returnStringSize);

class DNSSECTest : public QObject
{
    Q_OBJECT

public:
    enum lightStatus { UNKNOWN, GOOD, WARNING, BAD };

    explicit DNSSECTest(QObject *parent = 0, CheckFunction *check_function = 0, const char *serverAddress = 0, const QString &checkName = "");

    lightStatus status();
    QString statusString();
    void setStatus(lightStatus newStatus);

    const QString message() const;
    void setMessage(const QString &message);

    const QString name() const;
    int rowNumber() const;

    const QString serverAddress() const;

signals:

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
