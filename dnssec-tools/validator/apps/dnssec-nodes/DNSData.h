#ifndef DNSDATA_H
#define DNSDATA_H

#include <QtCore/QString>
#include <QtCore/QStringList>
#include <QHash>

#include "node.h"
class Node;

class DNSData : public QObject
{
    Q_OBJECT
public:
    enum Status { UNKNOWN = 1, TRUSTED = 2, VALIDATED = 4, DNE = 8, FAILED = 16, IGNORE = 32, AD_VERIFIED = 64 };

    DNSData();
    DNSData(QString recordType, int DNSSECStatus);
    DNSData(const DNSData &from);

    virtual ~DNSData() {}

    void setRecordType(QString recordType)    { m_recordType = recordType; }
    QString recordType() const                { return m_recordType; }

    void setDNSSECStatus(int DNSSECStatus)    { m_DNSSECStatus = DNSSECStatus; }
    int  DNSSECStatus() const                 { return m_DNSSECStatus; }
    QString     DNSSECStatusForEnum(int status) const;
    QStringList DNSSECStringStatuses() const;

    void addDNSSECStatus(int additionalStatus);

    void setNode(Node *node) { m_node = node; }

signals:
    void statusChanged(const DNSData *data);

private:
    QString m_recordType;
    int m_DNSSECStatus;
    Node *m_node;
};

inline bool operator==(const DNSData &a, const DNSData &b)
{
    return(a.recordType() == b.recordType());
}

inline uint qHash(const DNSData &key)
{
    return qHash(key.recordType());
}

#endif // DNSDATA_H
