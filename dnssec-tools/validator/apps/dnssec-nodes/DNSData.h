#ifndef DNSDATA_H
#define DNSDATA_H

#include <QGraphicsScene>
#include <QString>
#include <QStringList>
#include <QHash>
#include <QSet>

#include "node.h"
class Node;

class DNSData : public QObject
{
    Q_OBJECT
public:
    enum Status { UNKNOWN = 1, TRUSTED = 2, VALIDATED = 4, DNE = 8, FAILED = 16, IGNORE = 32, AD_VERIFIED = 64, SERVFAIL_RCODE = 128,
                  AUTHORATATIVE = 256, DSNOMATCH = 512 };

    DNSData();
    DNSData(QString recordType, int DNSSECStatus);
    DNSData(QString recordType, int DNSSECStatus, const QStringList &data);
    DNSData(const DNSData &from);

    static Status getStatusFromValStatus(int val_status);
    static Status getStatusFromValAStatus(int val_astatus);

    virtual ~DNSData() {}

    void setRecordType(QString recordType)    { m_recordType = recordType; }
    QString recordType() const                { return m_recordType; }

    void setDNSSECStatus(int DNSSECStatus)    { m_DNSSECStatus = DNSSECStatus; }
    int  DNSSECStatus() const                 { return m_DNSSECStatus; }
    QString     DNSSECStatusForEnum(int status) const;
    QStringList DNSSECStringStatuses() const;

    void addDNSSECStatus(int additionalStatus);

    void setNode(Node *node) { m_node = node; }

    void addData(const QStringList &data);
    QList<QString> data() const;

signals:
    void statusChanged(const DNSData *data);

private:
    QString m_recordType;
    int m_DNSSECStatus;
    Node *m_node;
    QSet<QString> m_data;
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
