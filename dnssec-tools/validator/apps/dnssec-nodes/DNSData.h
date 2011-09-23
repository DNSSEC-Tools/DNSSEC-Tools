#ifndef DNSDATA_H
#define DNSDATA_H

#include <QtCore/QString>
#include <QHash>

class DNSData
{
public:
    enum Status { UNKNOWN, VALIDATED, DNE, FAILED };

    DNSData();
    DNSData(QString recordType, Status DNSSECStatus);

    void setRecordType(QString recordType) { m_recordType = recordType; }
    QString recordType() const             { return m_recordType; }

    void setDNSSECStatus(Status DNSSECStatus) { m_DNSSECStatus = DNSSECStatus; }
    Status DNSSECStatus() const               { return m_DNSSECStatus; }

private:
    QString m_recordType;
    Status m_DNSSECStatus;
};

inline bool operator==(const DNSData &a, const DNSData &b)
{
    return(a.recordType() == b.recordType() && a.DNSSECStatus() == b.DNSSECStatus());
}

inline uint qHash(const DNSData &key)
{
    return qHash(key.recordType()) + key.DNSSECStatus();
}

#endif // DNSDATA_H
