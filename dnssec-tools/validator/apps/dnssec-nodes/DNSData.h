#ifndef DNSDATA_H
#define DNSDATA_H

#include <QtCore/QString>
#include <QHash>

class DNSData
{
public:
    enum Status { UNKNOWN = 1, TRUSTED = 2, VALIDATED = 4, DNE = 8, FAILED = 16 };

    DNSData();
    DNSData(QString recordType, Status DNSSECStatus);

    void setRecordType(QString recordType)    { m_recordType = recordType; }
    QString recordType() const                { return m_recordType; }

    void setDNSSECStatus(int DNSSECStatus)    { m_DNSSECStatus = DNSSECStatus; }
    int  DNSSECStatus() const                 { return m_DNSSECStatus; }

    void addDNSSECStatus(int additionalStatus) {
        if (m_DNSSECStatus & UNKNOWN) // we now should known something
            m_DNSSECStatus ^= UNKNOWN;
        m_DNSSECStatus |= additionalStatus;
    }

private:
    QString m_recordType;
    int m_DNSSECStatus;
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
