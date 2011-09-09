#ifndef DNSDATA_H
#define DNSDATA_H

#include <QtCore/QString>

class DNSData
{
public:
    enum Status { UNKNOWN, VALIDATED, DNE, FAILED };

    DNSData();
    DNSData(QString recordType, Status DNSSECStatus);


    void setRecordType(QString recordType) { m_recordType = recordType; }
    void setDNSSECStatus(Status DNSSECStatus) { m_DNSSECStatus = DNSSECStatus; }

private:
    QString m_recordType;
    Status m_DNSSECStatus;
};

#endif // DNSDATA_H
