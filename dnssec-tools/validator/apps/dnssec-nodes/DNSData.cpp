#include "DNSData.h"

DNSData::DNSData()
    : m_recordType()
{
}

DNSData::DNSData(QString recordType, int DNSSECStatus)
    : m_recordType(recordType),
      m_DNSSECStatus(DNSSECStatus)
{

}

QString DNSData::DNSSECStatusForEnum(int status) const
{
    switch (status) {
    case UNKNOWN:
        return "Unknown";
    case TRUSTED:
        return "Trusted";
    case VALIDATED:
        return "Validated";
    case DNE:
        return "Does Not Exist";
    case FAILED:
        return "DNSSEC Failed";
    case IGNORE:
        return "Validation Not Needed";
    case DNE|VALIDATED:
        return "Proven to not exist";
    default:
        return "Unknown Status";
    }
    return "No Such Status";
}

QStringList DNSData::DNSSECStringStatuses() const
{
    QStringList results;
    if (m_DNSSECStatus & UNKNOWN)
        results.push_back(DNSSECStatusForEnum(UNKNOWN));
    if (m_DNSSECStatus & TRUSTED)
        results.push_back(DNSSECStatusForEnum(TRUSTED));
    if (m_DNSSECStatus & VALIDATED)
        results.push_back(DNSSECStatusForEnum(VALIDATED));
    if (m_DNSSECStatus & DNE)
        results.push_back(DNSSECStatusForEnum(DNE));
    if (m_DNSSECStatus & FAILED)
        results.push_back(DNSSECStatusForEnum(FAILED));
    if (m_DNSSECStatus & IGNORE)
        results.push_back(DNSSECStatusForEnum(IGNORE));
    return results;
}

