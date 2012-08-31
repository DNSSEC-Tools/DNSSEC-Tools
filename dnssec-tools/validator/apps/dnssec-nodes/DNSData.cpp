#include "DNSData.h"

DNSData::DNSData()
    : m_recordType()
{
}

DNSData::DNSData(QString recordType, int DNSSECStatus)
    : m_recordType(recordType),
      m_DNSSECStatus(DNSSECStatus),
      m_node(0)
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
    case AD_VERIFIED:
        return "AD bit verified";
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
    if (m_DNSSECStatus & AD_VERIFIED)
        results.push_back(DNSSECStatusForEnum(AD_VERIFIED));

    if (m_node)
        m_node->update();

    return results;
}

// UNKNOWN really means "nothing known yet"
void DNSData::addDNSSECStatus(int additionalStatus) {
    // don't add UNKNOWN to something we do know
    if (m_DNSSECStatus != 0 && additionalStatus == UNKNOWN)
        return;

    // if we were unknown, we should now be more so remove the UNKNOWN
    if (m_DNSSECStatus & UNKNOWN)
        m_DNSSECStatus ^= UNKNOWN;

    // add in the status
    m_DNSSECStatus |= additionalStatus;

    if (m_node)
        m_node->update();
}
