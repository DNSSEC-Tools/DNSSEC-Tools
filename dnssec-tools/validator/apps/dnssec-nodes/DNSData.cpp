#include "DNSData.h"

#include <validator/validator-config.h>
#include <validator/validator.h>

#include <qdebug.h>

DNSData::DNSData()
    : QObject(), m_recordType()
{
}

DNSData::DNSData(QString recordType, int DNSSECStatus)
    : QObject(),
      m_recordType(recordType),
      m_DNSSECStatus(DNSSECStatus),
      m_node(0), m_data()
{

}

DNSData::DNSData(QString recordType, int DNSSECStatus, const QStringList &data)
    : QObject(),
      m_recordType(recordType),
      m_DNSSECStatus(DNSSECStatus),
      m_node(0), m_data()
{
    addData(data);
}

DNSData::DNSData(const DNSData &from)
    : QObject(), m_recordType(from.m_recordType), m_DNSSECStatus(from.m_DNSSECStatus), m_node(from.m_node)
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
    case SERVFAIL_RCODE:
        return "SERVFAIL set";
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
    if (m_DNSSECStatus & SERVFAIL_RCODE)
        results.push_back(DNSSECStatusForEnum(SERVFAIL_RCODE));

    return results;
}

// UNKNOWN really means "nothing known yet"
void DNSData::addDNSSECStatus(int additionalStatus) {
    int oldStatus = m_DNSSECStatus;

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

    if (oldStatus != m_DNSSECStatus)
        emit statusChanged(this);
}

void DNSData::addData(const QStringList &data)
{
    foreach (const QString item, data) {
        m_data.insert(item);
    }
}

QList<QString> DNSData::data() {
    return m_data.toList();
}

DNSData::Status DNSData::getStatusFromValStatus(int val_status) {
    if (val_isvalidated(val_status)) {
        return DNSData::VALIDATED;
    } else if (val_istrusted(val_status)) {
        return DNSData::TRUSTED;
    } else {
        return DNSData::FAILED;
    }
}

DNSData::Status DNSData::getStatusFromValAStatus(int val_astatus) {
    if (val_astatus == VAL_AC_VERIFIED_LINK ||
            val_astatus == VAL_AC_RRSIG_VERIFIED ||
            val_astatus == VAL_AC_SIGNING_KEY)
        return DNSData::VALIDATED;

    if (val_astatus == VAL_AC_UNSET)
        return DNSData::UNKNOWN;

    if (val_astatus == VAL_AC_TRUST_POINT)
        return DNSData::TRUSTED;

    qDebug() << "unknown astatus: " << val_astatus;
    return DNSData::UNKNOWN;
}
