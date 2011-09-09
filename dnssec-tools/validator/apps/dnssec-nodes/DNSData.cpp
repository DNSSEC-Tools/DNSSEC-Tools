#include "DNSData.h"

DNSData::DNSData()
    : m_recordType()
{
}

DNSData::DNSData(QString recordType, Status DNSSECStatus)
    : m_recordType(recordType),
      m_DNSSECStatus(DNSSECStatus)
{

}
