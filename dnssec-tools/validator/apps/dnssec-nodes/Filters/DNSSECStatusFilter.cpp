#include "DNSSECStatusFilter.h"

DNSSECStatusFilter::DNSSECStatusFilter(int dnssecValitiy, bool requireAll)
    : m_dnssecValidity(dnssecValitiy), m_requireAll(requireAll)
{
}

bool DNSSECStatusFilter::matches(Node *node)
{
    if ((m_requireAll && (node->DNSSECValidity() & m_dnssecValidity) == m_dnssecValidity) ||
            (!m_requireAll && (node->DNSSECValidity() & m_dnssecValidity)))
        return true;
    return false;
}
