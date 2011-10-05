#include "NameFilter.h"

NameFilter::NameFilter(const QString &searchName)
    : m_searchName(searchName)
{
    setRegExp();
}

void NameFilter::setSearchName(const QString &searchName)
{
    m_searchName = searchName;
    setRegExp();
}

QString NameFilter::searchName() const
{
    return m_searchName;
}

void NameFilter::setRegExp()
{
    m_regexp = QRegExp(m_searchName);
}

bool NameFilter::matches(Node *node)
{
    if (m_regexp.isEmpty() || m_regexp.indexIn(node->fqdn()) != -1)
        return true;
    return false;
}



