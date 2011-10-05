#include "NameFilter.h"

#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <qdebug.h>

NameFilter::NameFilter(const QString &searchName)
    : m_searchName(searchName)
{
    setRegExp();
}

void NameFilter::setSearchName(QString searchName)
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

void NameFilter::configWidgets(QHBoxLayout *hbox)
{
    QLabel *filterLabel = new QLabel("Filter by RegExp:");
    hbox->addWidget(filterLabel);
    QLineEdit *filterEditBox = new QLineEdit();
    hbox->addWidget(filterEditBox);
    filterEditBox->setText(m_searchName);

    connect(filterEditBox, SIGNAL(textChanged(QString)), this, SLOT(setSearchName(QString)));
}



