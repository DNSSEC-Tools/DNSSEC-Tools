#include "DNSSECStatusFilter.h"

#include <QtGui/QMenu>
#include <QtGui/QLabel>

DNSSECStatusFilter::DNSSECStatusFilter(int dnssecValitiy, bool requireAll)
    : m_dnssecValidity(dnssecValitiy), m_requireAll(requireAll), m_mapper(), m_menuButton(0)
{
    m_validityType[DNSData::UNKNOWN] = "That Have an Unkown (Inccomplete) Status";
    m_validityType[DNSData::TRUSTED] = "That Are Trusted";
    m_validityType[DNSData::VALIDATED]  = "That Were Validated";
    m_validityType[DNSData::FAILED] =  "That Failed Validation";
    m_validityType[DNSData::DNE] = "Which Do Not Exist";

}

bool DNSSECStatusFilter::matches(Node *node)
{
    if ((m_requireAll && (node->DNSSECValidity() & m_dnssecValidity) == m_dnssecValidity) ||
            (!m_requireAll && (node->DNSSECValidity() & m_dnssecValidity)))
        return true;
    return false;
}

void DNSSECStatusFilter::configWidgets(QHBoxLayout *hbox)
{
    QLabel *filterLabel = new QLabel("Highlight Nodes That Contain Records:");
    hbox->addWidget(filterLabel);


    QMenu *statusMenu = new QMenu();
    m_menuButton = new QPushButton("I am broken");
    m_menuButton->setMenu(statusMenu);
    hbox->addWidget(m_menuButton);


    QAction *action;

    // enum Status { UNKNOWN = 1, TRUSTED = 2, VALIDATED = 4, DNE = 8, FAILED = 16, IGNORE = 32 };

    QMap<DNSData::Status, QString>::const_iterator i = m_validityType.constBegin();
    while(i != m_validityType.constEnd()) {
        action = statusMenu->addAction(i.value());
        connect(action, SIGNAL(triggered()), &m_mapper, SLOT(map()));
        m_mapper.setMapping(action, i.key());
        m_mapper.setMapping(action, action->text());

        if (i.key() == m_dnssecValidity)
            m_menuButton->setText(action->text());

        ++i;
    }

    connect(&m_mapper, SIGNAL(mapped(int)), this, SLOT(setDNSSECValidity(int)));
    connect(&m_mapper, SIGNAL(mapped(QString)), this, SLOT(setDNSSECValidityName(QString)));
}

void DNSSECStatusFilter::setDNSSECValidityName(QString name)
{
    m_menuButton->setText(name);
}

void DNSSECStatusFilter::setDNSSECValidity(int dnssecValidity)
{
    m_dnssecValidity = dnssecValidity;
    emit filterChanged();
}

