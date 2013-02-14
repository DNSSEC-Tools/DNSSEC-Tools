#include "TypeFilter.h"

#include <QtGui/QLabel>
#include <QtGui/QMenu>

#include <qdebug.h>

TypeFilter::TypeFilter(QString type, QObject *parent)
    : Filter(parent), m_type(type), m_menuButton(0), m_mapper(this), m_typeMenu(0)
{
}

TypeFilter::~TypeFilter()
{
    if (m_typeMenu)
        delete m_typeMenu;
}

bool TypeFilter::matches(Node *node)
{
    if (node->subDataExistsFor(m_type))
        return true;
    return false;
}

void TypeFilter::configWidgets(QHBoxLayout *hbox)
{
    QLabel *filterLabel = new QLabel("Nodes with Record Type:");
    filterLabel->setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Minimum);
    hbox->addWidget(filterLabel);

    m_menuButton = new QPushButton(m_type);
    hbox->addWidget(m_menuButton);

    m_typeMenu = new TypeMenu(m_menuButton);
    connect(m_typeMenu, SIGNAL(typeSet(QString)), this, SLOT(setQueryType(QString)));

}

void TypeFilter::setQueryType(QString type)
{
    m_type = type;
    emit filterChanged();
}
