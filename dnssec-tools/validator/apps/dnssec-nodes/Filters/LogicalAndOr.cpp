#include "LogicalAndOr.h"

#include <QGroupBox>
#include <QMenu>

LogicalAndOr::LogicalAndOr(QObject *parent) :
    Filter(parent), m_filters(), m_filterTypeButton(0), m_logicType(AND)
{
    connect(this, SIGNAL(logicTypeChanged()), this, SIGNAL(filterChanged()));
}

bool LogicalAndOr::matches(Node *node)
{
    if (m_filters.count() == 0)
        return true;

    if (m_logicType == AND) {
        foreach(Filter *filter, m_filters) {
            if (!filter->matches(node)) {
                return false;
            }
        }
        return true;
    } else {
        foreach(Filter *filter, m_filters) {
            if (filter->matches(node)) {
                return true;
            }
        }
        return false;
    }
}

void LogicalAndOr::configWidgets(QHBoxLayout *hbox)
{
    m_filterTypeButton = new QPushButton((m_logicType == AND ? "AND" : "OR"));
    connect(m_filterTypeButton, SIGNAL(clicked()), this, SLOT(toggleFilterType()));
    hbox->addWidget(m_filterTypeButton);

    QVBoxLayout *vbox = new QVBoxLayout();
    hbox->addLayout(vbox);

    foreach (Filter *filter, m_filters) {
        QGroupBox *box = new QGroupBox(filter->name());
        QHBoxLayout *theirbox = new QHBoxLayout;
        box->setLayout(theirbox);
        filter->configWidgets(theirbox);
        vbox->addWidget(box);
    }

    m_addFilterButton = new QPushButton("Add Filter...");
    connect(m_addFilterButton, SIGNAL(clicked()), this, SLOT(showAddFilterMenu()));
    vbox->addWidget(m_addFilterButton);
}

void LogicalAndOr::showAddFilterMenu()
{
    Filter *newFilter = getNewFilterFromMenu(m_addFilterButton->mapToGlobal(QPoint(0,0)));
    if (newFilter) {
        m_filters.push_back(newFilter);
        emit filterAdded();
    }
}


void LogicalAndOr::addFilter(Filter *newFilter)
{
    m_filters.push_back(newFilter);
    connect(newFilter, SIGNAL(filterAdded()), this, SIGNAL(filterAdded()));
    connect(newFilter, SIGNAL(filterChanged()), this, SIGNAL(filterChanged()));
    emit filterAdded();
}

void LogicalAndOr::toggleFilterType()
{
    if (m_logicType == AND) {
        m_logicType = OR;
        if (m_filterTypeButton)
            m_filterTypeButton->setText("OR");
    } else {
        m_logicType = AND;
        if (m_filterTypeButton)
            m_filterTypeButton->setText("AND");
    }
    emit filterChanged();
}
