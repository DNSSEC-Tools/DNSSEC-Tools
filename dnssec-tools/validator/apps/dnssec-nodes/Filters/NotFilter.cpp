#include "NotFilter.h"

#include <QLabel>

NotFilter::NotFilter(Filter *ofThis, QObject *parent)
    : Filter(parent), m_childFilter(ofThis)
{
    bindEvents();
}

void NotFilter::bindEvents() {
    if (m_childFilter) {
        connect(m_childFilter, SIGNAL(filterChanged()), this, SIGNAL(filterChanged()));
        connect(m_childFilter, SIGNAL(filterAdded()), this, SIGNAL(filterAdded()));
    }
}

void NotFilter::configWidgets(QHBoxLayout *hbox)
{
    QLabel *filterLabel = new QLabel("Not: ");
    filterLabel->setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Minimum);
    hbox->addWidget(filterLabel);
    if (m_childFilter) {
        m_childFilter->configWidgets(hbox);
    } else {
        m_filterButton = new QPushButton("Set Filter");
        connect(m_filterButton, SIGNAL(clicked()), this, SLOT(setFilter()));
        hbox->addWidget(m_filterButton);
    }
}

void NotFilter::setFilter()
{
    Filter *filter = Filter::getNewFilterFromMenu(m_filterButton->mapToGlobal(QPoint(0,0)));
    if (filter) {
        m_childFilter = filter;
        bindEvents();
        emit filterAdded();
    }
}

bool      NotFilter::matches(Node *node) {
    if (! m_childFilter)
        return false;
    return ! m_childFilter->matches(node);
}

QString   NotFilter::name() {
    return "Opposite of: " + (m_childFilter ? m_childFilter->name() : "Filter Not Selected");
}
