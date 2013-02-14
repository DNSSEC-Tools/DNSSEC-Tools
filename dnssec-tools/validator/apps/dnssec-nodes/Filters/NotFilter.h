#ifndef NOTFILTER_H
#define NOTFILTER_H

#include "Filter.h"

#include <QPushButton>

class NotFilter : public Filter
{
    Q_OBJECT

public:
    NotFilter(Filter *ofThis = 0, QObject *parent = 0);
    void bindEvents();

    virtual bool      matches(Node *node);
    virtual QString   name();
    virtual void      configWidgets(QHBoxLayout *hbox);

public slots:
    virtual void      setFilter();

private:
    Filter *m_childFilter;
    QPushButton *m_filterButton;
};

#endif // NOTFILTER_H
