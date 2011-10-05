#ifndef NOTFILTER_H
#define NOTFILTER_H

#include "Filter.h"

class NotFilter : public Filter
{
    Q_OBJECT

public:
    NotFilter(Filter *ofThis);

    virtual bool      matches(Node *node) { return ! m_childFilter->matches(node); }
    virtual QString   name() { return "Opposite of: " + m_childFilter->name(); }
    virtual void      configWidgets(QHBoxLayout *hbox) { m_childFilter->configWidgets(hbox); }

private:
    Filter *m_childFilter;
};

#endif // NOTFILTER_H
