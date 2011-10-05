#ifndef NOTFILTER_H
#define NOTFILTER_H

#include "Filter.h"

class NotFilter : public Filter
{
public:
    NotFilter(Filter *ofThis);

    virtual bool      matches(Node *node) { return ! m_childFilter->matches(node); }
    virtual QString   name() { return "Opposite of: " + m_childFilter->name(); }

private:
    Filter *m_childFilter;
};

#endif // NOTFILTER_H
