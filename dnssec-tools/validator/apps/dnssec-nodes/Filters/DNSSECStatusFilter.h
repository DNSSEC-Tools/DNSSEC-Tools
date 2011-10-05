#ifndef DNSSECSTATUSFILTER_H
#define DNSSECSTATUSFILTER_H

#include "Filter.h"
#include "node.h"

class DNSSECStatusFilter
{
public:
    DNSSECStatusFilter(int dnssecValidity, bool requireAll = true);

    virtual bool      matches(Node *node);
    virtual QString   name() { return "DNSSEC Status Filter"; }

private:
    int               m_dnssecValidity;
    bool              m_requireAll;
};

#endif // DNSSECSTATUSFILTER_H
