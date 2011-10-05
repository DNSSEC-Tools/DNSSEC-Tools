#include "NotFilter.h"

NotFilter::NotFilter(Filter *ofThis)
    : m_childFilter(ofThis)
{
    connect(ofThis, SIGNAL(filterChanged()), this, SIGNAL(filterChanged()));
}
