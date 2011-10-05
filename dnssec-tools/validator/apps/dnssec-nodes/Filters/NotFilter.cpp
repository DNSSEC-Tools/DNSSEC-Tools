#include "NotFilter.h"

NotFilter::NotFilter(Filter *ofThis)
    : m_childFilter(ofThis)
{
}
