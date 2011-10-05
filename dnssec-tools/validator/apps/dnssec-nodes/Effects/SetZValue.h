#ifndef SETZVALUE_H
#define SETZVALUE_H

#include "Effect.h"

class SetZValue : public Effect
{
public:
    SetZValue(int zvalue);

    virtual void    applyToNode(Node *node);
    virtual void    resetNode(Node *node);
    virtual QString name() { return "Raise or Lower the Node"; }

private:
    int    m_zvalue;
};

#endif // SETZVALUE_H
