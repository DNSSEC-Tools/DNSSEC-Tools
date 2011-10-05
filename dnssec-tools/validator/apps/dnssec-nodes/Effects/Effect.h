#ifndef EFFECT_H
#define EFFECT_H

#include "node.h"

class Effect
{
public:
    Effect();

    virtual void    applyToNode(Node *node) = 0;
    virtual void    resetNode(Node *node) = 0;
    virtual QString name() = 0;
};

#endif // EFFECT_H
