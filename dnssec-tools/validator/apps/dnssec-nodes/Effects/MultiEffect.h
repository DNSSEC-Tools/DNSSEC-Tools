#ifndef MULTIEFFECT_H
#define MULTIEFFECT_H

#include "Effect.h"

class MultiEffect : public Effect
{
public:
    MultiEffect();
    ~MultiEffect();

    virtual void    applyToNode(Node *node);
    virtual void    resetNode(Node *node);
    virtual QString name();

    virtual void    addEffect(Effect *effect);
    virtual void    clear();

private:
    QList<Effect *> m_effects;

};

#endif // MULTIEFFECT_H
