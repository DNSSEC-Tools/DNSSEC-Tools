#ifndef SETALPHAEFFECT_H
#define SETALPHAEFFECT_H

#include "Effect.h"

class SetAlphaEffect : public Effect
{
public:
    SetAlphaEffect(unsigned int alpha);


    virtual void    applyToNode(Node *node);
    virtual void    resetNode(Node *node);
    virtual QString name() { return "Set Alpha Value"; }

private:
    unsigned int    m_alpha;
};

#endif // SETALPHAEFFECT_H
