#ifndef SETBorderColor_H
#define SETBorderColor_H

#include <QColor>

#include "Effect.h"

class SetBorderColor : public Effect
{
public:
    SetBorderColor(QColor borderColor);

    virtual void    applyToNode(Node *node);
    virtual void    resetNode(Node *node);
    virtual QString name() { return "Raise or Lower the Node"; }

private:
    QColor    m_borderColor;
};

#endif // SETBorderColor_H
