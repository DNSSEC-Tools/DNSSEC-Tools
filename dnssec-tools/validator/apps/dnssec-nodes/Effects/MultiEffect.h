#ifndef MULTIEFFECT_H
#define MULTIEFFECT_H

#include "Effect.h"

#include <QPushButton>

class MultiEffect : public Effect
{
    Q_OBJECT
public:
    MultiEffect(QObject *parent = 0);
    ~MultiEffect();

    virtual void    applyToNode(Node *node);
    virtual void    resetNode(Node *node);
    virtual QString name();

    virtual void    addEffect(Effect *effect);
    virtual void    clear();

    virtual void    configWidgets(QHBoxLayout *hbox);

public slots:
    virtual void    addNewEffect();

private:
    QList<Effect *> m_effects;
    QPushButton *m_addButton;
};

#endif // MULTIEFFECT_H
