#ifndef EFFECT_H
#define EFFECT_H

#include "node.h"

#include <QObject>
#include <QHBoxLayout>

class Effect: public QObject
{
    Q_OBJECT
public:
    Effect(QObject *parent = 0);
    virtual ~Effect() { }

    virtual void    applyToNode(Node *node) = 0;
    virtual void    resetNode(Node *node) = 0;
    virtual QString name() = 0;

    virtual void    configWidgets(QHBoxLayout *hbox) { Q_UNUSED(hbox); }

    static Effect  *getNewEffectFromMenu(QPoint where);
signals:

    void effectChanged();
    void effectAdded();
};

#endif // EFFECT_H
