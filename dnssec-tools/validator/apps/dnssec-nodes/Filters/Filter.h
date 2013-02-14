#ifndef FILTER_H
#define FILTER_H

#include <QObject>
#include <QtGui/QHBoxLayout>

#include "node.h"
#include <qdebug.h>

class Filter : public QObject
{
    Q_OBJECT
public:
    Filter(QObject *parent = 0);

    virtual bool      matches(Node *node) = 0;
    virtual QString   name() = 0;
    virtual void      configWidgets(QHBoxLayout *hbox) { Q_UNUSED(hbox); }

    void              filterHasChanged() { emit filterChanged(); }

    static Filter    *getNewFilterFromMenu(QPoint where);

signals:
    void              filterChanged();
    void              filterAdded();
};

#endif // FILTER_H
