#ifndef FILTER_H
#define FILTER_H

#include <QObject>
#include <QtGui/QHBoxLayout>

#include "node.h"

class Filter : public QObject
{
    Q_OBJECT
public:
    Filter();

    virtual bool      matches(Node *node) = 0;
    virtual QString   name() = 0;
    virtual void      configWidgets(QHBoxLayout *hbox) { Q_UNUSED(hbox); }
};

#endif // FILTER_H
