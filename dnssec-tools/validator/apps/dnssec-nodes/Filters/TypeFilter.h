#ifndef TYPEFILTER_H
#define TYPEFILTER_H

#include "Filter.h"
#include <QtGui/QPushButton>
#include <QtCore/QSignalMapper>

class TypeFilter : public Filter
{
    Q_OBJECT
public:
    explicit TypeFilter(QString type);

    virtual QString   name() { return "Type Filter"; }

    virtual bool      matches(Node *node);
    virtual void      configWidgets(QHBoxLayout *hbox);


signals:

public slots:
    virtual void      setQueryType(QString type);

private:
    void createTypeMenu();

    QString        m_type;
    QPushButton   *m_menuButton;
    QSignalMapper  m_mapper;
};

#endif // TYPEFILTER_H
