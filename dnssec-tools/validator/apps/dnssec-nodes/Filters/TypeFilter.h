#ifndef TYPEFILTER_H
#define TYPEFILTER_H

#include "Filter.h"
#include "TypeMenu.h"

#include <QtGui/QPushButton>
#include <QtCore/QSignalMapper>

class TypeFilter : public Filter
{
    Q_OBJECT
public:
    explicit TypeFilter(QString type);
    ~TypeFilter();

    virtual QString   name() { return "Type Filter"; }

    virtual bool      matches(Node *node);
    virtual void      configWidgets(QHBoxLayout *hbox);


signals:

public slots:
    virtual void      setQueryType(QString type);

private:
    QString        m_type;
    QPushButton   *m_menuButton;
    QSignalMapper  m_mapper;
    TypeMenu      *m_typeMenu;
};

#endif // TYPEFILTER_H
