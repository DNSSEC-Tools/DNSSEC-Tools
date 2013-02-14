#ifndef NAMEFILTER_H
#define NAMEFILTER_H

#include "Filter.h"

class NameFilter : public Filter
{
    Q_OBJECT
public:
    NameFilter(const QString &searchName = "", QObject *parent = 0);

    QString searchName() const;

    virtual bool      matches(Node *node);
    virtual QString   name() { return "Name Filter"; }
    virtual void      configWidgets(QHBoxLayout *hbox);

public slots:
    void setSearchName(QString searchName);

protected:
    virtual void      setRegExp();

private:
    QString m_searchName;
    QRegExp m_regexp;
};

#endif // NAMEFILTER_H
