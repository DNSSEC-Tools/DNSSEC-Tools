#ifndef DNSSECSTATUSFILTER_H
#define DNSSECSTATUSFILTER_H

#include "Filter.h"
#include "node.h"

#include <QtCore/QSignalMapper>
#include <QtGui/QPushButton>

class DNSSECStatusFilter : public Filter
{
    Q_OBJECT

public:
    DNSSECStatusFilter(int dnssecValidity = DNSData::VALIDATED, bool requireAll = true);


    virtual bool      matches(Node *node);
    virtual QString   name() { return "DNSSEC Status Filter"; }
    virtual void      configWidgets(QHBoxLayout *hbox);

public slots:
    virtual void      setDNSSECValidity(int dnssecValidity);
    virtual void      setDNSSECValidityName(QString name);

private:
    int               m_dnssecValidity;
    bool              m_requireAll;

    QSignalMapper     m_mapper;
    QPushButton      *m_menuButton;
    QMap<DNSData::Status, QString> m_validityType;
};

#endif // DNSSECSTATUSFILTER_H
