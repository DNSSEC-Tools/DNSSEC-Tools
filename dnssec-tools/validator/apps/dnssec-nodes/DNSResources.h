#ifndef DNSRESOURCES_H
#define DNSRESOURCES_H

#include <QString>

#include <validator/validator-config.h>
#include <validator/resolver.h>

class DNSResources
{
public:
    DNSResources();

    static const char *typeToRRName(int type);
    static int         RRNameToType(const QString &name);

    static QString     rrDataToQString(ns_rr rr);
};

#endif // DNSRESOURCES_H
