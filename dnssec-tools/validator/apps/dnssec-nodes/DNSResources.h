#ifndef DNSRESOURCES_H
#define DNSRESOURCES_H

#include <QString>

class DNSResources
{
public:
    DNSResources();

    static const char *typeToRRName(int type);
    static int         RRNameToType(const QString &name);
};

#endif // DNSRESOURCES_H
