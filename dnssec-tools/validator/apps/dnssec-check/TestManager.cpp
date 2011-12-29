#include "TestManager.h"
#include "dnssec_checks.h"
#include "qdebug.h"

#include <QtCore/QFile>
#include <QtCore/QRegExp>

TestManager::TestManager(QObject *parent) :
    QObject(parent), m_parent(parent)
{
}

DNSSECTest *TestManager::makeTest(testType type, QString address, QString name) {
    qDebug() << "creating " << address << " of type " << type << " and named " << name;
    switch (type) {
    case basic_dns:
            return new DNSSECTest(m_parent, &check_basic_dns, address.toAscii().data(), name);
    case basic_tcp:
            return new DNSSECTest(m_parent, &check_basic_tcp, address.toAscii().data(), name);
    case do_bit:
            return new DNSSECTest(m_parent, &check_do_bit, address.toAscii().data(), name);
    case do_has_rrsigs:
            return new DNSSECTest(m_parent, &check_do_has_rrsigs, address.toAscii().data(), name);
    case small_edns0:
            return new DNSSECTest(m_parent, &check_small_edns0, address.toAscii().data(), name);
    case can_get_nsec:
            return new DNSSECTest(m_parent, &check_can_get_nsec, address.toAscii().data(), name);
    case can_get_nsec3:
            return new DNSSECTest(m_parent, &check_can_get_nsec3, address.toAscii().data(), name);
    case can_get_dnskey:
            return new DNSSECTest(m_parent, &check_can_get_dnskey, address.toAscii().data(), name);
    case can_get_ds:
            return new DNSSECTest(m_parent, &check_can_get_ds, address.toAscii().data(), name);
    }
    return 0;
}

QStringList TestManager::loadResolvConf()
{
    const char *resolv_conf_file = resolv_conf_get();

#ifdef SMALL_DEVICE
    if (strcmp(resolv_conf_file, "/dev/null") == 0) {
        resolv_conf_file = "/var/run/resolv.conf.wlan0";
    }
#endif

    QFile resolvConf(resolv_conf_file);
    resolvConf.open(QIODevice::ReadOnly);

    QRegExp nsRegexp("^\\s*nameserver\\s+(\\S+)");
    qDebug() << "reading " << resolv_conf_file;

    while (!resolvConf.atEnd()) {
        QByteArray line = resolvConf.readLine();
        if (nsRegexp.indexIn(line) != -1) {
            m_serverAddresses.push_back(nsRegexp.cap(1));
        }
    }
    resolvConf.close();
    qDebug() << m_serverAddresses;
    return m_serverAddresses;
}



void TestManager::bogusTest()
{
    qDebug() << "here bogustest";
}
