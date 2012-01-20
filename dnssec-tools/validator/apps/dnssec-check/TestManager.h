#ifndef TESTMANAGER_H
#define TESTMANAGER_H

#include <QObject>
#include "DNSSECTest.h"

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <validator/resolver.h>
#include <validator/validator.h>

#include <QtCore/QStringList>

class TestManager : public QObject
{
    Q_OBJECT
    Q_ENUMS(testType)
public:

    enum testType
        { basic_dns,
          basic_tcp,
          do_bit,
          do_has_rrsigs,
          small_edns0,
          can_get_nsec,
          can_get_nsec3,
          can_get_dnskey,
          can_get_ds
        };
    explicit TestManager(QObject *parent = 0);

    Q_INVOKABLE DNSSECTest *makeTest(testType type, QString address, QString name);
    Q_INVOKABLE QStringList loadResolvConf();

signals:

public slots:

private:
    QObject *m_parent;
    QStringList  m_serverAddresses;
};

#endif // TESTMANAGER_H
