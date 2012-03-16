#include "TestManager.h"
#include "dnssec_checks.h"
#include "qdebug.h"

#include <arpa/inet.h>

#include <validator/validator-config.h>
#include <validator/validator.h>

#include <QtCore/QFile>
#include <QtCore/QRegExp>
#include <QtCore/QUrl>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QNetworkReply>
#include <QSettings>
#include <QCryptographicHash>

TestManager::TestManager(QObject *parent) :
    QObject(parent), m_parent(parent), m_manager(0), m_lastResultMessage(), m_socketWatchers(),
    m_tests(), m_num_fds(0)
{
    FD_ZERO(&m_fds);
    m_timeout.tv_sec = 0;
    m_timeout.tv_usec = 0;
}

void
TestManager::dataAvailable()
{
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 1;

    // loop through everything we have now
    while (val_async_check_wait(NULL, NULL, NULL, &tv, 0) > 0) {
        //qDebug() << " hit";
    }

    // tell the tests to check and emit as necessary
    foreach(DNSSECTest *test, m_tests) {
        test->update();
    }
}

void
TestManager::updateWatchedSockets()
{
    // process any buffered or cache data first
    dataAvailable();

    m_num_fds = 0;
    FD_ZERO(&m_fds);
    val_async_select_info(0, &m_fds, &m_num_fds, &m_timeout);
    for(int i = 0; i < m_num_fds; i++) {
        if (FD_ISSET(i, &m_fds) && !m_socketWatchers.contains(i)) {
            QAbstractSocket *socketToWatch = new QAbstractSocket(QAbstractSocket::UdpSocket, 0);
            m_socketWatchers[i] = socketToWatch;
            socketToWatch->setSocketDescriptor(i, QAbstractSocket::ConnectedState);
            connect(socketToWatch, SIGNAL(readyRead()), this, SLOT(dataAvailable()));
            //qDebug() << "Watching socket #" << i;
        }
    }
}

DNSSECTest *TestManager::makeTest(testType type, QString address, QString name) {
    DNSSECTest *newtest = 0;

    switch (type) {
    case basic_dns:
        newtest =  new DNSSECTest(m_parent, &check_basic_dns, address.toAscii().data(), name);
        break;
    case basic_tcp:
        newtest =  new DNSSECTest(m_parent, &check_basic_tcp, address.toAscii().data(), name);
        break;
    case do_bit:
        newtest =  new DNSSECTest(m_parent, &check_do_bit, address.toAscii().data(), name);
        break;
    case ad_bit:
        newtest =  new DNSSECTest(m_parent, &check_ad_bit, address.toAscii().data(), name);
        break;
    case do_has_rrsigs:
        newtest =  new DNSSECTest(m_parent, &check_do_has_rrsigs, address.toAscii().data(), name);
        break;
    case small_edns0:
        newtest =  new DNSSECTest(m_parent, &check_small_edns0, address.toAscii().data(), name);
        break;
    case can_get_nsec:
        newtest =  new DNSSECTest(m_parent, &check_can_get_nsec, address.toAscii().data(), name);
        break;
    case can_get_nsec3:
        newtest =  new DNSSECTest(m_parent, &check_can_get_nsec3, address.toAscii().data(), name);
        break;
    case can_get_dnskey:
        newtest =  new DNSSECTest(m_parent, &check_can_get_dnskey, address.toAscii().data(), name);
        break;
    case can_get_ds:
        newtest =  new DNSSECTest(m_parent, &check_can_get_ds, address.toAscii().data(), name);
        break;
    case basic_async:
        newtest =  new DNSSECTest(m_parent, &check_basic_async, address.toAscii().data(), name);
        newtest->setAsync(true);
        break;
    }
    if (newtest) {
        m_tests.push_back(newtest);
        connect(newtest, SIGNAL(messageChanged(QString)), this, SLOT(handleResultMessageChanged(QString)));
        connect(newtest, SIGNAL(messageChanged(QString)), this, SIGNAL(aResultMessageChanged(QString)));
        if (newtest->async()) {
            connect(newtest, SIGNAL(asyncTestSubmitted()), this, SLOT(updateWatchedSockets()));
        }
    }
    return newtest;
}

QStringList TestManager::loadResolvConf()
{
    // create a libval context
    val_context_t *ctx = NULL;
    val_create_context(NULL, &ctx);
    if (!ctx)
        return QStringList();

    // loop through them
    struct name_server *ns_list = val_get_nameservers(ctx);
    char buffer[1025];
    buffer[sizeof(buffer)-1] = '\0';
    const char *ret;

    while(ns_list) {
        QString addr;
        struct sockaddr_storage *serv_addr = ns_list->ns_address[0];
        struct sockaddr_in      *sa = (struct sockaddr_in *) serv_addr;
        struct sockaddr_in6     *sa6 = (struct sockaddr_in6 *) serv_addr;

        if (sa->sin_family == AF_INET) {
            ret = inet_ntop(sa->sin_family, &sa->sin_addr,
                            buffer, sizeof(buffer)-1);
        } else {
            ret = inet_ntop(sa6->sin6_family, &sa6->sin6_addr,
                            buffer, sizeof(buffer)-1);
        }
        if (ret) {
            m_serverAddresses.push_back(QString(buffer));
        }

        ns_list = ns_list->ns_next;
    }

    qDebug() << m_serverAddresses;
    return m_serverAddresses;
}

void TestManager::submitResults(QVariantList tests) {
    QUrl accessURL = resultServerBaseURL;

    if (tests.count() % 2 != 0) {
        qWarning() << "data submitted to TestManager::submitResults wasn't in pairs; giving up";
        return;
    }

    // add base data
    accessURL.addQueryItem("dataVersion", "1");
    accessURL.addQueryItem("DNSSECToolsVersion", "1.11");

    // add the query results passed to us
    for(int i = 0; i < tests.count(); i += 2) {
        accessURL.addQueryItem(tests.at(i).toString(), tests.at(i+1).toString());
    }

    if (!m_manager) {
        m_manager = new QNetworkAccessManager();
        connect(m_manager, SIGNAL(finished(QNetworkReply*)), this, SLOT(responseReceived(QNetworkReply*)));
    }
    //qDebug() << "submitting: " << accessURL;
    m_manager->get(QNetworkRequest(accessURL));
}

void TestManager::responseReceived(QNetworkReply *response)
{
    if (response->error() == QNetworkReply::NoError)
        m_submissionMessage = response->readAll();
    else
        m_submissionMessage = QString("Unfortunately we failed to send your test results to the collection server: " + response->errorString());

    //qDebug() << "setting message to " << m_submissionMessage;
    emit submissionMessageChanged();
}

QString TestManager::submissionMessage()
{
    return m_submissionMessage;
}

void TestManager::saveSetting(QString key, QVariant value) {
    QSettings settings("DNSSEC-Tools", "DNSSEC-Check");
    settings.setValue(key, value);
}

QVariant TestManager::getSetting(QString key) {
    QSettings settings("DNSSEC-Tools", "DNSSEC-Check");
    return settings.value(key).toString();
}

void TestManager::handleResultMessageChanged(QString message)
{
    m_lastResultMessage = message;
    emit lastResultMessageChanged();
}

QString TestManager::lastResultMessage()
{
    return m_lastResultMessage;
}

QString TestManager::sha1hex(QString input) {
    return QCryptographicHash::hash(input.toUtf8(), QCryptographicHash::Sha1).toHex();
}
