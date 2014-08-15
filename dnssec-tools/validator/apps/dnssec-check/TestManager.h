#ifndef TESTMANAGER_H
#define TESTMANAGER_H

#include <QObject>
#include "DNSSECTest.h"
#include "DNSSECCheckThread.h"

#include <validator/resolver.h>
#include <validator/validator.h>

#include <QtCore/QStringList>
#include <QtCore/QVariantList>
#include <QtNetwork/QNetworkAccessManager>
#include <QtNetwork/QAbstractSocket>
#include <QtCore/QList>

#include "DnssecCheckVersion.h"

#define ENABLE_RESULTS_SUBMISSION 1

#ifndef RESULTS_SUBMIT_URL
#define RESULTS_SUBMIT_URL "https://www.dnssec-tools.org/dnssec-check/?type=submit&"
#endif

static const QString resultServerBaseURL = RESULTS_SUBMIT_URL;

class TestManager : public QObject
{
    Q_OBJECT
    Q_ENUMS(testType)
public:

    enum testType
        { basic_dns,
          basic_tcp,
          do_bit,
          ad_bit,
          do_has_rrsigs,
          small_edns0,
          can_get_nsec,
          can_get_nsec3,
          can_get_dnskey,
          can_get_ds,
          can_get_signed_dname
  #ifdef LIBVAL_ASYNC_TESTING
          , basic_async
  #endif
        };
    explicit TestManager(QObject *parent = 0);

    Q_INVOKABLE DNSSECTest *makeTest(testType type, QString address, QString name);
    Q_INVOKABLE QStringList loadResolvConf();

    Q_INVOKABLE void submitResults(QVariantList tests);
    Q_INVOKABLE void saveSetting(QString key, QVariant value);
    Q_INVOKABLE QVariant getSetting(QString key);
    Q_INVOKABLE QString sha1hex(QString input);
    Q_INVOKABLE int outStandingRequests();
    Q_INVOKABLE void checkAvailableUpdates();
    Q_INVOKABLE void startQueuedTransactions();
    Q_INVOKABLE bool testName(const QString &resolverAddress);

    Q_PROPERTY(QString submissionMessage  READ submissionMessage                      NOTIFY submissionMessageChanged)
    Q_PROPERTY(QString lastResultMessage  READ lastResultMessage                      NOTIFY lastResultMessageChanged)
    Q_PROPERTY(bool inTestLoop            READ inTestLoop         WRITE setInTestLoop NOTIFY inTestLoopChanged)
    Q_PROPERTY(QString dnssecCheckVersion READ dnssecCheckVersion)

    QString submissionMessage();
    QString lastResultMessage();

    bool inTestLoop();
    void setInTestLoop(bool newval);

    QString dnssecCheckVersion() { return QString(DNSSEC_CHECK_VERSION); }

signals:
    void submissionMessageChanged();
    void aResultMessageChanged(QString message);
    void lastResultMessageChanged();
    void inTestLoopChanged();
    void inTestLoopChangedBool(bool);
    void updatesMaybeAvailable();
    void addedNewTest(DNSSECTest *);
    void startQueuedTransactionsSignal();
    void checkAvailableUpdatesSignal();

public slots:
    void responseReceived(QNetworkReply *response);
    void handleResultMessageChanged(QString message);
    void handlerReady(DNSSECCheckThreadHandler *handler);
    void cancelOutstandingRequests();

private:
    QObject *m_parent;
    QStringList  m_serverAddresses;
    QNetworkAccessManager *m_manager;
    QString m_submissionMessage;
    QString m_lastResultMessage;
    QList<DNSSECTest *> m_tests;
    DNSSECCheckThread m_otherThread;

    bool            m_inTestLoop;
};

#endif // TESTMANAGER_H
