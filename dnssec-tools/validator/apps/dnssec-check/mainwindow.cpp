// checksum 0xd429 version 0x10001
#include "mainwindow.h"

#include <QtCore/QCoreApplication>
#include <QtCore/QFile>
#include <QtCore/QRegExp>
#include <QtCore/QTimer>
#include "QStatusLight.h"
#include "SubmitDialog.h"
#include "dnssec_checks.h"

#include <QtGui/QMenuBar>
#include <QtGui/QMenu>
#include <QtGui/QMessageBox>
#include <QMessageBox>
#include <QtNetwork/QNetworkRequest>
#include <QtNetwork/QNetworkReply>

#include <qdebug.h>

#if defined(Q_OS_SYMBIAN) && defined(ORIENTATIONLOCK)
#include <eikenv.h>
#include <eikappui.h>
#include <aknenv.h>
#include <aknappui.h>
#endif // Q_OS_SYMBIAN && ORIENTATIONLOCK

// --------------------------------------------------------------------------
// CONFIG: UNCOMMENT THIS IF YOU WANT TO SUBMIT TEST RESULTS TO A CGI SCRIPT:
// #define ENABLE_RESULTS_SUBMISSION 1

#ifndef RESULTS_SUBMIT_URL
#define RESULTS_SUBMIT_URL "http://www.hardakers.net/cgi-bin/dnssec-check-results.fcgi"
#endif

static const QString resultServerBaseURL = RESULTS_SUBMIT_URL;

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), m_rows(0), m_manager(0), m_detailedResults(0), m_submitResults(0)
{
    loadResolvConf();
    setupWidgets();
    setupMenus();
    setWindowIcon(QIcon(":/images/dnssec-check-64x64.png"));
    setCentralWidget(m_mainWidget);
}


MainWindow::~MainWindow()
{
}

void MainWindow::setupWidgets()
{
    m_mainWidget = new QWidget();
    m_mainLayout = new QVBoxLayout();
    m_mainWidget->setLayout(m_mainLayout);

    m_mainLayout->addWidget(m_titleLabel = new QLabel(tr("DNSSEC-Check")));
    QFont font = m_titleLabel->font();
    font.setBold(true);
    font.setPointSize(18);
    font.setUnderline(true);
    m_titleLabel->setFont(font);
    m_titleLabel->setAlignment(Qt::AlignHCenter);

    m_results = new QGridLayout();
    m_mainLayout->addLayout(m_results);

    int numAddresses = qMax(m_serverAddresses.count(), 2); // want at least 2 to force the main light to be bigger

    QLabel *label;
    m_results->addWidget(label = new QLabel(tr("ISP")), 1, 1, numAddresses, 1, 0);
    label->setAlignment(Qt::AlignVCenter | Qt::AlignLeft);
    label->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_results->addWidget(m_resolverResult = new QStatusLight(), 1, 2, numAddresses, 1, 0);

    foreach(QString server, m_serverAddresses) {
        addAddress(server);
    }

    m_results->addWidget(m_bypassResult = new QStatusLight(), 1+numAddresses, 2);
    m_results->addWidget(new QLabel(tr("ISP Bypassing")), 1+numAddresses, 1);

    m_mainLayout->addStretch(1);

    QHBoxLayout *editBox = new QHBoxLayout();
    m_mainLayout->addLayout(editBox);
    editBox->addWidget(new QLabel(tr("Add a new resolver:")));
    editBox->addWidget(m_lineEdit = new QLineEdit());
    connect(m_lineEdit, SIGNAL(returnPressed()), this, SLOT(addLineAddress()));

    m_mainLayout->addWidget(m_testButton = new QPushButton(tr("Test")));
    connect(m_testButton, SIGNAL(clicked()), this, SLOT(startGetAnswers()));
}

void MainWindow::addLineAddress() {
    addAddress(m_lineEdit->text());
    m_lineEdit->clear();
}

void MainWindow::addAddress(QString server, int row) {
    QStatusLight *light;
    QLabel *label;
    int column = 3;

    qDebug() << "here: " << row << " / " << m_rows;
    if (row < 0) {
        qDebug() << "using mrows: " << m_rows;
        row = m_rows;
        m_rows++;
    }

#ifdef SMALL_DEVICE
    m_results->addWidget(new QLabel(QString().number(row) + ": "), row, column++);
#else
    m_results->addWidget(label = new QLabel(server + ": "), row, column++);
    label->setAlignment(Qt::AlignRight | Qt::AlignVCenter);
#endif

    m_results->addWidget(light = new QStatusLight(0, &check_basic_dns, server.toAscii().data(), "DNS", row), row, column++);
    m_tests.push_back(light);

    m_results->addWidget(light = new QStatusLight(0, &check_basic_tcp, server.toAscii().data(), "TCP", row), row, column++);
    m_tests.push_back(light);

    m_results->addWidget(light = new QStatusLight(0, &check_do_bit, server.toAscii().data(), "DO", row), row, column++);
    m_tests.push_back(light);

    m_results->addWidget(light = new QStatusLight(0, &check_do_has_rrsigs, server.toAscii().data(), "RRSIG", row), row, column++);
    m_tests.push_back(light);

    m_results->addWidget(light = new QStatusLight(0, &check_small_edns0, server.toAscii().data(), "EDNS0", row), row, column++);
    m_tests.push_back(light);

    m_results->addWidget(light = new QStatusLight(0, &check_can_get_nsec, server.toAscii().data(), "NSEC", row), row, column++);
    m_tests.push_back(light);

    m_results->addWidget(light = new QStatusLight(0, &check_can_get_nsec3, server.toAscii().data(), "NSEC3", row), row, column++);
    m_tests.push_back(light);

    m_results->addWidget(light = new QStatusLight(0, &check_can_get_dnskey, server.toAscii().data(), "DNSKEY", row), row, column++);
    m_tests.push_back(light);

    m_results->addWidget(light = new QStatusLight(0, &check_can_get_ds, server.toAscii().data(), "DS", row), row, column++);
    m_tests.push_back(light);
}

void MainWindow::setupMenus() {
    QAction *about;
    QAction *exitAction;

#ifdef SMALL_DEVICE
    QMenuBar *bar = menuBar();
    results = bar->addAction(tr("Detailed results"));
#ifdef ENABLE_RESULTS_SUBMISSION
    submitResults = bar->addAction(tr("Submit Results"));
#endif
    about = bar->addAction(tr("About"));
#else
    QMenu *nameMenu = menuBar()->addMenu(tr("&File"));
    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));
    m_detailedResults = nameMenu->addAction(tr("&Detailed results"));
#ifdef ENABLE_RESULTS_SUBMISSION
    m_submitResults = nameMenu->addAction(tr("&Submit Results"));
#endif
    about = helpMenu->addAction(tr("About"));
    nameMenu->addSeparator();
    exitAction = nameMenu->addAction(tr("&Quit"));
    connect(exitAction, SIGNAL(triggered()), this, SLOT(close()));
#endif

    connect(about, SIGNAL(triggered()), this, SLOT(showAbout()));
    connect(m_detailedResults, SIGNAL(triggered()), this, SLOT(showResultDetails()));

    if (m_submitResults) {
        connect(m_submitResults, SIGNAL(triggered()), this, SLOT(maybeSubmitResults()));
        m_submitResults->setEnabled(false);
    }
    m_detailedResults->setEnabled(false);
}

void MainWindow::setOrientation(Orientation orientation)
{
#ifdef Q_OS_SYMBIAN
    if (orientation != Auto) {
#if defined(ORIENTATIONLOCK)
        const CAknAppUiBase::TAppUiOrientation uiOrientation =
                (orientation == LockPortrait) ? CAknAppUi::EAppUiOrientationPortrait
                    : CAknAppUi::EAppUiOrientationLandscape;
        CAknAppUi* appUi = dynamic_cast<CAknAppUi*> (CEikonEnv::Static()->AppUi());
        TRAPD(error,
            if (appUi)
                appUi->SetOrientationL(uiOrientation);
        );
#else // ORIENTATIONLOCK
        qWarning("'ORIENTATIONLOCK' needs to be defined on Symbian when locking the orientation.");
#endif // ORIENTATIONLOCK
    }
#elif defined(Q_WS_MAEMO_5)
    Qt::WidgetAttribute attribute;
    switch (orientation) {
    case LockPortrait:
        attribute = Qt::WA_Maemo5PortraitOrientation;
        break;
    case LockLandscape:
        attribute = Qt::WA_Maemo5LandscapeOrientation;
        break;
    case Auto:
    default:
        attribute = Qt::WA_Maemo5AutoOrientation;
        break;
    }
    setAttribute(attribute, true);
#else // Q_OS_SYMBIAN
    Q_UNUSED(orientation);
#endif // Q_OS_SYMBIAN
}

void MainWindow::startGetAnswers()
{
    foreach(QStatusLight *light, m_tests) {
        light->setStatus(QStatusLight::UNKNOWN);
    }
    m_resolverResult->setStatus(QStatusLight::UNKNOWN);
    m_bypassResult->setStatus(QStatusLight::UNKNOWN);

    QTimer::singleShot(0, this, SLOT(getAnswers()));
}


void MainWindow::getAnswers()
{
    busy();

    getSubAnswers();

    // try with the default context (and, ie, the default resolver)
    if (doLookupTest()) {
        m_resolverResult->setStatus(QStatusLight::GOOD);
        m_resolverResult->setMessage(tr("Succeeded in a DNSSEC validation using the local ISP"));
    } else {
        m_resolverResult->setStatus(QStatusLight::BAD);
        m_resolverResult->setMessage(tr("Failed to perform a DNSSEC validation using the local ISP"));
    }

    if (doLookupTest("dnssec-tools.org", 48, "/dev/null")) {
        m_bypassResult->setStatus(QStatusLight::GOOD);
        m_bypassResult->setMessage(tr("Succeeded in a DNSSEC validation bypassing local ISP"));
    } else {
        m_bypassResult->setStatus(QStatusLight::BAD);
        m_bypassResult->setMessage(tr("Failed to bypass the local ISP for performing DNSSEC validation"));
    }

    unbusy();

}

void MainWindow::getSubAnswers() {
    //m_testResult->check();
    foreach(QStatusLight *light, m_tests) {
        light->check();
        repaint();
    }
}

bool
MainWindow::doLookupTest(QString lookupName, int queryType, char *resolv_conf)
{
    val_status_t val_status;
    struct addrinfo *aitop = NULL;
    int ret;
    u_char buf[4096];
    val_context_t *context = NULL;

    if (resolv_conf != NULL) {
        int result = val_create_context_with_conf(NULL, NULL, resolv_conf, NULL, &context);
        qDebug() << "running with resolv_conf of " << resolv_conf << " / result=" << result << " / ctx=" << context;
    }

    // perform the lookup
    ret = val_res_query(context, lookupName.toUtf8(), ns_c_in,
                        queryType, buf, sizeof(buf), &val_status);
    qDebug() << "here: lookingup=" << lookupName << ", ret=" << ret << " / " << val_status;

    freeaddrinfo(aitop);
    if (ret < 0)
        return false;
    if (!val_istrusted(val_status))
        return false;
    return true;
}

void MainWindow::unbusy() {
    setCursor(Qt::ArrowCursor);
    m_testButton->setEnabled(true);
    m_detailedResults->setEnabled(true);
    if (m_submitResults)
        m_submitResults->setEnabled(true);
}

void MainWindow::busy() {
    setCursor(Qt::WaitCursor);
    m_testButton->setEnabled(false);
    m_detailedResults->setEnabled(false);
    if (m_submitResults)
        m_submitResults->setEnabled(false);
}

void MainWindow::loadResolvConf()
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
}

void MainWindow::showAbout()
{
    QMessageBox message;
    message.setText("<p><b>DNSSEC-Check</b><p><i>DNSSEC-Tools Version: 1.11</i></p><p>DNSSEC-Check tests the likelyhood that your network will support client-side DNSSEC validation.  "
                    "DNSSEC-Check is a application created for the <a href=\"http://www.dnssec-tools.org/\">DNSSEC-Tools</a> project."
                    "<p>This project is a work-in-progress and this is an alpha-version of this software.  It is currently most suited to people that "
                    "know and understand how the DNS and DNSSEC works."
                #ifdef SMALL_DEVICE
                    "<p>Note for the N900/Maemo: This only works on WLAN networks, and will not work on cell-phone networks at the moment due to an "
                    "oddity in how dhcp works on the N900."
                #endif
                    );
    message.setIcon(QMessageBox::Information);
    message.exec();
}

void MainWindow::showResultDetails()
{
    QMessageBox message;
    QString results = tr("<p><b>Detailed DNSSEC-Check Results:</b><br />\n"
                         "<p>The results show below are the detailed results for each test that was sent to each of the tested name server.<br /><p>");

    foreach (QStatusLight *light, m_tests) {
        results = results + light->serverAddress() + ": " + light->message() + "<br />\n";
    }

    message.setText(results);
    message.setIcon(QMessageBox::Information);
    message.exec();
}

void MainWindow::maybeSubmitResults()
{
    SubmitDialog dialog(0);
    qDebug() << "got to submitting results";
    if (dialog.exec() == QDialog::Accepted) {
        qDebug() << "done; will send";
        submitResults(dialog.locationDescription());
    } else {
        qDebug() << "denied";
    }
}

void MainWindow::submitResults(QString locationDescription)
{
    QUrl accessURL = resultServerBaseURL;
    accessURL.addQueryItem("dataVersion", "1");
    int count=0;
    foreach(QString serverAddress, m_serverAddresses) {
        accessURL.addQueryItem("server" + QString::number(count++), serverAddress);
    }

    foreach(QStatusLight *light, m_tests) {
        accessURL.addQueryItem(light->name() + QString::number(light->rowNumber()), light->statusString());
    }

    accessURL.addQueryItem("locationDescription", locationDescription);
    accessURL.addQueryItem("DNSSECToolsVersion", "1.11");

    if (!m_manager) {
        m_manager = new QNetworkAccessManager();
        connect(m_manager, SIGNAL(finished(QNetworkReply*)), this, SLOT(respnonseReceived(QNetworkReply*)));
    }
    m_manager->get(QNetworkRequest(accessURL));
}

void MainWindow::respnonseReceived(QNetworkReply *response)
{
    QMessageBox msg;
    if (response->error() == QNetworkReply::NoError)
        msg.setText("We've successfully recevied your test results.  Thank you for your help!");
    else
        msg.setText("Unfortunately we failed to send your test results to the collection server.");
    msg.exec();
}

