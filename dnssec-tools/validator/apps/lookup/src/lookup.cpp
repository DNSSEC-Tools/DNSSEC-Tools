#include <QWidget>
#include <QApplication>
#include <QFont>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLCDNumber>
#include <QLabel>
#include <QPushButton>
#include <QShortcut>
#include <QVBoxLayout>
#include <QLineEdit>
#include <QWidget>
#include <QScrollArea>
#include <QMenu>
#include <QPixmap>
#include <QRegExp>
#include <QMap>
#include <QVector>
#include <QTimer>
#include <QTime>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QSettings>
#include <QDebug>

#include "lookup.h"

#include "QDNSItemModel.h"
#include "LookupPrefs.h"

void
Lookup::setQueryType(int type)
{
    m_queryType = type;
    dolookup();
}

void
Lookup::setTypeText(const QString &label)
{
    m_queryButton->setText(label);
}

void val_qdebug(struct val_log *logp, int level, const char *buf)
{
    Q_UNUSED(logp);
    qDebug() << level << " -- " << buf;
}

static QList<QPair<int, QString> > val_log_strings;
void val_collect_logs(struct val_log *logp, int level, const char *buf)
{
    Q_UNUSED(logp);
    val_log_strings.push_back(QPair<int, QString>(level, buf));
}


Lookup::Lookup(QWidget *parent)
    : QMainWindow(parent), found(false), m_queryType(ns_t_a), val_ctx(0)
{
    QWidget *widget = new QWidget();
    //labels = new QLabel[fields];

    loadPreferences();
    createMainWidgets();
    createMenus();

    // start by doing an initial lookup of the starting record
    QTimer::singleShot(200, this, SLOT(dolookup()));

    setCentralWidget(widget);
    widget->setLayout(vlayout);
    resize(QSize(800,400));
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
}

void
Lookup::createMainWidgets() {
    //
    // Input widget bar
    //
    QHBoxLayout *hlayout = new QHBoxLayout();

    lookupline = new QLineEdit("www.dnssec-tools.org");
    hlayout->addWidget(lookupline);

    m_queryButton = new QPushButton("A", this);
    hlayout->addWidget(m_queryButton);

    // Icons
    m_validated = QPixmap(":/images/validated.png");
    m_trusted   = QPixmap(":/images/trusted.png");
    m_bad       = QPixmap(":/images/bad.png");
    m_unknown   = QPixmap(":/images/unknown.png");

    m_resultsIcon = new QLabel();
    m_resultsIcon->setPixmap(m_unknown);
    hlayout->addWidget(m_resultsIcon);

    createQueryMenu();

    gobutton = new QPushButton("Go");
    hlayout->addWidget(gobutton);
    connect(gobutton, SIGNAL(clicked()), this, SLOT(dolookup()));
    connect(lookupline, SIGNAL(textEdited(QString)), this, SLOT(entryTextChanged(QString)));
    connect(lookupline, SIGNAL(returnPressed()), this, SLOT(dolookup()));

    //
    // Create the vertical answer sheet
    //
    vlayout = new QVBoxLayout();
    vlayout->addLayout(hlayout);

    m_answerView = new QTreeView(this);
    m_answers = new QDNSItemModel(this);
    m_answerView->setModel(m_answers);

    vlayout->addWidget(m_answerView);
}

void
Lookup::createQueryMenu() {
    //
    // create the QUERY TYPE menu
    //
    QMenu *querymenu = new QMenu(m_queryButton);
    m_queryButton->setMenu(querymenu);

    m_signalMapper = new QSignalMapper(this);

    QMap<int, QString> valuemap, dnssecmap, othermap;

    valuemap[1] = "A";
    valuemap[2] = "NS";
    valuemap[5] = "CNAME";
    valuemap[6] = "SOA";
    valuemap[12] = "PTR";
    valuemap[15] = "MX";
    valuemap[16] = "TXT";
    valuemap[28] = "AAAA";
    valuemap[33] = "SRV";
    valuemap[255] = "ANY";

    dnssecmap[43]    = "DS";
    dnssecmap[46]    = "RRSIG";
    dnssecmap[47]    = "NSEC";
    dnssecmap[48]    = "DNSKEY";
    dnssecmap[50]    = "NSEC3";
    dnssecmap[32769] = "DLV";

    othermap[3] = "MD";
    othermap[4] = "MF";
    othermap[7] = "MB";
    othermap[8] = "MG";
    othermap[9] = "MR";
    othermap[10] = "NULL";
    othermap[11] = "WKS";
    othermap[13] = "HINFO";
    othermap[14] = "MINFO";
    othermap[17] = "RP";
    othermap[18] = "AFSDB";
    othermap[19] = "X25";
    othermap[20] = "ISDN";
    othermap[21] = "RT";
    othermap[22] = "NSAP";
    othermap[23] = "NSAP_PTR";
    othermap[24] = "SIG";
    othermap[25] = "KEY";
    othermap[26] = "PX";
    othermap[27] = "GPOS";
    othermap[29] = "LOC";
    othermap[30] = "NXT";
    othermap[31] = "EID";
    othermap[32] = "NIMLOC";
    othermap[34] = "ATMA";
    othermap[35] = "NAPTR";
    othermap[36] = "KX";
    othermap[37] = "CERT";
    othermap[38] = "A6";
    othermap[39] = "DNAME";
    othermap[40] = "SINK";
    othermap[41] = "OPT";
    othermap[250] = "TSIG";
    othermap[251] = "IXFR";
    othermap[252] = "AXFR";
    othermap[253] = "MAILB";
    othermap[254] = "MAILA";


    QAction *action;

    QMenu *submenu = querymenu->addMenu("Common");
    for(QMap<int, QString>::iterator iter = valuemap.begin();
        iter != valuemap.end();
        iter++) {

        action = submenu->addAction(iter.value());
        connect(action, SIGNAL(triggered()), m_signalMapper, SLOT(map()));
        m_signalMapper->setMapping(action, iter.key());
        m_signalMapper->setMapping(action, iter.value());
    }

    submenu = querymenu->addMenu("DNSSEC");
    for(QMap<int, QString>::iterator iter = dnssecmap.begin();
        iter != dnssecmap.end();
        iter++) {

        action = submenu->addAction(iter.value());
        connect(action, SIGNAL(triggered()), m_signalMapper, SLOT(map()));
        m_signalMapper->setMapping(action, iter.key());
        m_signalMapper->setMapping(action, iter.value());
    }

    submenu = querymenu->addMenu("Others");
    for(QMap<int, QString>::iterator iter = othermap.begin();
        iter != othermap.end();
        iter++) {

        action = submenu->addAction(iter.value());
        connect(action, SIGNAL(triggered()), m_signalMapper, SLOT(map()));
        m_signalMapper->setMapping(action, iter.key());
        m_signalMapper->setMapping(action, iter.value());
    }

    connect(m_signalMapper, SIGNAL(mapped(int)), this, SLOT(setQueryType(int)));
    connect(m_signalMapper, SIGNAL(mapped(const QString &)),
            this, SLOT(setTypeText(const QString &)));
}

void
Lookup::createMenus() {
    QAction *about;
    QAction *results;
    QAction *submitResults;
    QAction *exitAction;
    QAction *preferences;

#ifdef SMALL_DEVICE
    QMenuBar *bar = menuBar();
    preferences = bar->addAction(tr("&Preferences"));
    about = bar->addAction(tr("&About"));
#else
    QMenu *nameMenu = menuBar()->addMenu(tr("&File"));
    QMenu *helpMenu = menuBar()->addMenu(tr("&Help"));

    about = helpMenu->addAction(tr("&About"));
    preferences = nameMenu->addAction(tr("&Preferences"));
    exitAction = nameMenu->addAction(tr("&Quit"));
    connect(exitAction, SIGNAL(triggered()), this, SLOT(close()));
#endif

    connect(about, SIGNAL(triggered()), this, SLOT(showAbout()));
    connect(preferences, SIGNAL(triggered()), this, SLOT(showPreferences()));
}

void
Lookup::init_libval() {
    //val_log_add_cb(NULL, 99, &val_qdebug);
    if (val_ctx)
        val_free_context(val_ctx);

    // create a validator context
    val_create_context("lookup", &val_ctx);
    if (m_logLocation.length() > 0)
        val_log_add_optarg(QString("7:file:" + m_logLocation).toLatin1().data(), 0);

    // capture our own log messages
    val_log_add_cb(NULL, 99, &val_collect_logs);
}

QSize Lookup::sizeHint()
{
    return QSize(640,480);
}

Lookup::~Lookup()
{
    if (val_ctx)
        val_free_context(val_ctx);
}

void
Lookup::dolookup()
{
    val_status_t val_status;
    struct addrinfo *aitop = NULL;
    int ret;
    u_char buf[4096];
    char printbuf[4096];
    int columns = 4;
    QTime start, stop;

    val_log_strings.clear();
    m_answers->clear();
    m_answers->setColumnCount(columns);
    QStringList headers;
    headers << QString("Name") << QString("Type") << QString("TTL") << QString("Data");
    m_answers->setHorizontalHeaderLabels(headers);

    busy();

    // perform the lookup
    start = QTime::currentTime();
    ret = val_res_query(val_ctx, lookupline->text().toUtf8(), ns_c_in,
                        m_queryType, buf, sizeof(buf), &val_status);
    stop = QTime::currentTime();

    // do something with the results
    if (ret <= 0) {
        QStandardItem *answers = new QStandardItem("Results");
        m_answers->appendRow(answers);
        answers->appendRow(new QStandardItem("No Answer Data"));
        m_answerView->setExpanded(answers->index(), true);

        if (!val_istrusted(val_status)) {
            // untrusted error for host
        }
 	if (!val_istrusted(val_status)) {
            // untrusted for ip address
        }

        setSecurityStatus(val_status);
    } else {

        ns_msg          handle;
        int             id, qdcount, ancount, nscount, arcount;
        ns_rr           rr;
        int             rrnum = 0;
        int             n;
        QString         text;

        if (ns_initparse(buf, ret, &handle) < 0) {
            // Error
            unbusy();
            return;
        }

        id = ns_msg_id(handle);
        qdcount = ns_msg_count(handle, ns_s_qd);
        ancount = ns_msg_count(handle, ns_s_an);
        nscount = ns_msg_count(handle, ns_s_ns);
        arcount = ns_msg_count(handle, ns_s_ar);

//         do_section(&handle, ns_s_qd, RES_PRF_QUES, file);
//         do_section(&handle, ns_s_an, RES_PRF_ANS, file);
//         do_section(&handle, ns_s_ns, RES_PRF_AUTH, file);
//         do_section(&handle, ns_s_ar, RES_PRF_ADD, file);

        QMap<ns_sect, QStandardItem *> sections;
        sections[ns_s_qd] = new QStandardItem(QString("Question"));
        sections[ns_s_an] = new QStandardItem(QString("Answers"));
        sections[ns_s_ns] = new QStandardItem(QString("Authority"));
        sections[ns_s_ar] = new QStandardItem(QString("Additional"));

        QStandardItem *results = new QStandardItem("Results");
        results->appendRow(sections[ns_s_qd]);
        results->appendRow(sections[ns_s_an]);
        results->appendRow(sections[ns_s_ns]);
        results->appendRow(sections[ns_s_ar]);
        m_answers->appendRow(results);

        QStandardItem *theRealAnswer = 0;

        for(QMap<ns_sect, QStandardItem *>::iterator iter = sections.begin();
            iter != sections.end(); iter++) {
            QMap<QString,QStandardItem *> dataItems;
            rrnum = 0;
            while(1) {
                if (ns_parserr(&handle, iter.key(), rrnum, &rr)) {
                    break;
                }
                n = ns_sprintrr(&handle, &rr, NULL, NULL,
                                printbuf, sizeof(printbuf));
                if (n < 0) {
                    // error
                    unbusy();
                    return;
                }

                // Create the row to display
                QList<QStandardItem *> newRow;
                QString rrType = QString(p_type(ns_rr_type(rr)));
                newRow.push_back(new QStandardItem(QString(ns_rr_name(rr))));
                newRow.push_back(new QStandardItem(rrType));
                newRow.push_back(new QStandardItem(QString().number(ns_rr_ttl(rr))));

                // remove the leading data from a printed representation that we've already extracted
                QString dataBuffer = QString(printbuf);
                dataBuffer.replace(QRegExp("^[-\\.\\w]+\\s+\\w+\\s+IN\\s+\\w+\\s+"), QString(""));
                newRow.push_back(new QStandardItem(dataBuffer));

                if(! dataItems.contains(rrType)) {
                    QList<QStandardItem *> parentRow;
                    parentRow.push_back(new QStandardItem(QString(ns_rr_name(rr))));
                    parentRow.push_back(new QStandardItem(QString(p_type(ns_rr_type(rr)))));
                    iter.value()->appendRow(parentRow);
                    iter.value()->setColumnCount(parentRow.count());
                    dataItems[rrType] = parentRow[0];
                }

                dataItems[rrType]->appendRow(newRow);
                dataItems[rrType]->setColumnCount(newRow.count());

                if (iter.key() == ns_s_an && m_queryType == ns_rr_type(rr)) {
                    // remember that this is the real answer so we can expand it later
                    theRealAnswer = dataItems[rrType];
                    qDebug() << " found the answer";
                }

                rrnum++;
            }
        }
        
        setSecurityStatus(val_status);

        m_answerView->setExpanded(results->index(), true);
        m_answerView->setExpanded(sections[ns_s_an]->index(), true);
        if (theRealAnswer) {
            m_answerView->setExpanded(theRealAnswer->index(), true);
            qDebug() << "Expanding" << theRealAnswer->index();
        }

    }

    m_answers->appendRow(new QStandardItem(QString("Time: %1 msec").arg(start.msecsTo(stop))));

    //m_answerView->setHeaderHidden(true);
    m_answerView->setRootIsDecorated(false);
    m_answers->emitChanges();
    for(int i = 0 ; i < columns; i++) {
        m_answerView->resizeColumnToContents(i);
    }

    vlayout->invalidate();

    val_freeaddrinfo(aitop);
    unbusy();
}

void Lookup::setSecurityStatus(int val_status) {
    //
    // Set the security results into the display
    //
    QStandardItem *security = new QStandardItem("Security");
    m_answers->appendRow(security);

    if (val_isvalidated(val_status)) {
        m_securityStatus =
            new QStandardItem("Status: Validated");
        m_answers->setSecurityStatus(m_securityStatus,
                                     QDNSItemModel::validated);
        m_resultsIcon->setPixmap(m_validated);
    #ifndef BROKENBACKGROUND
        m_answerView->setStyleSheet("QTreeView { background-color: #96ff96; }");
    #endif
    } else if (val_istrusted(val_status)) {
        m_securityStatus =
            new QStandardItem("Status: Trusted");
        m_answers->setSecurityStatus(m_securityStatus,
                                     QDNSItemModel::trusted);
        m_resultsIcon->setPixmap(m_trusted);
    #ifndef BROKENBACKGROUND
        m_answerView->setStyleSheet("QTreeView { background-color: #ffff96; }");
    #endif
    } else {
        m_securityStatus = new QStandardItem("Status: Bogus");
        m_answers->setSecurityStatus(m_securityStatus,
                                     QDNSItemModel::bad);
        m_resultsIcon->setPixmap(m_bad);
    #ifndef BROKENBACKGROUND
        m_answerView->setStyleSheet("QTreeView { background-color: #ff9696; }");
    #endif
    }

    security->appendRow(m_securityStatus);
    security->appendRow(new QStandardItem(QString("code: ") + QString(p_val_status(val_status))));

    QStandardItem *logs = new QStandardItem("Logs");
    m_answers->appendRow(logs);
    QStandardItem *interesting = new QStandardItem("Interesting");
    logs->appendRow(interesting);

    QStandardItem *allLogs = new QStandardItem("All");
    logs->appendRow(allLogs);

    // Interesting log engine
    QRegExp keepit("([^:]+): +(.*)(looking for.*DNSKEY|looking for|Verified a RRSIG|Could not link|BOGUS|FAILURE|PINSECURE|Bogus|Cannot show|is provably insecure|matches|key.*is trusted|ending.*chain)(.*)");
    QRegExp logParser("([^ ]+) +(.*)");

    QString lastInterestingString;
    QList<QPair<int, QString> >::iterator logEnd = val_log_strings.end();

    for(QList<QPair<int, QString> >::iterator start = val_log_strings.begin();
        start != logEnd; start++) {
        QList<QStandardItem *> newRow;
        int level = (*start).first;
        QString valLog = (*start).second;

        logParser.indexIn(valLog);
        QString dateNTime = logParser.cap(1);
        QString logText   = logParser.cap(2);
        newRow.push_back(new QStandardItem(dateNTime));
        newRow.push_back(new QStandardItem(QString().number(level)));
        newRow.push_back(new QStandardItem());
        newRow.push_back(new QStandardItem(logText));

        //log->setColumnCount(newRow.count());

        allLogs->appendRow(newRow);

        // look for interesting logs
        if (keepit.indexIn(valLog) <= 0)
            continue;

        QList<QStandardItem *> interestingLog;
        QString interestingResults = keepit.cap(2) + keepit.cap(3) + keepit.cap(4);

        if (interestingResults == lastInterestingString)
            continue;

        interestingLog.push_back(new QStandardItem(dateNTime));
        interestingLog.push_back(new QStandardItem(QString().number(level)));
        interestingLog.push_back(new QStandardItem());
        interestingLog.push_back(new QStandardItem(interestingResults));

        interesting->appendRow(interestingLog);

        lastInterestingString = interestingResults;
    }

    m_answerView->setExpanded(security->index(), true);
    m_answerView->setExpanded(logs->index(), true);
}

void Lookup::unbusy() {
    setCursor(Qt::ArrowCursor);
    gobutton->setEnabled(true);
}

void Lookup::busy() {
    setCursor(Qt::WaitCursor);
    gobutton->setDisabled(true);
}

void Lookup::entryTextChanged(const QString &newtext) {
    Q_UNUSED(newtext);
    m_answers->clear();
    m_answers->setSecurityStatus(m_securityStatus,
                                 QDNSItemModel::unknown);
#ifndef BROKENBACKGROUND
    m_answerView->setStyleSheet("QTreeView { background-color: #ffffff; }");
#endif
    m_resultsIcon->setPixmap(m_unknown);
}

void Lookup::showAbout()
{
    QMessageBox message;
    message.setText("<p><b>Lookup</b><br /><p>Lookup is a simple graphical utility that can be used to query a network for domain name records.  "
                    "The tool understands DNSSEC and color-codes the results based on whether the record has been securely validated (green), is a "
                    "'trusted' answer but not validated (yellow), or fails DNSSEC validation (red)."
                    "<p>For example records to test the coloring try these three:"
                    "<ul><li>www.dnssec-tools.org</li><li>www.cnn.com</li><li>badsign-a.test.dnssec-tools.org</li></ul>"
                    );
    message.setIcon(QMessageBox::Information);
    message.exec();
}

void Lookup::showPreferences()
{
    LookupPrefs prefs;
    connect(&prefs, SIGNAL(accepted()), this, SLOT(loadPreferences()));
    prefs.exec();
}

void Lookup::loadPreferences()
{
    QSettings settings("DNSSEC-Tools", "Lookup");
    m_logLocation = settings.value("logPath", "").toString();
    init_libval();
}
