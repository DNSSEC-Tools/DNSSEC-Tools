#include "LogWatcher.h"
#include "node.h"
#include "graphwidget.h"

#include <QtCore/QSettings>
#include <QtGui/QColor>

#include <qdebug.h>

// This matches strings like {www.dnssec-tools.org, IN(1), AAAA(28)}
// Also the same without commas: {www.dnssec-tools.org IN(1) AAAA(28)}
// and match #1 is the name, and match #2 is the type (eg AAAA)

#define QUERY_MATCH "\\{([^, ]+).*[, ]([A-Z0-9]*)\\([0-9]+\\)\\}"

// Matches "@0x7fbf08476ee0: com SOA: "
#define BIND_MATCH  "@0x[0-9a-f]+: ([^ ]+) ([^:]+): "

// Matches "0x7fbf0c0a7850(www.dnssec-deployment.org/AAAA'): "
#define BIND_PAREN_MATCH "0x[0-9a-f]+\\(([^/]+)/([^:']+)'*\\): "

#define UNBOUND_ANGLE_MATCH "<([^ ]+) ([A-Z0-9]+) IN>"
#define UNBOUND_MATCH       "([^ ]+) ([A-Z0-9]+) IN"

LogWatcher::LogWatcher(GraphWidget *parent)
    : m_graphWidget(parent), m_timer(0),

      // libval regexps
      m_validatedRegexp("Validation result for " QUERY_MATCH ": VAL_SUCCESS:"),
      m_validatedChainPartRegexp("name=(.*) class=IN type=([^\[]*).* from-server.*status=VAL_AC_VERIFIED:"),
      m_cryptoSuccessRegexp("Verified a RRSIG for ([^ ]+) \\(([^\\)]+)\\)"),
      m_lookingUpRegexp("looking for " QUERY_MATCH),
      m_bogusRegexp("Validation result for " QUERY_MATCH ".*BOGUS"),
      m_trustedRegexp("Validation result for " QUERY_MATCH ": (VAL_IGNORE_VALIDATION|VAL_PINSECURE)"),
      m_pinsecureRegexp("Setting proof status for " QUERY_MATCH " to: VAL_NONEXISTENT_TYPE"),
      m_pinsecure2Regexp("Setting authentication chain status for " QUERY_MATCH " to Provably Insecure"),
      m_dneRegexp("Validation result for " QUERY_MATCH ".*VAL_NONEXISTENT_(NAME|TYPE):"),
      m_maybeDneRegexp("Validation result for " QUERY_MATCH ".*VAL_NONEXISTENT_(NAME|TYPE)_NOCHAIN:"),
      m_ignoreValidationRegexp("Assertion end state for " QUERY_MATCH " already set to VAL_IGNORE_VALIDATION"),

      // bind regexps
      m_bindValidatedRegex(BIND_MATCH "verify rdataset.*: success"),
      m_bindBogusRegexp(BIND_MATCH "verify rdataset.*failed to verify"),
      m_bindQueryRegexp(BIND_PAREN_MATCH "query"),
      m_bindPIRegexp(BIND_MATCH "marking.*proveunsecure"),
      m_bindDNERegexp(BIND_PAREN_MATCH "nonexistence validation OK"),
      m_bindTrustedAnswerRegexp(BIND_MATCH "marking as answer.*dsfetched"),
      m_bindNoAnswerResponseRegexp(BIND_PAREN_MATCH "noanswer_response"),
      m_bindAnswerResponseRegexp(BIND_PAREN_MATCH "answer_response"),
      m_bindProvenNSECRegexp(BIND_MATCH "nonexistence proof\\(s\\) found"),

      // unbound regexps
      m_unboundValidatedRegex("validation success " UNBOUND_MATCH),
      m_unboundBogusRegexp("validation failure " UNBOUND_ANGLE_MATCH),
      m_unboundQueryRegexp("resolving" UNBOUND_MATCH),
      //m_unboundPIRegexp(UNBOUND_MATCH "marking.*proveunsecure"),
      //m_unboundDNERegexp(UNBOUND_PAREN_MATCH "nonexistence validation OK"),
      //m_unboundTrustedAnswerRegexp(UNBOUND_MATCH "marking as answer.*dsfetched"),
      //m_unboundNoAnswerResponseRegexp(UNBOUND_PAREN_MATCH "noanswer_response"),
      //m_unboundAnswerResponseRegexp(UNBOUND_PAREN_MATCH "answer_response"),
      //m_unboundProvenNSECRegexp(UNBOUND_MATCH "nonexistence proof\\(s\\) found"),

      m_regexpList()
{
    m_nodeList = m_graphWidget->nodeList();

    // libval regexps
    m_regexpList.push_back(RegexpData(m_validatedRegexp,          DNSData::VALIDATED, "green") );
    m_regexpList.push_back(RegexpData(m_validatedChainPartRegexp, DNSData::VALIDATED, "green") );
    m_regexpList.push_back(RegexpData(m_cryptoSuccessRegexp,      DNSData::VALIDATED, "green") );
    m_regexpList.push_back(RegexpData(m_lookingUpRegexp,          DNSData::UNKNOWN,   "black") );
    m_regexpList.push_back(RegexpData(m_bogusRegexp,              DNSData::FAILED,    "red") );
    m_regexpList.push_back(RegexpData(m_trustedRegexp,            DNSData::TRUSTED,   "brown") );
    m_regexpList.push_back(RegexpData(m_pinsecure2Regexp,         DNSData::TRUSTED,   "brown"));
    m_regexpList.push_back(RegexpData(m_dneRegexp,                DNSData::VALIDATED | DNSData::DNE,   "green"));
    m_regexpList.push_back(RegexpData(m_maybeDneRegexp,           DNSData::DNE,       "brown"));
    m_regexpList.push_back(RegexpData(m_ignoreValidationRegexp,   DNSData::IGNORE,    "brown"));

    // bind regexps
    m_regexpList.push_back(RegexpData(m_bindBogusRegexp,          DNSData::FAILED,    "red"));
    m_regexpList.push_back(RegexpData(m_bindValidatedRegex,       DNSData::VALIDATED, "green"));
    m_regexpList.push_back(RegexpData(m_bindQueryRegexp,          DNSData::UNKNOWN,   "black"));
    m_regexpList.push_back(RegexpData(m_bindPIRegexp,             DNSData::TRUSTED,   "brown"));
    m_regexpList.push_back(RegexpData(m_bindTrustedAnswerRegexp,  DNSData::TRUSTED,   "brown"));
    m_regexpList.push_back(RegexpData(m_bindAnswerResponseRegexp, DNSData::UNKNOWN,   "brown"));
    // Unfortunately, this catches missing servers and stuff and doesn't mark *only* non-existance
    // m_regexpList.push_back(RegexpData(m_bindNoAnswerResponseRegexp, DNSData::DNE,   "brown"));
    m_regexpList.push_back(RegexpData(m_bindDNERegexp,            DNSData::DNE,       "brown"));
    m_regexpList.push_back(RegexpData(m_bindProvenNSECRegexp,     DNSData::DNE | DNSData::VALIDATED,   "brown"));

    // unbound regexps
    m_regexpList.push_back(RegexpData(m_unboundBogusRegexp,          DNSData::FAILED,    "red"));
    m_regexpList.push_back(RegexpData(m_unboundValidatedRegex,       DNSData::VALIDATED, "green"));
    m_regexpList.push_back(RegexpData(m_unboundQueryRegexp,          DNSData::UNKNOWN,   "black"));
    m_regexpList.push_back(RegexpData(m_unboundPIRegexp,             DNSData::TRUSTED,   "brown"));
    m_regexpList.push_back(RegexpData(m_unboundTrustedAnswerRegexp,  DNSData::TRUSTED,   "brown"));
    m_regexpList.push_back(RegexpData(m_unboundAnswerResponseRegexp, DNSData::UNKNOWN,   "brown"));
    // Unfortunately, this catches missing servers and stuff and doesn't mark *only* non-existance
    // m_regexpList.push_back(RegexpData(m_unboundNoAnswerResponseRegexp, DNSData::DNE,   "brown"));
    m_regexpList.push_back(RegexpData(m_unboundDNERegexp,            DNSData::DNE,       "brown"));
    m_regexpList.push_back(RegexpData(m_unboundProvenNSECRegexp,     DNSData::DNE | DNSData::VALIDATED,   "brown"));
}


bool LogWatcher::parseLogMessage(QString logMessage) {
    QColor color;
    QString nodeName;
    QList<DNSData> dnsDataNodes;
    Node *thenode;
    DNSData result("UNKNOWN", DNSData::UNKNOWN);

    // qDebug() << logMessage;

    // loop through all the registered regexps and mark them appropriately
    QList< RegexpData >::const_iterator i = m_regexpList.constBegin();
    QList< RegexpData >::const_iterator last = m_regexpList.constEnd();
    while (i != last) {
        if ((*i).regexp.indexIn(logMessage) > -1) {
            if (m_graphWidget && !m_graphWidget->showNsec3() && (*i).regexp.cap(2) == "NSEC3")
                return false;
            if ((*i).regexp.cap(2) == "NSEC")
                return false; // never show 'good' for something missing

            nodeName = (*i).regexp.cap(1);
            result.setRecordType((*i).regexp.cap(2));
            result.addDNSSECStatus((*i).status);
            logMessage = "<b><font color=\"" + (*i).colorName + "\">" + logMessage + "</font></b>";
            break;
        }
        i++;
    }

    // This one can't be put in the normal list since it remarks the data type as DS
    if (m_pinsecureRegexp.indexIn(logMessage) > -1) {
        nodeName = m_pinsecureRegexp.cap(1);
        // XXX: need the query type
        //result.setRecordType(m_validatedRegexp.cap(2));
        result.addDNSSECStatus(DNSData::VALIDATED | DNSData::DNE);
        result.setRecordType("DS");
        logMessage = "<b><font color=\"brown\">" + logMessage + "</font></b>";
    } else if (nodeName.isEmpty()) {
        return false;
    }

    if (nodeName == ".")
        return false;

    // add the data to the node
    thenode = m_nodeList->node(nodeName);
    thenode->addSubData(result);
    thenode->addLogMessage(logMessage);

    // update the screen
    m_nodeList->reApplyFiltersTo(thenode);
    return true;
}

void LogWatcher::parseLogFile(const QString &fileToOpen, bool skipToEnd) {
    QString fileName = fileToOpen;
    QFile       *logFile;
    QTextStream *logStream;

    if (fileName.length() == 0)
        return;

    // qDebug() << "Trying to open: " << fileName;

    // start the timer to keep reading/trying the log file
    if (!m_timer) {
        m_timer = new QTimer(this);
        connect(m_timer, SIGNAL(timeout()), this, SLOT(parseTillEnd()));
        m_timer->start(1000);
    }

    logFile = new QFile(fileName);
    if (!logFile->exists() || !logFile->open(QIODevice::ReadOnly | QIODevice::Text)) {
        delete logFile;
        logFile = 0;
        return;
    }

    logStream = new QTextStream(logFile);

    m_logFileNames.push_back(fileToOpen);
    m_logFiles.push_back(logFile);
    m_logStreams.push_back(logStream);

    // QFile doesn't implement a file watcher, so this won't work:
    // connect(logFile, SIGNAL(readyRead()), this, SLOT(parseTillEnd()));

    // qDebug() << "Opened: " << fileName;

    // if requested, skip to the end of the file
    if (skipToEnd)
        logStream->seek(logStream->device()->bytesAvailable());

    parseTillEnd();
}

void LogWatcher::parseTillEnd() {
    bool newData = false;

    foreach(QTextStream *logStream, m_logStreams) {
        while (!logStream->atEnd()) {
            QString line = logStream->readLine();
            if (parseLogMessage(line))
                newData = true;
        }
    }
    if (newData)
        emit dataChanged();
}

void LogWatcher::reReadLogFile() {
    while (!m_logStreams.isEmpty())
        delete m_logStreams.takeFirst();

    while (!m_logFiles.isEmpty())
        delete m_logFiles.takeFirst();

    // Restart from the top
    QStringList listCopy = m_logFileNames;
    m_logFileNames.clear();

    foreach (QString fileName, listCopy) {
        parseLogFile(fileName);
    }
}
