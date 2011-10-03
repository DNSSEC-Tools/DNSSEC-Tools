#include "LogWatcher.h"
#include "node.h"

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

      // bind regexps
      m_bindValidatedRegex(BIND_MATCH "verify rdataset.*: success"),
      m_bindBogusRegexp(BIND_MATCH "verify rdataset.*failed to verify"),
      m_bindQueryRegexp(BIND_PAREN_MATCH "query"),
      m_bindPIRegexp(BIND_MATCH "marking.*proveunsecure"),
      m_bindDNERegexp(BIND_PAREN_MATCH "nonexistence validation OK"),
      m_bindTrustedAnswerRegexp(BIND_MATCH "marking as answer.*dsfetched"),
      m_bindAnswerResponseRegexp(BIND_PAREN_MATCH "answer_response"),
      m_bindNoAnswerResponseRegexp(BIND_PAREN_MATCH "noanswer_response"),
      m_bindProvenNSECRegexp(BIND_MATCH "nonexistence proof\\(s\\) found")
{
    m_nodeList = m_graphWidget->nodeList();
}


bool LogWatcher::parseLogMessage(QString logMessage) {
    QColor color;
    QString nodeName;
    QString additionalInfo = "";
    QList<DNSData> dnsDataNodes;
    Node *thenode;
    DNSData result("UNKNOWN", DNSData::UNKNOWN);

    // qDebug() << logMessage;

    // ---------------------------------------------------------------
    // match libval patterns
    //
    if (m_lookingUpRegexp.indexIn(logMessage) > -1) {
        nodeName = m_lookingUpRegexp.cap(1);
        result.setRecordType(m_lookingUpRegexp.cap(2));
        result.addDNSSECStatus(DNSData::UNKNOWN);
        logMessage.replace(m_lookingUpRegexp, "<b>looking up a \\2 record for \\1</b>  ");

    } else if (m_validatedRegexp.indexIn(logMessage) > -1) {
        if (m_graphWidget && !m_graphWidget->showNsec3() && m_validatedRegexp.cap(2) == "NSEC3")
            return false;
        if (m_validatedRegexp.cap(2) == "NSEC")
            return false; // never show 'good' for something missing
        nodeName = m_validatedRegexp.cap(1);
        result.setRecordType(m_validatedRegexp.cap(2));
        result.addDNSSECStatus(DNSData::VALIDATED);
        logMessage.replace(m_validatedRegexp, "<b><font color=\"green\">Verified a \\2 record for \\1 </font></b>");
        additionalInfo = "The data for this node has been Validated";

    } else if (m_validatedChainPartRegexp.indexIn(logMessage) > -1) {
        if (m_graphWidget && !m_graphWidget->showNsec3() && m_validatedChainPartRegexp.cap(2) == "NSEC3")
            return false;
        if (m_validatedChainPartRegexp.cap(2) == "NSEC")
            return false; // never show 'good' for something missing
        nodeName = m_validatedChainPartRegexp.cap(1);
        result.setRecordType(m_validatedChainPartRegexp.cap(2));
        result.addDNSSECStatus(DNSData::VALIDATED);
        logMessage.replace(m_validatedChainPartRegexp, "<b><font color=\"green\">Verified a \\2 record for \\1 </font></b>");
        additionalInfo = "The data for this node has been ValidatedChainPart";

    } else if (m_bogusRegexp.indexIn(logMessage) > -1) {
        nodeName = m_bogusRegexp.cap(1);
        result.setRecordType(m_bogusRegexp.cap(2));
        result.addDNSSECStatus(DNSData::FAILED);
        logMessage.replace(m_bogusRegexp, "<b><font color=\"green\">BOGUS Record found for a \\2 record for \\1 </font></b>");
        additionalInfo = "DNSSEC Security for this Node Failed";

    } else if (m_trustedRegexp.indexIn(logMessage) > -1) {
        nodeName = m_trustedRegexp.cap(1);
        result.setRecordType(m_trustedRegexp.cap(2));
        result.addDNSSECStatus(DNSData::TRUSTED);
        logMessage.replace(m_trustedRegexp, "<b><font color=\"brown\">Trusting result for \\2 record for \\1 </font></b>");
        additionalInfo = "Data is trusted, but not proven to be secure";

    } else if (m_pinsecure2Regexp.indexIn(logMessage) > -1) {
        nodeName = m_pinsecure2Regexp.cap(1);
        result.addDNSSECStatus(DNSData::TRUSTED);
        result.setRecordType(m_pinsecure2Regexp.cap(2));
        // XXX: need the query type
        //result.setRecordType(m_validatedRegexp.cap(2));
        logMessage.replace(m_pinsecure2Regexp, ":<b><font color=\"brown\"> \\1 (\\2) is provably insecure </font></b>");
        additionalInfo = "This node has been proven to be <b>not</b> DNSEC protected";

    } else if (m_pinsecureRegexp.indexIn(logMessage) > -1) {
        nodeName = m_pinsecureRegexp.cap(1);
        // XXX: need the query type
        //result.setRecordType(m_validatedRegexp.cap(2));
        result.addDNSSECStatus(DNSData::VALIDATED | DNSData::DNE);
        result.setRecordType("DS");
        logMessage.replace(m_pinsecureRegexp, ":<b><font color=\"brown\"> \\1 is provably insecure </font></b>");
        additionalInfo = "This node has been proven to be <b>not</b> DNSEC protected";

    } else if (m_dneRegexp.indexIn(logMessage) > -1) {
        nodeName = m_dneRegexp.cap(1);
        result.setRecordType(m_dneRegexp.cap(2));
        result.addDNSSECStatus(DNSData::VALIDATED | DNSData::DNE);
        logMessage.replace(m_dneRegexp, ":<b><font color=\"brown\"> \\1 provably does not exist </font></b>");
        additionalInfo = "This node has been proven to not exist in the DNS";

    } else if (m_maybeDneRegexp.indexIn(logMessage) > -1) {
        nodeName = m_maybeDneRegexp.cap(1);
        result.setRecordType(m_maybeDneRegexp.cap(2));
        result.addDNSSECStatus(DNSData::DNE);
        additionalInfo = "This node supposedly doesn't exist, but its non-existence can't be proven.";
        logMessage.replace(m_maybeDneRegexp, ":<b><font color=\"brown\"> \\1 does not exist, but can't be proven' </font></b>");

    } else if (m_cryptoSuccessRegexp.indexIn(logMessage) > -1) {
        if (m_graphWidget && !m_graphWidget->showNsec3() && m_cryptoSuccessRegexp.cap(2) == "NSEC3")
            return false;
        if (m_cryptoSuccessRegexp.cap(2) == "NSEC")
            return false; // never show 'good' for something missing
        nodeName = m_cryptoSuccessRegexp.cap(1);
        result.setRecordType(m_cryptoSuccessRegexp.cap(2));
        result.addDNSSECStatus(DNSData::VALIDATED);
        logMessage.replace(m_cryptoSuccessRegexp, "<b><font color=\"green\">Verified a \\2 record for \\1 </font></b>");
        additionalInfo = "The data for this node has been Validated";



    // --------------------------------------------------------------
    // Match bind patterns

    } else if (m_bindBogusRegexp.indexIn(logMessage) > -1) {
        nodeName = m_bindBogusRegexp.cap(1);
        result.setRecordType(m_bindBogusRegexp.cap(2));
        result.addDNSSECStatus(DNSData::FAILED);
        logMessage.replace(m_bindBogusRegexp, "<b><font color=\"green\">BOGUS Record found for a \\2 record for \\1 </font></b>");
        additionalInfo = "DNSSEC Security for this Node Failed";

    } else if (m_bindValidatedRegex.indexIn(logMessage) > -1) {
        nodeName = m_bindValidatedRegex.cap(1);
        result.setRecordType(m_bindValidatedRegex.cap(2));
        result.addDNSSECStatus(DNSData::VALIDATED);
        logMessage.replace(m_bindValidatedRegex, "<b><font color=\"green\">Verified a \\2 record for \\1 </font></b>");
        additionalInfo = "The data for this node has been Validated";

    } else if (m_bindQueryRegexp.indexIn(logMessage) > -1) {
        nodeName = m_bindQueryRegexp.cap(1);
        result.setRecordType(m_bindQueryRegexp.cap(2));
        result.addDNSSECStatus(DNSData::UNKNOWN);
        logMessage.replace(m_bindQueryRegexp, "<b>looking up a \\2 record for \\1</b>  ");

    } else if (m_bindPIRegexp.indexIn(logMessage) > -1) {
        nodeName = m_bindPIRegexp.cap(1);
        result.setRecordType(m_bindPIRegexp.cap(2));
        result.addDNSSECStatus(DNSData::TRUSTED);
        logMessage.replace(m_bindPIRegexp, "<b><font color=\"brown\"> \\1 (\\2) is provably insecure </font></b>  ");

    } else if (m_bindTrustedAnswerRegexp.indexIn(logMessage) > -1) {
        nodeName = m_bindTrustedAnswerRegexp.cap(1);
        result.setRecordType(m_bindTrustedAnswerRegexp.cap(2));
        result.addDNSSECStatus(DNSData::TRUSTED);
        logMessage.replace(m_bindTrustedAnswerRegexp, "<b><font color=\"brown\"> \\1 (\\2) is trusted but not proven </font></b>  ");

    } else if (m_bindAnswerResponseRegexp.indexIn(logMessage) > -1) {
        nodeName = m_bindAnswerResponseRegexp.cap(1);
        result.setRecordType(m_bindAnswerResponseRegexp.cap(2));
        result.addDNSSECStatus(DNSData::TRUSTED);
        logMessage.replace(m_bindAnswerResponseRegexp, "<b><font color=\"brown\"> an answer for a \\2 record for \\1 was found</font></b>  ");//    } else if (m_bindDNERegexp.indexIn(logMessage) > -1) {

        // Unfortunately, this catches missing servers and stuff and doesn't mark *only* non-existance
//    } else if (m_bindNoAnswerResponseRegexp.indexIn(logMessage) > -1) {
//        nodeName = m_bindNoAnswerResponseRegexp.cap(1);
//        result.setRecordType(m_bindNoAnswerResponseRegexp.cap(2));
//        result.addDNSSECStatus(DNSData::DNE);
//        logMessage.replace(m_bindNoAnswerResponseRegexp, "<b><font color=\"brown\"> an answer for a \\2 record for \\1 was not found</font></b>  ");//    } else if (m_bindDNERegexp.indexIn(logMessage) > -1) {


    } else if (m_bindDNERegexp.indexIn(logMessage) > -1) {
        nodeName = m_bindDNERegexp.cap(1);
        result.setRecordType(m_bindDNERegexp.cap(2));
        result.addDNSSECStatus(DNSData::DNE);
        logMessage.replace(m_bindDNERegexp, "<b><font color=\"brown\"> a \\2 record for \\1 provably does not exist </font></b>  ");

    } else if (m_bindProvenNSECRegexp.indexIn(logMessage) > -1) {
        nodeName = m_bindProvenNSECRegexp.cap(1);
        result.setRecordType(m_bindProvenNSECRegexp.cap(2));
        result.addDNSSECStatus(DNSData::DNE | DNSData::VALIDATED);
        logMessage.replace(m_bindProvenNSECRegexp, "<b><font color=\"brown\"> a \\2 record for \\1 provably does not exist </font></b>  ");

    } else {
        return false;
    }
    if (nodeName == ".")
        return false;
    thenode = m_nodeList->node(nodeName);
    thenode->addSubData(result);
    if (additionalInfo.length() > 0)
        thenode->setAdditionalInfo(additionalInfo);
    thenode->addLogMessage(logMessage);
    return true;
}

void LogWatcher::parseLogFile(const QString &fileToOpen) {
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
