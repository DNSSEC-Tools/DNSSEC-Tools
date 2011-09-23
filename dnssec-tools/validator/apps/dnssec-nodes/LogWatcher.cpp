#include "LogWatcher.h"
#include "node.h"

#include <QtCore/QSettings>
#include <QtGui/QColor>

#include <qdebug.h>

LogWatcher::LogWatcher(GraphWidget *parent)
    : m_graphWidget(parent), m_timer(0),
    m_validatedRegexp("Verified a RRSIG for ([^ ]+) \\(([^\\)]+)\\)"),
    m_lookingUpRegexp("looking for \\{([^ ]+) .* ([^\\(]+)\\([0-9]+\\)\\}"),
    m_bogusRegexp("Validation result for \\{([^,]+),.*BOGUS"),                                     // XXX: type not listed; fix in libval
    m_trustedRegexp("Validation result for \\{([^,]+),.*: (VAL_IGNORE_VALIDATION|VAL_PINSECURE)"), // XXX: type not listed; fix in libval
    m_pinsecureRegexp("Setting proof status for ([^ ]+) to: VAL_NONEXISTENT_TYPE_NOCHAIN"),
    m_dneRegexp("Validation result for \\{([^,]+),.*VAL_NONEXISTENT_(NAME|TYPE):"),
    m_maybeDneRegexp("Validation result for \\{([^,]+),.*VAL_NONEXISTENT_NAME_NOCHAIN:")
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

    if (m_lookingUpRegexp.indexIn(logMessage) > -1) {
        nodeName = m_lookingUpRegexp.cap(1);
        result.setRecordType(m_lookingUpRegexp.cap(2));
        logMessage.replace(m_lookingUpRegexp, "<b>looking up \\1</b>  ");
    } else if (m_validatedRegexp.indexIn(logMessage) > -1) {
        if (m_graphWidget && !m_graphWidget->showNsec3() && m_validatedRegexp.cap(2) == "NSEC3")
            return false;
        if (m_validatedRegexp.cap(2) == "NSEC")
            return false; // never show 'good' for something missing
        nodeName = m_validatedRegexp.cap(1);
        result.setRecordType(m_validatedRegexp.cap(2));
        result.setDNSSECStatus(DNSData::VALIDATED);
        logMessage.replace(m_validatedRegexp, "<b><font color=\"green\">Verified a \\2 record for \\1 </font></b>");
        additionalInfo = "The data for this node has been Validated";
    } else if (m_bogusRegexp.indexIn(logMessage) > -1) {
        nodeName = m_bogusRegexp.cap(1);
        //result.setRecordType(m_validatedRegexp.cap(2)); // XXX: Need to modify the log message to find the type
        result.setDNSSECStatus(DNSData::FAILED);
        logMessage.replace(m_bogusRegexp, "<b><font color=\"red\">BOGUS Record found for \\1 </font></b>");
        additionalInfo = "DNSSEC Security for this Node Failed";
    } else if (m_trustedRegexp.indexIn(logMessage) > -1) {
        nodeName = m_trustedRegexp.cap(1);
        result.setDNSSECStatus(DNSData::TRUSTED);
        logMessage.replace(m_trustedRegexp, "<b><font color=\"brown\">Trusting result for \\1 </font></b>");
        additionalInfo = "Data is trusted, but not proven to be secure";
    } else if (m_pinsecureRegexp.indexIn(logMessage) > -1) {
        nodeName = m_pinsecureRegexp.cap(1);
        result.setDNSSECStatus(DNSData::TRUSTED);
        logMessage.replace(m_pinsecureRegexp, ":<b><font color=\"brown\"> \\1 is provably insecure </font></b>");
        additionalInfo = "This node has been proven to be <b>not</b> DNSEC protected";
    } else if (m_dneRegexp.indexIn(logMessage) > -1) {
        nodeName = m_dneRegexp.cap(1);
        result.setDNSSECStatus(DNSData::VALIDATED | DNSData::DNE);
        logMessage.replace(m_dneRegexp, ":<b><font color=\"brown\"> \\1 provably does not exist </font></b>");
        additionalInfo = "This node has been proven to not exist in the DNS";
    } else if (m_maybeDneRegexp.indexIn(logMessage) > -1) {
        nodeName = m_maybeDneRegexp.cap(1);
        result.setDNSSECStatus(DNSData::DNE);
        additionalInfo = "This node supposedly doesn't exist, but its non-existence can't be proven.";
        logMessage.replace(m_maybeDneRegexp, ":<b><font color=\"brown\"> \\1 does not exist, but can't be proven' </font></b>");
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
