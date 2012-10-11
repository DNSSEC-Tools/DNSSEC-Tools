#ifndef LOGWATCHER_H
#define LOGWATCHER_H

#include <QtCore/QFile>
#include <QtCore/QTextStream>
#include <QtCore/QStringList>
#include <QtCore/QString>
#include <QtCore/QRegExp>
#include <QtCore/QTimer>
#include <QtCore/QList>
#include <QtCore/QPair>

#include "NodeList.h"
#include "DNSData.h"

class GraphWidget;
class NodeList;

class RegexpData {
public:
    RegexpData(QRegExp r, int s, QString c) : regexp(r), status(s), colorName(c) { }
    QRegExp         regexp;
    int             status;
    QString         colorName;
};

class LogWatcher : public QObject
{
    Q_OBJECT

public:
    LogWatcher(GraphWidget *parent = 0);

    void parseLogFile(const QString &fileToOpen, bool skipToEnd = false);
    bool parseLogMessage(QString logMessage);

    void openLogFile();

public slots:
    void parseTillEnd();
    void reReadLogFile();

signals:
    void dataChanged();

private:
    GraphWidget         *m_graphWidget;
    NodeList            *m_nodeList;

    QStringList          m_logFileNames;
    QList<QFile *>       m_logFiles;
    QList<QTextStream *> m_logStreams;

    QTimer              *m_timer;

    // libval regexps
    QRegExp    m_validatedRegexp;
    QRegExp    m_validatedChainPartRegexp;
    QRegExp    m_cryptoSuccessRegexp;
    QRegExp    m_lookingUpRegexp;
    QRegExp    m_bogusRegexp;
    QRegExp    m_trustedRegexp;
    QRegExp    m_pinsecureRegexp, m_pinsecure2Regexp;
    QRegExp    m_dneRegexp;
    QRegExp    m_maybeDneRegexp;
    QRegExp    m_ignoreValidationRegexp;

    // bind regexps
    QRegExp    m_bindValidatedRegex;
    QRegExp    m_bindBogusRegexp;
    QRegExp    m_bindQueryRegexp;
    QRegExp    m_bindPIRegexp;
    QRegExp    m_bindDNERegexp;
    QRegExp    m_bindTrustedAnswerRegexp;
    QRegExp    m_bindNoAnswerResponseRegexp;
    QRegExp    m_bindAnswerResponseRegexp;
    QRegExp    m_bindProvenNSECRegexp;

    // unbound regexps
    QRegExp    m_unboundValidatedRegex;
    QRegExp    m_unboundBogusRegexp;
    QRegExp    m_unboundQueryRegexp;
    QRegExp    m_unboundPIRegexp;
    QRegExp    m_unboundDNERegexp;
    QRegExp    m_unboundTrustedAnswerRegexp;
    QRegExp    m_unboundNoAnswerResponseRegexp;
    QRegExp    m_unboundAnswerResponseRegexp;
    QRegExp    m_unboundProvenNSECRegexp;

    QList< RegexpData > m_regexpList;
};

#endif // LOGWATCHER_H
