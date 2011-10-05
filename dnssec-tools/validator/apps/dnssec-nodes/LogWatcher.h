#ifndef LOGWATCHER_H
#define LOGWATCHER_H

#include <QtCore/QFile>
#include <QtCore/QTextStream>
#include <QtCore/QStringList>
#include <QtCore/QRegExp>
#include <QtCore/QTimer>

#include "graphwidget.h"
#include "NodeList.h"

class GraphWidget;
class NodeList;

class LogWatcher : public QObject
{
    Q_OBJECT

public:
    LogWatcher(GraphWidget *parent = 0);

    void parseLogFile(const QString &fileToOpen);
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
};

#endif // LOGWATCHER_H
