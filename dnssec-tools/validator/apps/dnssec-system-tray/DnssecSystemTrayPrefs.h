#ifndef DNSSECSYSTEMTRAYPREFS_H
#define DNSSECSYSTEMTRAYPREFS_H

#define QT_NO_PRINTER

#include <QDialog>
#include <QtGui/QVBoxLayout>
#include <QtGui/QFormLayout>
#include <QtGui/QLineEdit>
#include <QtGui/QSpinBox>
#include <QtGui/QCheckBox>
#include <QtGui/QTextEdit>

class DnssecSystemTrayPrefs : public QDialog
{
    Q_OBJECT
public:
    explicit DnssecSystemTrayPrefs(QWidget *parent = 0);

    void setupWindow();
    void readLogFiles();
    void listFromString();
signals:

public slots:
    void savePrefs();
    void openBrowseWindow();

private:
    QVBoxLayout     *m_topLayout;
    QFormLayout     *m_formLayout;
    QTextEdit       *m_logFile;
    QSpinBox        *m_logNumber;
    QCheckBox       *m_stillRunningWarning;
    QStringList      m_logFileList;
};

#endif // DNSSECSYSTEMTRAYPREFS_H
