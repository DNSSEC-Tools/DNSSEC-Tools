#ifndef DNSSECSYSTEMTRAYPREFS_H
#define DNSSECSYSTEMTRAYPREFS_H

#include <QDialog>
#include <QtGui/QVBoxLayout>
#include <QtGui/QFormLayout>
#include <QtGui/QLineEdit>

class DnssecSystemTrayPrefs : public QDialog
{
    Q_OBJECT
public:
    explicit DnssecSystemTrayPrefs(QWidget *parent = 0);

    void setupWindow();
signals:

public slots:
    void savePrefs();

private:
    QVBoxLayout     *m_topLayout;
    QFormLayout     *m_formLayout;
    QLineEdit       *m_logFile;
};

#endif // DNSSECSYSTEMTRAYPREFS_H
