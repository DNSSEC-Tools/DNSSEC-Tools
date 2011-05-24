#include "DnssecSystemTrayPrefs.h"

#include <QtCore/QSettings>
#include <QtGui/QDialogButtonBox>

DnssecSystemTrayPrefs::DnssecSystemTrayPrefs(QWidget *parent) :
    QDialog(parent)
{
    setupWindow();
}

void
DnssecSystemTrayPrefs::setupWindow() {
    QSettings settings("DNSSEC-Tools", "dnssec-system-tray");

    m_topLayout = new QVBoxLayout();
    m_topLayout->addLayout(m_formLayout = new QFormLayout());

    m_formLayout->addRow(tr("Log File to Watch"), m_logFile = new QLineEdit());
    m_logFile->setText(settings.value("logFile", QString("")).toString());

    QDialogButtonBox *buttonBox;
    buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok |
                                     QDialogButtonBox::Cancel,
                                     Qt::Horizontal, this);
    connect(buttonBox, SIGNAL(accepted()), this, SLOT(savePrefs()));
    connect(buttonBox, SIGNAL(rejected()), this, SLOT(reject()));
    m_topLayout->addWidget(buttonBox);

    setLayout(m_topLayout);
}

void
DnssecSystemTrayPrefs::savePrefs() {
    QSettings settings("DNSSEC-Tools", "dnssec-system-tray");
    settings.setValue("logFile", m_logFile->text());
    accept();
}
