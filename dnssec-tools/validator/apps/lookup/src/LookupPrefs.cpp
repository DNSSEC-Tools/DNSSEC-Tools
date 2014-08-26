#include <QWidget>
#include "LookupPrefs.h"
#include <QtGui/QWidget>
#include <QtGui/QDialogButtonBox>
#include <QtCore/QSettings>
LookupPrefs::LookupPrefs(QWidget *parent) :
    QDialog(parent)
{
    createLayout();
    setLayout(topLayout);
}

void
LookupPrefs::createLayout() {

    QSettings settings("DNSSEC-Tools", "Lookup");

    topLayout = new QVBoxLayout();
    formLayout = new QFormLayout();
    topLayout->addLayout(formLayout);
    formLayout->addRow("Log File Location", logLocation = new QLineEdit);
    logLocation->setText(settings.value("logPath", "").toString());

    QDialogButtonBox *buttonBox;
    buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok |
                                     QDialogButtonBox::Cancel,
                                     Qt::Horizontal, this);
    connect(buttonBox, SIGNAL(accepted()), this, SLOT(savePrefs()));
    connect(buttonBox, SIGNAL(rejected()), this, SLOT(reject()));
    topLayout->addWidget(buttonBox);
}

void
LookupPrefs::savePrefs() {
    QSettings settings("DNSSEC-Tools", "Lookup");
    settings.setValue("logPath", logLocation->text());
    accept();
}
