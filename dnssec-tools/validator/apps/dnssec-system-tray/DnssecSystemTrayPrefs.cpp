#include "DnssecSystemTrayPrefs.h"

#include <QtCore/QSettings>
#include <QtGui/QDialogButtonBox>
#include <QtGui/QPushButton>
#include <QtGui/QFileDialog>
#include <QtGui/QLabel>
#include <QtGui/QFont>

DnssecSystemTrayPrefs::DnssecSystemTrayPrefs(QWidget *parent) :
    QDialog(parent)
{
    readLogFiles();
    setupWindow();
}


void
DnssecSystemTrayPrefs::setupWindow() {
    QSettings settings("DNSSEC-Tools", "dnssec-system-tray");
    QLabel *label;

    m_topLayout = new QVBoxLayout();
    m_topLayout->addLayout(m_formLayout = new QFormLayout());

    QHBoxLayout *hbox = new QHBoxLayout();
    m_logFile = new QTextEdit();
    hbox->addWidget(m_logFile);
    QPushButton *browserButton = new QPushButton(tr("Browse..."));
    hbox->addWidget(browserButton);
    connect(browserButton, SIGNAL(clicked()), this, SLOT(openBrowseWindow()));

    m_formLayout->addRow(tr("<p>Log File(s) to Watch<br /><i>(either bind-named, unbound or libval logs)</i></p>"), hbox);
    m_formLayout->addRow(new QLabel(""), label = new QLabel(""));
    QFont font = label->font();
    font.setItalic(true);
    label->setFont(font);
    m_logFile->setText(m_logFileList.join("\n"));

    m_formLayout->addRow(tr("Number of Log Messages to Keep"), m_logNumber = new QSpinBox());
    m_logNumber->setRange(1, 1000);
    m_logNumber->setValue(settings.value("logNumber", 5).toInt());

    m_formLayout->addRow(tr("Show still-running warning on close:"),
                         m_stillRunningWarning = new QCheckBox());
    m_stillRunningWarning->setChecked(settings.value("stillRunningWarning", true).toBool());

    QDialogButtonBox *buttonBox;
    buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok |
                                     QDialogButtonBox::Cancel,
                                     Qt::Horizontal, this);
    connect(buttonBox, SIGNAL(accepted()), this, SLOT(savePrefs()));
    connect(buttonBox, SIGNAL(rejected()), this, SLOT(reject()));
    m_topLayout->addWidget(buttonBox);

    setLayout(m_topLayout);
    setMinimumSize(640,400);
}

void
DnssecSystemTrayPrefs::readLogFiles()
{
    QSettings settings("DNSSEC-Tools", "dnssec-system-tray");
    int numFiles = settings.beginReadArray("logFileList");
    for(int i = 0 ; i < numFiles; i++) {
        settings.setArrayIndex(i);
        m_logFileList.push_back(settings.value("logFile").toString());
    }
    settings.endArray();
}

void
DnssecSystemTrayPrefs::savePrefs() {
    QSettings settings("DNSSEC-Tools", "dnssec-system-tray");
    settings.setValue("logNumber", m_logNumber->value());
    settings.setValue("stillRunningWarning", m_stillRunningWarning->isChecked());

    // create the list of files
    listFromString();

    // save the list of log files
    settings.beginWriteArray("logFileList");
    int count = 0;
    foreach(QString logFile, m_logFileList) {
        settings.setArrayIndex(count);
        settings.setValue("logFile", logFile);
        count++;
    }
    settings.endArray();

    accept();
}

void DnssecSystemTrayPrefs::openBrowseWindow()
{
    QFileDialog dialog;
    dialog.setAcceptMode(QFileDialog::AcceptOpen);
    dialog.setFileMode(QFileDialog::ExistingFiles);

    foreach(QString logFile, m_logFileList) {
        dialog.selectFile(logFile);
    }

    if (!dialog.exec())
        return;

    m_logFile->setText(dialog.selectedFiles().join("\n"));
    listFromString();
}

void DnssecSystemTrayPrefs::listFromString() {
    m_logFileList.clear();
    foreach(QString logFile, m_logFile->toPlainText().split("\n", QString::SkipEmptyParts)) {
        if (!logFile.isEmpty()) {
            m_logFileList.append(logFile);
        }
    }
}
