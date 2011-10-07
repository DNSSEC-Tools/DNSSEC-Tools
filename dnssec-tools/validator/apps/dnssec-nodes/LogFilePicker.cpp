#include "LogFilePicker.h"

#include <QtGui/QLabel>
#include <QtGui/QPushButton>
#include <QtGui/QCheckBox>
#include <QtGui/QDialogButtonBox>
#include <QtGui/QFileDialog>

LogFilePicker::LogFilePicker(QString defaultFile, QWidget *parent) :
    QDialog(parent)
{
    QVBoxLayout *vbox = new QVBoxLayout(this);
    setLayout(vbox);

    vbox->addWidget(new QLabel("Read a Log File"));

    QHBoxLayout *hbox = new QHBoxLayout();
    vbox->addLayout(hbox);
    m_fileEditBox = new QLineEdit();
    m_fileEditBox->setText(defaultFile);
    hbox->addWidget(m_fileEditBox);

    QPushButton *browserButton = new QPushButton(tr("Browse..."));
    hbox->addWidget(browserButton);
    connect(browserButton, SIGNAL(clicked()), this, SLOT(openBrowseWindow()));


    vbox->addWidget(m_skipToEnd = new QCheckBox(tr("Start Reading at the End of the File")));

    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, Qt::Horizontal, this);
    vbox->addWidget(buttonBox);

    connect(buttonBox, SIGNAL(rejected()), this, SLOT(reject()));
    connect(buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
}

void LogFilePicker::openBrowseWindow()
{
    QFileDialog dialog;
    dialog.selectFile(m_fileEditBox->text());
    dialog.setFileMode(QFileDialog::AnyFile);
    if (!dialog.exec())
        return;

    m_fileEditBox->setText(dialog.selectedFiles()[0]);
}

QString LogFilePicker::file()
{
    return m_fileEditBox->text();
}

bool LogFilePicker::skipToEnd()
{
    return m_skipToEnd->isChecked();
}
