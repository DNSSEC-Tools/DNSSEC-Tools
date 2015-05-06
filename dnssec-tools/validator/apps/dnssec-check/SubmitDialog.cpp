#include "SubmitDialog.h"

#include <QtWidgets/QLabel>
#include <QtWidgets/QDialogButtonBox>

SubmitDialog::SubmitDialog(QWidget *parent) :
    QDialog(parent)
{
    QDialogButtonBox *buttonBox;
    topLayout = new QVBoxLayout();
    topLayout->addWidget(new QLabel("Would you like to submit the results to the public database?"));

    topLayout->addWidget(new QLabel("(optional) A short description of your location:"));
    m_locationDescription = new QLineEdit();
    m_locationDescription->setMaxLength(255);
    topLayout->addWidget(m_locationDescription);

    buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok |
                                     QDialogButtonBox::Cancel,
                                     Qt::Horizontal, this);
    connect(buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
    connect(buttonBox, SIGNAL(rejected()), this, SLOT(reject()));
    topLayout->addWidget(buttonBox);


    setLayout(topLayout);
    m_locationDescription->setFocus();
}

QString
SubmitDialog::locationDescription() {
    return m_locationDescription->text();
}
