#include "SubmitDialog.h"

#include <QtGui/QLabel>
#include <QtGui/QDialogButtonBox>

SubmitDialog::SubmitDialog(QWidget *parent) :
    QDialog(parent)
{
    QDialogButtonBox *buttonBox;
    topLayout = new QVBoxLayout();
    topLayout->addWidget(new QLabel("Would you like to submit the results to the public database?"));

    buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok |
                                     QDialogButtonBox::Cancel,
                                     Qt::Horizontal, this);
    connect(buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
    connect(buttonBox, SIGNAL(rejected()), this, SLOT(reject()));
    topLayout->addWidget(buttonBox);

    setLayout(topLayout);
}

