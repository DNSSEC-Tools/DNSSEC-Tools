#include "Legend.h"

#include <QtGui/QVBoxLayout>
#include <QtGui/QLabel>
#include <QtGui/QDialogButtonBox>

Legend::Legend(QWidget *parent) :
    QDialog(parent)
{
    QLabel *label;
    QVBoxLayout *layout = new QVBoxLayout();
    setLayout(layout);

    layout->addWidget(label = new QLabel("<h2>Legend</h2>"));
    label->setAlignment(Qt::AlignHCenter);

    //
    // closing button box
    //

    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, Qt::Horizontal, this);
    layout->addWidget(buttonBox);

    setMinimumSize(600,400);

    connect(buttonBox, SIGNAL(rejected()), this, SLOT(accept()));
}
