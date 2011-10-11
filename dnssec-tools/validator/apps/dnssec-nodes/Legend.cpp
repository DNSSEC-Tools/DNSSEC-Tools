#include "Legend.h"

#include <QtGui/QVBoxLayout>
#include <QtGui/QLabel>
#include <QtGui/QDialogButtonBox>
#include <QTableWidget>

#include <qdebug.h>

#include "DNSData.h"
#include "node.h"

Legend::Legend(QWidget *parent) :
    QDialog(parent)
{
    QLabel *label;
    QVBoxLayout *layout = new QVBoxLayout();
    setLayout(layout);

    DNSData d;
    Node *n = new Node(0);

    layout->addWidget(label = new QLabel("<h2>Legend</h2>"));
    label->setAlignment(Qt::AlignHCenter);

    QList<DNSData::Status> statuses;
    statuses << DNSData::UNKNOWN <<  DNSData::TRUSTED <<  DNSData::VALIDATED <<  DNSData::DNE << DNSData::FAILED <<  DNSData::IGNORE;

    // Add the legend widget
    QTableWidget *table = new QTableWidget(statuses.count(), 2, this);
    layout->addWidget(table);


    int row = 0;
    foreach(DNSData::Status status, statuses) {
        QTableWidgetItem *item = new QTableWidgetItem(d.DNSSECStatusForEnum(status));
        item->setFlags(Qt::ItemIsEnabled);
        item->setBackgroundColor(n->getColorForStatus(status).lighter());
        table->setItem(row, 0, item);
        row++;
    }
    table->setRowCount(row);
    table->setColumnCount(1);
    table->resizeColumnsToContents();

    //
    // closing button box
    //

    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, Qt::Horizontal, this);
    layout->addWidget(buttonBox);

    setMinimumSize(600,400);

    connect(buttonBox, SIGNAL(rejected()), this, SLOT(accept()));
}
