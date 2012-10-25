#include "Legend.h"

#include <QtGui/QVBoxLayout>
#include <QtGui/QLabel>
#include <QtGui/QDialogButtonBox>
#include <QTableWidget>
#include <QtGui/QPainter>
#include <QtGui/QPixmap>
#include <QtGui/QIcon>
#include <QtGui/QTableWidgetItem>
#include <QtGui/QHeaderView>

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

    layout->addWidget(label = new QLabel(tr("<h2>DNSSEC-Nodes Coloring Legend</h2>")));
    label->setAlignment(Qt::AlignHCenter);

    QList<int> statuses;
    statuses << DNSData::UNKNOWN <<  DNSData::TRUSTED <<  DNSData::VALIDATED <<  DNSData::DNE
             << DNSData::FAILED <<  DNSData::IGNORE << (DNSData::DNE | DNSData::VALIDATED) << (DNSData::AD_VERIFIED)
             << DNSData::SERVFAIL_RCODE << DNSData::AUTHORATATIVE;

    // Add the legend widget
    QTableWidget *table = new QTableWidget(statuses.count(), 2, this);
    layout->addWidget(table);

    table->setHorizontalHeaderItem(0, new QTableWidgetItem(tr("Node")));
    table->setHorizontalHeaderItem(1, new QTableWidgetItem(tr("Description")));
    table->verticalHeader()->hide();

    QPointF rect = n->boundingRect().bottomRight() - n->boundingRect().topLeft();
    QSize size(rect.x() + 2, rect.y() + 2);
    QPointF br = n->boundingRect().bottomRight();

    int row = 0;
    foreach(int status, statuses) {
        QTableWidgetItem *item = new QTableWidgetItem(d.DNSSECStatusForEnum(status));
        item->setFlags(Qt::ItemIsEnabled);
        item->setBackgroundColor(n->getColorForStatus(status).lighter());
        table->setItem(row, 1, item);

        Node *node = new Node(0);
        QPixmap pm = QPixmap(size);
        QPainter painter(&pm);

        node->addSubData(DNSData("", status));

        painter.setBackground(Qt::white);
        painter.setBrush(Qt::white);
        painter.drawRect(-5, -5, size.width() + 5, size.height() + 5);
        painter.translate(br.x(), br.y());
        node->paint(&painter, 0, 0);

        QIcon icon = QIcon(pm);
        item = new QTableWidgetItem(icon, "");
        item->setFlags(Qt::ItemIsEnabled);
        table->setItem(row, 0, item);

        row++;
    }
    table->setRowCount(row);
    table->setColumnCount(2);
    table->resizeColumnsToContents();
    table->setSelectionMode(QAbstractItemView::NoSelection);

    layout->addWidget(new QLabel(tr("<p>Note: Widgets containing multiple nodes will show multiple status colors</p>")));
    layout->addWidget(new QLabel(tr("<p>Note: Some colors will take precedence over others; the color represents the most important status.</p>")));

    //
    // closing button box
    //

    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, Qt::Horizontal, this);
    layout->addWidget(buttonBox);

    setMinimumSize(600,400);

    connect(buttonBox, SIGNAL(rejected()), this, SLOT(accept()));
}
