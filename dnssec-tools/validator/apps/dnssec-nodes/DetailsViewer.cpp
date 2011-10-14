#include "DetailsViewer.h"

#include <QtGui/QLabel>
#include <QtGui/QTextEdit>
#include <QtGui/QFont>
#include <QtGui/QTabWidget>
#include <QtGui/QFormLayout>
#include <QtGui/QStandardItemModel>
#include <QtGui/QTableView>
#include <QtGui/QTableWidget>
#include <QtGui/QHeaderView>
#include <QtGui/QIcon>
#include <QtGui/QPainter>

#include <qdebug.h>

DetailsViewer::DetailsViewer(Node *node, QWidget *parent) :
    QDialog(parent), m_node(node)
{
    QWidget *widget;
    m_layout = new QVBoxLayout();
    setLayout(m_layout);

    // Title
    QLabel *title = new QLabel(node->fqdn(), this);
    QFont font = title->font();
    font.setBold(true);
    font.setUnderline(true);
    font.setPointSize(16);
    title->setFont(font);
    title->setAlignment(Qt::AlignCenter);
    m_layout->addWidget(title);

    // display tabs
    QTabWidget *tabs = new QTabWidget();
    m_layout->addWidget(tabs);

    //
    // Data Collected Info
    //
    QTableWidget *table = new QTableWidget(node->getAllSubData().count(), 2, tabs);

    table->setHorizontalHeaderItem(0, new QTableWidgetItem(tr("Record Type")));
    table->setHorizontalHeaderItem(1, new QTableWidgetItem(tr("Status")));
    table->verticalHeader()->hide();

    QMapIterator<QString, DNSData> iterator(node->getAllSubData());
    QTableWidgetItem *item;
    int row = 0;
    while(iterator.hasNext()) {
        iterator.next();

        QColor backgroundColor = node->getColorForStatus(iterator.value().DNSSECStatus()).lighter(175);

        item = new QTableWidgetItem(iterator.key());
        item->setFlags(Qt::ItemIsEnabled);
        item->setBackgroundColor(backgroundColor);
        table->setItem(row, 0, item);

        item = new QTableWidgetItem(iterator.value().DNSSECStringStatuses().join(", "));
        item->setFlags(Qt::ItemIsEnabled);
        item->setBackgroundColor(backgroundColor);
        table->setItem(row, 1, item);

        row++;
    }
    table->resizeColumnsToContents();

    tabs->addTab(table, tr("Datatypes Seen"));

    //
    // Log Message Viewer
    //
    widget = new QWidget();
    QVBoxLayout *vbox = new QVBoxLayout();

    widget->setLayout(vbox);


    QTextEdit *textEdit = new QTextEdit("<p>" + node->logMessages().join("</p><p>") + "</p>", this);
    textEdit->setReadOnly(true);
    textEdit->setLineWrapMode(QTextEdit::NoWrap);
    vbox->addWidget(textEdit);

    tabs->addTab(widget, tr("Log Messages"));

    //
    // closing button box
    //

    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, Qt::Horizontal, this);
    m_layout->addWidget(buttonBox);

    setMinimumSize(600,400);

    connect(buttonBox, SIGNAL(rejected()), this, SLOT(accept()));
}
