#include "DetailsViewer.h"

#define QT_NO_PRINTER
#include <QtGui/QLabel>
#include <QtGui/QTextEdit>
#include <QtGui/QFont>
#include <QtGui/QFormLayout>
#include <QtGui/QStandardItemModel>
#include <QtGui/QTableView>
#include <QtGui/QTableWidget>
#include <QtGui/QHeaderView>
#include <QtGui/QIcon>
#include <QtGui/QPainter>
#include <QtGui/QPushButton>

#include "ValidateViewWidgetHolder.h"

#include <qdebug.h>

DetailsViewer::DetailsViewer(Node *node, GraphWidget *graphWidget, QTabWidget *tabs, QWidget *parent):
    QWidget(parent), m_node(node), m_mapper(new QSignalMapper()), m_tabs(tabs), m_rows(), m_rowCount(0), m_graphWidget(graphWidget)
{
    QVBoxLayout *mainLayout = new QVBoxLayout();
    QVBoxLayout  *dataTypesBox = new QVBoxLayout();
    m_table = new QTableWidget(node->getAllSubData().count(), 4);

    // Title
    m_title = new QLabel(node->fqdn());
    QFont font = m_title->font();
    font.setBold(true);
    font.setUnderline(true);
    font.setPointSize(16);
    m_title->setFont(font);
    m_title->setAlignment(Qt::AlignCenter);
    dataTypesBox->addWidget(m_title);

    //
    // Data Collected Info
    //
    dataTypesBox->addWidget(m_table);

    int itemnum = 0;
    m_table->setHorizontalHeaderItem(itemnum++, new QTableWidgetItem(tr("Record Type")));
    m_table->setHorizontalHeaderItem(itemnum++, new QTableWidgetItem(tr("Status")));
    m_table->setHorizontalHeaderItem(itemnum++, new QTableWidgetItem(tr("Data")));
    m_table->verticalHeader()->hide();

    setNode(node);

    mainLayout->addWidget(m_table);
    setLayout(mainLayout);
}

void DetailsViewer::setNode(Node *node) {
    if (!node)
        return;

    m_title->setText(node->fqdn());

    m_table->clearContents();
    m_rowCount = 0;

    QMapIterator<QString, DNSData *> iterator(node->getAllSubData());
    while(iterator.hasNext()) {
        iterator.next();

        addRow(iterator.key(), iterator.value());
    }
    connect(m_mapper, SIGNAL(mapped(QString)), this, SLOT(validateNode(QString)));
    m_table->resizeColumnsToContents();
}

void DetailsViewer::addRow(QString recordType, DNSData *data) {
    QTableWidgetItem *item;
    QPushButton *button;

    int itemnum = 0;

    m_table->setRowCount(m_rowCount+1);

    NodeWidgets *info = new NodeWidgets();

    item = new QTableWidgetItem(recordType);
    item->setFlags(Qt::ItemIsEnabled);
    m_table->setItem(m_rowCount, itemnum++, item);
    info->label = item;

    item = new QTableWidgetItem();
    item->setFlags(Qt::ItemIsEnabled);
    m_table->setItem(m_rowCount, itemnum++, item);
    info->status = item;

    item = new QTableWidgetItem(QStringList(data->data()).join(",\n"));
    item->setFlags(Qt::ItemIsEnabled);
    m_table->setItem(m_rowCount, itemnum++, item);
    info->data = item;

    button = new QPushButton("Validate");
    connect(button, SIGNAL(clicked()), m_mapper, SLOT(map()));
    m_mapper->setMapping(button, recordType);
    m_table->setCellWidget(m_rowCount, itemnum++, button);

    m_rows[recordType] = info;

    connect(data, SIGNAL(statusChanged(const DNSData*)), this, SLOT(setStatus(const DNSData *)));

    setStatus(data);

    m_rowCount++;
    m_table->resizeRowsToContents();
    m_table->resizeColumnsToContents();
}

void DetailsViewer::validateNode(QString nodeType)
{
    m_tabs->addTab(new ValidateViewWidgetHolder(m_node->fqdn(), nodeType, m_graphWidget), m_node->fqdn() + "/" + nodeType);
    m_tabs->setCurrentIndex(m_tabs->count()-1);
}

void DetailsViewer::setStatus(const DNSData *data) {
    QString recordType = data->recordType();
    QColor color = m_node->getColorForStatus(data->DNSSECStatus()).lighter(175);

    QTableWidgetItem *item = m_rows[recordType]->status;
    item->setBackgroundColor(color);
    item->setText(data->DNSSECStringStatuses().join(", "));

    item = m_rows[recordType]->data;
    item->setBackgroundColor(color);
    item->setText(QStringList(data->data()).join(",\n"));

    m_rows[recordType]->label->setBackgroundColor(color);
}
