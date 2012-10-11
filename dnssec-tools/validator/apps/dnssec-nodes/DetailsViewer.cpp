#include "DetailsViewer.h"

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

#include "ValidateViewWidget.h"

#include <qdebug.h>

DetailsViewer::DetailsViewer(Node *node, QTabWidget *tabs, QWidget *parent):
    QWidget(parent), m_node(node), m_mapper(new QSignalMapper()), m_tabs(tabs), m_rows(), m_rowCount(0)
{
    QVBoxLayout *mainLayout = new QVBoxLayout();
    QVBoxLayout  *dataTypesBox = new QVBoxLayout();
    m_table = new QTableWidget(node->getAllSubData().count(), 3);

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

    m_table->setHorizontalHeaderItem(0, new QTableWidgetItem(tr("Record Type")));
    m_table->setHorizontalHeaderItem(1, new QTableWidgetItem(tr("Status")));
    m_table->verticalHeader()->hide();

    setNode(node);

    mainLayout->addWidget(m_table);
    setLayout(mainLayout);
}

void DetailsViewer::setNode(Node *node) {
    m_title->setText(node->fqdn());

    m_table->clear();
    m_rowCount = 0;

    QMapIterator<QString, DNSData> iterator(node->getAllSubData());
    while(iterator.hasNext()) {
        iterator.next();

        addRow(iterator.key(), iterator.value());
    }
    connect(m_mapper, SIGNAL(mapped(QString)), this, SLOT(validateNode(QString)));
    m_table->resizeColumnsToContents();
}

void DetailsViewer::addRow(QString recordType, const DNSData &data) {
    QTableWidgetItem *item;
    QPushButton *button;

    NodeWidgets *info = new NodeWidgets();

    item = new QTableWidgetItem(recordType);
    item->setFlags(Qt::ItemIsEnabled);
    m_table->setItem(m_rowCount, 0, item);
    info->label = item;

    item = new QTableWidgetItem();
    item->setFlags(Qt::ItemIsEnabled);
    m_table->setItem(m_rowCount, 1, item);
    info->status = item;

    button = new QPushButton("Validate");
    connect(button, SIGNAL(clicked()), m_mapper, SLOT(map()));
    m_mapper->setMapping(button, recordType);
    m_table->setCellWidget(m_rowCount, 2, button);

    m_rows[recordType] = info;

    setStatus(data);

    m_rowCount++;
    m_table->resizeColumnsToContents();
}

void DetailsViewer::validateNode(QString nodeType)
{
    m_tabs->addTab(new ValidateViewWidget(m_node->fqdn(), nodeType), m_node->fqdn() + "/" + nodeType);
    m_tabs->setCurrentIndex(m_tabs->count()-1);
}

void DetailsViewer::setStatus(DNSData data) {
    QString recordType = data.recordType();
    QColor color = m_node->getColorForStatus(data.DNSSECStatus()).lighter(175);

    QTableWidgetItem *statusItem = m_rows[recordType]->status;
    statusItem->setBackgroundColor(color);
    statusItem->setText(data.DNSSECStringStatuses().join(", "));

    m_rows[recordType]->label->setBackgroundColor(color);
}
