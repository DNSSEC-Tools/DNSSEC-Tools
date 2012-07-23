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
    QObject(parent), m_node(node), m_tabs(tabs), m_mapper(new QSignalMapper())
{

\
    QVBoxLayout  *dataTypesBox = new QVBoxLayout();
    QTableWidget *table = new QTableWidget(node->getAllSubData().count(), 3, m_tabs);

    // Title
    QLabel *title = new QLabel(node->fqdn());
    QFont font = title->font();
    font.setBold(true);
    font.setUnderline(true);
    font.setPointSize(16);
    title->setFont(font);
    title->setAlignment(Qt::AlignCenter);
    dataTypesBox->addWidget(title);

    //
    // Data Collected Info
    //
    dataTypesBox->addWidget(table);

    table->setHorizontalHeaderItem(0, new QTableWidgetItem(tr("Record Type")));
    table->setHorizontalHeaderItem(1, new QTableWidgetItem(tr("Status")));
    table->verticalHeader()->hide();

    QMapIterator<QString, DNSData> iterator(node->getAllSubData());
    QTableWidgetItem *item;
    QPushButton *button;
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

        button = new QPushButton("Validate");
        connect(button, SIGNAL(clicked()), m_mapper, SLOT(map()));
        m_mapper->setMapping(button, iterator.key());
        table->setCellWidget(row, 2, button);
        row++;
    }
    connect(m_mapper, SIGNAL(mapped(QString)), this, SLOT(validateNode(QString)));
    table->resizeColumnsToContents();

    m_tabs->addTab(table, tr("%1 data").arg(node->fqdn()));
    m_tabs->setCurrentWidget(table);

    //
    // Log Message Viewer
    //
    QWidget *widget = new QWidget();
    QVBoxLayout *vbox = new QVBoxLayout();

    widget->setLayout(vbox);


    QTextEdit *textEdit = new QTextEdit("<p>" + node->logMessages().join("</p><p>") + "</p>");
    textEdit->setReadOnly(true);
    textEdit->setLineWrapMode(QTextEdit::NoWrap);
    vbox->addWidget(textEdit);

    m_tabs->addTab(widget, tr("%1 Log").arg(node->fqdn()));
}

void DetailsViewer::validateNode(QString nodeType)
{
    m_tabs->addTab(new ValidateViewWidget(m_node->fqdn(), nodeType), m_node->fqdn() + "/" + nodeType);
    m_tabs->setCurrentIndex(m_tabs->count()-1);
}

