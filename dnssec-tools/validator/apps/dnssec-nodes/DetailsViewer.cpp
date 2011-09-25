#include "DetailsViewer.h"

#include <QtGui/QLabel>
#include <QtGui/QTextEdit>
#include <QtGui/QFont>
#include <QtGui/QTabWidget>
#include <QtGui/QFormLayout>

#include <qdebug.h>

DetailsViewer::DetailsViewer(Node *node, QWidget *parent) :
    QDialog(parent), m_node(node)
{

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
    // Log Message Viewer
    //
    QWidget *widget = new QWidget();
    QVBoxLayout *vbox = new QVBoxLayout();

    widget->setLayout(vbox);


    QTextEdit *textEdit = new QTextEdit("<p>" + node->logMessages().join("</p><p>") + "</p>", this);
    textEdit->setReadOnly(true);
    textEdit->setLineWrapMode(QTextEdit::NoWrap);
    vbox->addWidget(textEdit);

    tabs->addTab(widget, tr("Log Messages"));

    //
    // Data Collected Info
    //
    widget = new QWidget();
    QFormLayout *form = new QFormLayout();
    widget->setLayout(form);

    QMapIterator<QString, DNSData> iterator(node->getAllSubData());
    QLabel *label;
    while(iterator.hasNext()) {
        iterator.next();
        form->addRow(iterator.key(), label = new QLabel(iterator.value().DNSSECStringStatuses().join(",")));
    }

    tabs->addTab(widget, tr("Datatypes Seen"));

    //
    // closing button box
    //

    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, Qt::Horizontal, this);
    m_layout->addWidget(buttonBox);

    setMinimumSize(600,400);

    connect(buttonBox, SIGNAL(rejected()), this, SLOT(accept()));
}
