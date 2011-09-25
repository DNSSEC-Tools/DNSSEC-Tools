#include "DetailsViewer.h"

#include <QtGui/QLabel>
#include <QtGui/QTextEdit>
#include <QtGui/QFont>

#include <qdebug.h>

DetailsViewer::DetailsViewer(Node *node, QWidget *parent) :
    QDialog(parent), m_node(node)
{
    m_layout = new QVBoxLayout();
    setLayout(m_layout);

    QLabel *title = new QLabel(node->fqdn(), this);
    QFont font = title->font();
    font.setBold(true);
    font.setUnderline(true);
    font.setPointSize(16);
    title->setFont(font);
    m_layout->addWidget(title);

    QTextEdit *textEdit = new QTextEdit("<p>" + node->logMessages().join("</p><p>") + "</p>", this);
    textEdit->setReadOnly(true);
    textEdit->setLineWrapMode(QTextEdit::NoWrap);
    m_layout->addWidget(textEdit);

    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok, Qt::Horizontal, this);
    m_layout->addWidget(buttonBox);

    setMinimumSize(600,400);

    connect(buttonBox, SIGNAL(accepted()), this, SLOT(accept()));
}
