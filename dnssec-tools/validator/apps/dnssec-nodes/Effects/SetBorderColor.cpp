#include "SetBorderColor.h"

#include "node.h"
#include <qdebug.h>

#include <QLabel>

SetBorderColor::SetBorderColor(QColor borderColor, QObject *parent)
    : Effect(parent), m_borderColor(borderColor)
{
    connect(this, SIGNAL(borderColorChanged()), this, SIGNAL(effectChanged()));
}

void SetBorderColor::applyToNode(Node *node)
{
    node->setBorderColor(m_borderColor);
}

void SetBorderColor::resetNode(Node *node)
{
    node->setBorderColor(Qt::black);
}

void SetBorderColor::configWidgets(QHBoxLayout *hbox)
{
    QLabel *label = new QLabel("color");
    hbox->addWidget(label);
}
