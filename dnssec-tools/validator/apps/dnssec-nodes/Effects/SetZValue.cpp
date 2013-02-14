#include "SetZValue.h"

#include "node.h"
#include <qdebug.h>
#include <QSpinBox>
#include <QHBoxLayout>

SetZValue::SetZValue(int zvalue, QObject *parent)
    : Effect(parent), m_zvalue(zvalue)
{
    connect(this, SIGNAL(zvalueChanged()), this, SIGNAL(effectChanged()));
}

void SetZValue::applyToNode(Node *node)
{
    node->setZValue(m_zvalue);
}

void SetZValue::resetNode(Node *node)
{
    node->setZValue(-1);
}

void SetZValue::configWidgets(QHBoxLayout *hbox)
{
    QSpinBox *spinner = new QSpinBox();
    spinner->setRange(-10,100);
    spinner->setValue(m_zvalue);
    connect(spinner, SIGNAL(valueChanged(int)), this, SLOT(setZvalue(int)));
    hbox->addWidget(spinner);
}

