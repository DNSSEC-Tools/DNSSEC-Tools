#include "SetSize.h"

#include "node.h"
#include <qdebug.h>
#include <QSpinBox>
#include <QHBoxLayout>

SetSize::SetSize(int size, QObject *parent)
    : Effect(parent), m_size(size)
{
    connect(this, SIGNAL(sizeChanged()), this, SIGNAL(effectChanged()));
}

void SetSize::applyToNode(Node *node)
{
    node->setNodeSize(m_size);
}

void SetSize::resetNode(Node *node)
{
    node->setNodeSize(20);
}

void SetSize::configWidgets(QHBoxLayout *hbox)
{
    QSpinBox *spinner = new QSpinBox();
    spinner->setRange(1,100);
    spinner->setValue(m_size);
    connect(spinner, SIGNAL(valueChanged(int)), this, SLOT(setSize(int)));
    hbox->addWidget(spinner);
}
