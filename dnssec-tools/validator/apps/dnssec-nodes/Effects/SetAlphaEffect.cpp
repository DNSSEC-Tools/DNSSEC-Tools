#include "SetAlphaEffect.h"

#include <QSpinBox>

SetAlphaEffect::SetAlphaEffect(int alpha, QObject *parent)
    : Effect(parent), m_alpha(alpha)
{
    connect(this, SIGNAL(alphaChanged()), this, SIGNAL(effectChanged()));
}

void SetAlphaEffect::applyToNode(Node *node)
{
    node->setAlpha(m_alpha);
}

void SetAlphaEffect::resetNode(Node *node)
{
    node->setAlpha(255);
}

void SetAlphaEffect::configWidgets(QHBoxLayout *hbox)
{
    QSpinBox *spinner = new QSpinBox();
    spinner->setRange(0,255);
    spinner->setValue(m_alpha);
    connect(spinner, SIGNAL(valueChanged(int)), this, SLOT(setAlpha(int)));
    hbox->addWidget(spinner);
}

