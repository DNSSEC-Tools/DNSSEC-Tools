#include "SetBorderColor.h"

#include "node.h"
#include <qdebug.h>

#include <QLabel>
#include <QColorDialog>
#include <QPushButton>

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
    QPushButton *button = new QPushButton("Select Color");
    connect(button, SIGNAL(clicked()), this, SLOT(selectNewColor()));
    hbox->addWidget(button);

    m_currentColor = new QLabel();
    updateLabelColor();
    hbox->addWidget(m_currentColor);
}

void SetBorderColor::updateLabelColor() {
    m_currentColor->setText(tr("Current Color: %1").arg(m_borderColor.name()));
}

void SetBorderColor::selectNewColor()
{
    QColorDialog cDialog;
    QColor color = cDialog.getColor();
    if (color.isValid())
        setBorderColor(color);
    updateLabelColor();
    emit effectChanged();
}
