#include "SetBorderColor.h"

#include "node.h"
#include <qdebug.h>

#include <QLabel>
#include <QColorDialog>
#include <QPushButton>

SetBorderColor::SetBorderColor(QColor borderColor, QColor nodeColor, QObject *parent)
    : Effect(parent), m_borderColor(borderColor), m_nodeColor(nodeColor)
{
    connect(this, SIGNAL(borderColorChanged()), this, SIGNAL(effectChanged()));
}

void SetBorderColor::applyToNode(Node *node)
{
    node->setBorderColor(m_borderColor);
    node->setNodeColor(m_nodeColor);
}

void SetBorderColor::resetNode(Node *node)
{
    node->setBorderColor(Qt::black);
    node->setNodeColor(QColor());
}

void SetBorderColor::configWidgets(QHBoxLayout *hbox)
{
    QVBoxLayout *vbox = new QVBoxLayout();
    hbox->addLayout(vbox)
            ;
    QHBoxLayout *rowBox = new QHBoxLayout();
    vbox->addLayout(rowBox);

    QPushButton *button = new QPushButton("Select Node Color");
    connect(button, SIGNAL(clicked()), this, SLOT(selectNewNodeColor()));
    rowBox->addWidget(button);

    m_currentNodeColor = new QLabel();
    rowBox->addWidget(m_currentNodeColor);

    rowBox = new QHBoxLayout();
    vbox->addLayout(rowBox);

    button = new QPushButton("Select Border Color");
    connect(button, SIGNAL(clicked()), this, SLOT(selectNewBorderColor()));
    rowBox->addWidget(button);

    m_currentBorderColor = new QLabel();
    rowBox->addWidget(m_currentBorderColor);

    updateLabelColor();
}

void SetBorderColor::updateLabelColor() {
    m_currentNodeColor->setText(tr("Current Node Color: %1").arg(m_nodeColor.name()));
    m_currentBorderColor->setText(tr("Current Border Color: %1").arg(m_borderColor.name()));
}

void SetBorderColor::selectNewBorderColor()
{
    QColorDialog cDialog;
    QColor color = cDialog.getColor();
    if (color.isValid())
        setBorderColor(color);
    updateLabelColor();
    emit effectChanged();
}

void SetBorderColor::selectNewNodeColor()
{
    QColorDialog cDialog;
    QColor color = cDialog.getColor();
    if (color.isValid())
        setNodeColor(color);
    updateLabelColor();
    emit effectChanged();
}
