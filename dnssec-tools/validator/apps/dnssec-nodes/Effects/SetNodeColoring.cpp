#include "SetNodeColoring.h"

#include "node.h"
#include <qdebug.h>

#include <QLabel>
#include <QColorDialog>
#include <QPushButton>

SetNodeColoring::SetNodeColoring(QColor borderColor, QColor nodeColor, QObject *parent)
    : Effect(parent), m_borderColor(borderColor), m_nodeColor(nodeColor)
{
    connect(this, SIGNAL(borderColorChanged()), this, SIGNAL(effectChanged()));
}

void SetNodeColoring::applyToNode(Node *node)
{
    node->setBorderColor(m_borderColor);
    node->setNodeColor(m_nodeColor);
}

void SetNodeColoring::resetNode(Node *node)
{
    node->setBorderColor(Qt::black);
    node->setNodeColor(QColor());
}

void SetNodeColoring::configWidgets(QHBoxLayout *hbox)
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

void SetNodeColoring::updateLabelColor() {
    m_currentNodeColor->setText(tr("Current Node Color: %1").arg(m_nodeColor.name()));
    m_currentBorderColor->setText(tr("Current Border Color: %1").arg(m_borderColor.name()));
}

void SetNodeColoring::selectNewBorderColor()
{
    QColorDialog cDialog;
    QColor color = cDialog.getColor();
    if (color.isValid())
        setBorderColor(color);
    updateLabelColor();
    emit effectChanged();
}

void SetNodeColoring::selectNewNodeColor()
{
    QColorDialog cDialog;
    QColor color = cDialog.getColor();
    if (color.isValid())
        setNodeColor(color);
    updateLabelColor();
    emit effectChanged();
}
