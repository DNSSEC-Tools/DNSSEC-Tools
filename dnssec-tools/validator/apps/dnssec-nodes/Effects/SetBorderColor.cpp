#include "SetBorderColor.h"

#include "node.h"
#include <qdebug.h>

SetBorderColor::SetBorderColor(QColor borderColor)
    : m_borderColor(borderColor)
{
}

void SetBorderColor::applyToNode(Node *node)
{
    qDebug() << "setting color to " << m_borderColor;
    node->setBorderColor(m_borderColor);
}

void SetBorderColor::resetNode(Node *node)
{
    node->setBorderColor(Qt::black);
}
