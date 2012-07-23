#include "SetBorderColor.h"

#include "node.h"
#include <qdebug.h>

SetBorderColor::SetBorderColor(QColor borderColor)
    : m_borderColor(borderColor)
{
}

void SetBorderColor::applyToNode(Node *node)
{
    node->setBorderColor(m_borderColor);
}

void SetBorderColor::resetNode(Node *node)
{
    node->setBorderColor(Qt::black);
}
