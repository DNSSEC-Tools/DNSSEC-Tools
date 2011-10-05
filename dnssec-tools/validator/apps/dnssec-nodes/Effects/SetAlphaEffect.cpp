#include "SetAlphaEffect.h"

SetAlphaEffect::SetAlphaEffect(unsigned int alpha)
{
    m_alpha = alpha;
}

void SetAlphaEffect::applyToNode(Node *node)
{
    node->setAlpha(m_alpha);
}

void SetAlphaEffect::resetNode(Node *node)
{
    node->setAlpha(255);
}
