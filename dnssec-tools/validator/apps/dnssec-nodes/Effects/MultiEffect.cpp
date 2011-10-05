#include "MultiEffect.h"

MultiEffect::MultiEffect()
{
}

MultiEffect::~MultiEffect()
{
    foreach (Effect *effect, m_effects) {
        delete effect;
    }
    m_effects.clear();
}

void MultiEffect::resetNode(Node *node)
{
    foreach (Effect *effect, m_effects) {
        effect->resetNode(node);
    }
}

void MultiEffect::applyToNode(Node *node)
{
    foreach (Effect *effect, m_effects) {
        effect->applyToNode(node);
    }
}

void MultiEffect::addEffect(Effect *effect)
{
    m_effects.push_back(effect);
}

void MultiEffect::clear()
{
    m_effects.clear();
}

