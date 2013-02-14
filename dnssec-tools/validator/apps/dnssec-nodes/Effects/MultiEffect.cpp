#include "MultiEffect.h"

#include <QGroupBox>
#include <QMenu>
#include <QPushButton>

#include "filtersAndEffects.h"

MultiEffect::MultiEffect(QObject *parent)
    : Effect(parent), m_effects(), m_addButton(0)
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
    connect(effect, SIGNAL(effectChanged()), this, SIGNAL(effectChanged()));
    connect(effect, SIGNAL(effectAdded()), this, SIGNAL(effectAdded()));
    emit effectAdded();
}

void MultiEffect::clear()
{
    foreach(Effect *effect, m_effects) {
        effect->deleteLater();
    }

    m_effects.clear();
    emit effectChanged();
}

void MultiEffect::configWidgets(QHBoxLayout *hbox)
{
    QVBoxLayout *vbox = new QVBoxLayout();
    hbox->addLayout(vbox);
    foreach(Effect *effect, m_effects) {
        QGroupBox *groupBox = new QGroupBox(effect->name());
        groupBox->setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Minimum);
        vbox->addWidget(groupBox);
        QHBoxLayout *subhbox = new QHBoxLayout();
        effect->configWidgets(subhbox);
        groupBox->setLayout(subhbox);
    }

    m_addButton = new QPushButton("Add New Effect...");
    vbox->addWidget(m_addButton);
    connect(m_addButton, SIGNAL(clicked()), this, SLOT(addNewEffect()));
}

void MultiEffect::addNewEffect()
{
    Effect *effect = getNewEffectFromMenu(m_addButton->mapToGlobal(QPoint(0,0)));
    if (!effect)
        return;
    m_effects.push_back(effect);
    connect(effect, SIGNAL(effectChanged()), this, SIGNAL(effectChanged()));
    emit effectAdded();
}

QString MultiEffect::name() {
    QString desc = "Multiple: ";
#ifdef COMBINE_NAMES
    bool first = true;
    foreach(Effect *effect, m_effects) {
        if (!first)
            desc += " and ";
        first = false;
        desc += effect->name();
    }
#endif
    return desc;
}
