#include "FilterEditorWindow.h"

#include <QtGui/QLabel>
#include <QtGui/QDialogButtonBox>
#include <QtGui/QGroupBox>

FilterEditorWindow::FilterEditorWindow(NodeList *nodeList, QWidget *parent) :
    QDialog(parent), m_nodeList(nodeList)
{
    m_mainLayout = new QVBoxLayout();
    m_pairLayouts = new QVBoxLayout();
    m_mainWidget = new QWidget();
    m_mainWidget->setLayout(m_mainLayout);

    m_mainLayout->addLayout(m_pairLayouts);
    setupEditPanel();

    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, Qt::Horizontal, this);
    m_mainLayout->addWidget(buttonBox);
    connect(buttonBox, SIGNAL(rejected()), this, SLOT(deleteLater()));

    setLayout(m_mainLayout);
}

void FilterEditorWindow::setupEditPanel() {
    QList< QPair<Filter *,Effect *> *> filterList = m_nodeList->filtersAndEffects();

    foreach(FilterEffectPair *pairing, filterList) {
        QGroupBox *groupBox = new QGroupBox("Filter and Effect Pair");
        m_pairLayouts->addWidget(groupBox);

        QVBoxLayout *pairBox = new QVBoxLayout();
        groupBox->setLayout(pairBox);

        QGroupBox *filterBox = new QGroupBox(pairing->first->name());
        pairBox->addWidget(filterBox);

        QHBoxLayout *hbox = new QHBoxLayout();
        pairing->first->configWidgets(hbox);
        filterBox->setLayout(hbox);

        QGroupBox *effectBox = new QGroupBox(pairing->second->name());
        pairBox->addWidget(effectBox);
    }
}
