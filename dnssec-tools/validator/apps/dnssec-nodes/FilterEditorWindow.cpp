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

    m_scrolled = new QScrollArea();
    m_scrolled->setBackgroundRole(QPalette::Window);
    m_scrolled->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_scrolled->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Expanding);

    QWidget *theWidget = new QWidget();
    theWidget->setLayout(m_pairLayouts);
    m_scrolled->setWidget(theWidget);
    m_scrolled->setWidgetResizable(true);
    m_mainLayout->addWidget(m_scrolled);
    setupEditPanel();

    QHBoxLayout *buttonBoxes = new QHBoxLayout();
    m_mainLayout->addLayout(buttonBoxes);

    m_addPairButton = new QPushButton("Add New Filter/Effect Pair");
    buttonBoxes->addWidget(m_addPairButton);
    connect(m_addPairButton, SIGNAL(clicked()), this, SLOT(addNewFilterEffectPair()));

    QPushButton *erase = new QPushButton("Erase All Filter/Effect Pairs");
    buttonBoxes->addWidget(erase);
    connect(erase, SIGNAL(clicked()), this, SLOT(eraseAllFilterEffectPairs()));

    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Close, Qt::Horizontal, this);
    m_mainLayout->addWidget(buttonBox);
    connect(buttonBox, SIGNAL(rejected()), this, SLOT(deleteLater()));

    resize(600,600);

    setLayout(m_mainLayout);
}

void FilterEditorWindow::setupEditPanel() {
    QList< QPair<Filter *,Effect *> *> filterList = m_nodeList->filtersAndEffects();

    foreach(FilterEffectPair *pairing, filterList) {
        QGroupBox *groupBox = new QGroupBox("Filter and Effect Pair");
        groupBox->setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Minimum);
        m_pairLayouts->addWidget(groupBox);

        QVBoxLayout *pairBox = new QVBoxLayout();
        groupBox->setLayout(pairBox);

        QGroupBox *filterBox = new QGroupBox("Filter: " + pairing->first->name());
        filterBox->setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Minimum);
        pairBox->addWidget(filterBox);

        QHBoxLayout *hbox = new QHBoxLayout();
        pairing->first->configWidgets(hbox);
        filterBox->setLayout(hbox);

        QGroupBox *effectBox = new QGroupBox("Effect: " + pairing->second->name());
        effectBox->setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Minimum);
        pairBox->addWidget(effectBox);

        hbox = new QHBoxLayout();
        pairing->second->configWidgets(hbox);
        effectBox->setLayout(hbox);

        connect(pairing->first, SIGNAL(filterAdded()), this, SLOT(resetupEditPanel()));
        connect(pairing->second, SIGNAL(effectAdded()), this, SLOT(resetupEditPanel()));
    }
}

void FilterEditorWindow::clearEditPanel()
{
    NodeList::clearLayout(m_pairLayouts);
}

void FilterEditorWindow::resetupEditPanel()
{
    clearEditPanel();
    setupEditPanel();
}

void FilterEditorWindow::addNewFilterEffectPair()
{
    Filter *filter = Filter::getNewFilterFromMenu(m_addPairButton->mapToGlobal(QPoint(0,0)));
    if (filter) {
        m_nodeList->addFilterAndEffect(filter, new MultiEffect());
        resetupEditPanel();
    }
}

void FilterEditorWindow::eraseAllFilterEffectPairs()
{
    m_nodeList->clearAllFiltersAndEffects();
    resetupEditPanel();
}

