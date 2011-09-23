#include "NodesPreferences.h"

#include <QtGui/QDialogButtonBox>

NodesPreferences::NodesPreferences(QSettings &settings, QWidget *parent) :
    QDialog(parent), m_settings(settings)
{
    m_vbox = new QVBoxLayout();
    m_layout = new QFormLayout();
    m_vbox->addLayout(m_layout);
    setLayout(m_vbox);

    m_maxNodes = new QSpinBox();
    m_layout->addRow("Max Nodes: ", m_maxNodes);
    m_maxNodes->setMaximum(0xffff);
    m_maxNodes->setMinimum(0);
    m_maxNodes->setValue(m_settings.value("maxNodes", 0).toInt());

    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    m_vbox->addWidget(buttonBox);

    connect(buttonBox, SIGNAL(accepted()), this, SLOT(ok()));
    connect(buttonBox, SIGNAL(rejected()), this, SLOT(close()));
}

void NodesPreferences::ok() {
    m_settings.setValue("maxNodes", m_maxNodes->value());
    accept();
}

int NodesPreferences::maxNodeCount() {
    return m_maxNodes->value();
}
