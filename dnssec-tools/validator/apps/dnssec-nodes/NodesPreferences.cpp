#include "NodesPreferences.h"

#include <QtGui/QDialogButtonBox>

NodesPreferences::NodesPreferences(QSettings *settings, QWidget *parent) :
    QDialog(parent), m_settings(settings)
{
    m_vbox = new QVBoxLayout();
    m_layout = new QFormLayout();
    m_vbox->addLayout(m_layout);
    setLayout(m_vbox);

    m_enableMaxNodes = new QCheckBox("Limit Number");
    m_enableMaxNodes->setChecked(settings->value("enableMaxNodes", false).toBool());
    m_layout->addRow("Limit the maximum number of nodes:", m_enableMaxNodes);

    m_maxNodes = new QSpinBox();
    m_layout->addRow("Max Nodes: ", m_maxNodes);
    m_maxNodes->setMaximum(0xffff);
    m_maxNodes->setMinimum(1);
    m_maxNodes->setValue(m_settings->value("maxNodes", 200).toInt());

    enableMaxNodesChanged(m_enableMaxNodes->checkState());

    m_enableTimeNodes = new QCheckBox("Limit Time");
    m_enableTimeNodes->setChecked(settings->value("enableTimeNodes", false).toBool());
    m_layout->addRow("Limit the maximum time of nodes:", m_enableTimeNodes);

    m_maxTime = new QSpinBox();
    m_layout->addRow("Max Time: ", m_maxTime);
    m_maxTime->setMaximum(0xffff);
    m_maxTime->setMinimum(1);
    m_maxTime->setValue(m_settings->value("maxTime", 300).toInt());

    enableTimeNodesChanged(m_enableTimeNodes->checkState());

    QDialogButtonBox *buttonBox = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    m_vbox->addWidget(buttonBox);

    connect(buttonBox, SIGNAL(accepted()), this, SLOT(ok()));
    connect(buttonBox, SIGNAL(rejected()), this, SLOT(close()));

    connect(m_enableMaxNodes, SIGNAL(stateChanged(int)), this, SLOT(enableMaxNodesChanged(int)));
    connect(m_enableTimeNodes, SIGNAL(stateChanged(int)), this, SLOT(enableTimeNodesChanged(int)));
}

void NodesPreferences::ok() {
    m_settings->setValue("maxNodes", m_maxNodes->value());
    m_settings->setValue("maxTime",  m_maxTime->value());
    m_settings->setValue("enableMaxNodes", m_enableMaxNodes->isChecked());
    m_settings->setValue("enableTimeNodes", m_enableTimeNodes->isChecked());
    accept();
}

int NodesPreferences::maxNodeCount() {
    return m_maxNodes->value();
}

int NodesPreferences::maxTime() {
    return m_maxTime->value();
}

bool NodesPreferences::enableMaxNodes() {
    return m_enableMaxNodes->isChecked();
}

bool NodesPreferences::enableTimeNodes() {
    return m_enableTimeNodes->isChecked();
}

void NodesPreferences::enableMaxNodesChanged(int value)
{
    m_maxNodes->setEnabled(value == Qt::Checked ? true : false);
    m_layout->labelForField(m_maxNodes)->setEnabled(value == Qt::Checked ? true : false);
}

void NodesPreferences::enableTimeNodesChanged(int value)
{
    m_maxTime->setEnabled(value == Qt::Checked ? true : false);
    m_layout->labelForField(m_maxTime)->setEnabled(value == Qt::Checked ? true : false);
}
