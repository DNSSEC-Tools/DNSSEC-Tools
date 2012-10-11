#include "ValidateViewWidgetHolder.h"

#include <QVBoxLayout>

ValidateViewWidgetHolder::ValidateViewWidgetHolder(const QString &nodeName, const QString &recordType, GraphWidget *graphWidget, QWidget *parent) :
    QWidget(parent), m_view(new ValidateViewWidget(nodeName, recordType, graphWidget, parent))
{
    QVBoxLayout *layout = new QVBoxLayout();
    setLayout(layout);
    layout->addWidget(m_view);

    QHBoxLayout *buttonHBox = new QHBoxLayout();

    buttonHBox->addWidget(new QLabel("Zoom Layout: "));
    QPushButton *button;
    buttonHBox->addWidget(button = new QPushButton("+"));
    button->connect(button, SIGNAL(clicked()), m_view, SLOT(zoomIn()));

    buttonHBox->addWidget(button = new QPushButton("-"));
    button->connect(button, SIGNAL(clicked()), m_view, SLOT(zoomOut()));

    layout->addLayout(buttonHBox);
}
