#include "QStatusLight.h"

#include <QPainter>
#include <QPen>
#include <QBrush>
#include <QMessageBox>
#include <qdebug.h>

QStatusLight::QStatusLight(QWidget *parent, CheckFunction *check_function, const char *serverAddress, const QString &checkName, int rowNumber) :
    QPushButton(parent), m_dnssecTest(parent, check_function, serverAddress, checkName), m_rowNumber(rowNumber)
{
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    connect(this, SIGNAL(clicked()), this, SLOT(showError()));
}

void QStatusLight::paintEvent(QPaintEvent *e)
{
    Q_UNUSED(e);
    QPainter painter(this);
    int dropShadowSize = 4;
    int maxSize = qMin(width(), height()) -1 - dropShadowSize;  // -1 to fit and -2 to allow for dropshadow and border space
    painter.save();

    painter.setPen(Qt::darkGray);
    painter.setBrush(Qt::darkGray);
    painter.drawEllipse(dropShadowSize -1, dropShadowSize, maxSize, maxSize);

    painter.setPen(Qt::black);
    painter.setBrush(Qt::black);
    painter.drawEllipse(0,0,maxSize+1,maxSize+1);

    QColor darkColor;
    QRadialGradient gradiant(maxSize/2, maxSize/2, maxSize/2, maxSize/3, maxSize/3);
    gradiant.setColorAt(0, Qt::white);

    switch (m_dnssecTest.status()) {
    case DNSSECTest::UNKNOWN:
    case DNSSECTest::TESTINGNOW:
        painter.setPen(Qt::gray);
        darkColor = Qt::darkGray;
        gradiant.setColorAt(1, Qt::gray);
        break;
    case DNSSECTest::GOOD:
        painter.setPen(Qt::green);
        darkColor = Qt::darkGreen;
        gradiant.setColorAt(1, Qt::green);
        break;
    case DNSSECTest::BAD:
        painter.setPen(Qt::red);
        darkColor = Qt::darkRed;
        gradiant.setColorAt(1, Qt::red);
        break;
    case DNSSECTest::WARNING:
        painter.setPen(Qt::yellow);
        darkColor = Qt::darkYellow;
        gradiant.setColorAt(1, Qt::yellow);
        break;
    }


    QBrush gbrush(gradiant);
    painter.setBrush(gbrush);
    painter.drawEllipse(0,0,maxSize,maxSize);

    painter.setPen(darkColor);
    painter.setBrush(Qt::NoBrush);

    painter.drawEllipse(0,0,maxSize+1,maxSize+1);
    if (m_dnssecTest.name().length() > 0) {
        QFont font = painter.font();
        font.setPointSize(3*font.pointSize()/4);
        painter.setFont(font);
        painter.setPen(Qt::black);
        painter.drawText(QRect(1,maxSize/2, maxSize, maxSize/2), Qt::AlignCenter, m_dnssecTest.name());
    }

    painter.restore();
}

QSize QStatusLight::minimumSizeHint() {
    return QSize(10,10);
}

QSize QStatusLight::sizeHint() {
    return minimumSizeHint();
}

void QStatusLight::showError()
{
    if (m_dnssecTest.message().length() == 0)
        return;

    QMessageBox message;
    message.setText(m_dnssecTest.message());

    if (m_dnssecTest.status() == DNSSECTest::GOOD)
        message.setIcon(QMessageBox::Information);
    else if (m_dnssecTest.status() == DNSSECTest::BAD)
        message.setIcon(QMessageBox::Warning);
    message.exec();
}

void QStatusLight::reset()
{
    m_dnssecTest.setStatus(DNSSECTest::UNKNOWN);
    update();
}

void QStatusLight::check()
{
    m_dnssecTest.check();
    setToolTip(QString(m_dnssecTest.message()));
}

DNSSECTest * QStatusLight::test()
{
    return &m_dnssecTest;
}

int QStatusLight::rowNumber()
{
    return m_rowNumber;
}
