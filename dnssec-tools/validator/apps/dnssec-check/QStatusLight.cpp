#include "QStatusLight.h"

#include <QPainter>
#include <QPen>
#include <QBrush>
#include <QMessageBox>
#include <qdebug.h>

QStatusLight::QStatusLight(QWidget *parent, CheckFunction *check_function, const char *serverAddress, const QString &checkName) :
    QPushButton(parent), m_status(UNKNOWN), m_checkFunction(check_function), m_serverAddress(0), m_checkName(checkName)
{
    if (serverAddress)
        m_serverAddress = strdup(serverAddress);
    m_msgBuffer[0] = 0;
    m_msgBuffer[sizeof(m_msgBuffer)-1] = 0;
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

    switch (m_status) {
    case UNKNOWN:
        painter.setPen(Qt::gray);
        darkColor = Qt::darkGray;
        gradiant.setColorAt(1, Qt::gray);
        break;
    case GOOD:
        painter.setPen(Qt::green);
        darkColor = Qt::darkGreen;
        gradiant.setColorAt(1, Qt::green);
        break;
    case BAD:
        painter.setPen(Qt::red);
        darkColor = Qt::darkRed;
        gradiant.setColorAt(1, Qt::red);
        break;
    case WARNING:
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
    if (m_checkName.length() > 0) {
        QFont font = painter.font();
        font.setPointSize(3*font.pointSize()/4);
        painter.setFont(font);
        painter.setPen(Qt::black);
        painter.drawText(QRect(1,maxSize/2, maxSize, maxSize/2), Qt::AlignCenter, m_checkName);
    }

    painter.restore();
}

QSize QStatusLight::minimumSizeHint() {
    return QSize(10,10);
}

QSize QStatusLight::sizeHint() {
    return minimumSizeHint();
}

QStatusLight::lightStatus QStatusLight::status()
{
    return m_status;
}

void QStatusLight::setStatus(QStatusLight::lightStatus newStatus)
{
    m_status = newStatus;
    update();
}

void QStatusLight::check()
{
    if (!m_checkFunction || !m_serverAddress)
        return;
    int rc = (*m_checkFunction)(m_serverAddress, m_msgBuffer, sizeof(m_msgBuffer));
    if (rc == 0)
        setStatus(GOOD);
    if (rc == 1)
        setStatus(BAD);
    if (rc == 2)
        setStatus(WARNING);
    setToolTip(QString(m_msgBuffer));
}

void QStatusLight::showError()
{
    if (m_msgBuffer[0] == 0)
        return;
    QMessageBox message;
    message.setText(m_msgBuffer);
    if (m_status == GOOD)
        message.setIcon(QMessageBox::Information);
    else if (m_status == BAD)
        message.setIcon(QMessageBox::Warning);
    message.exec();
}

void QStatusLight::setMessage(const QString &message)
{
    strncpy(m_msgBuffer, message.toAscii().data(), sizeof(m_msgBuffer)-1);
}

const QString QStatusLight::message() const
{
    return QString(m_msgBuffer);
}

const QString QStatusLight::serverAddress() const
{
    return QString(m_serverAddress);
}
