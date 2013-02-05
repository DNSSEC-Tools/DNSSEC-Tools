#include "ValidateViewBox.h"

#include <QPen>
#include <QBrush>
#include <qdebug.h>

ValidateViewBox::ValidateViewBox(qreal x, qreal y, qreal width, qreal height, QGraphicsItem *parent) :
    QGraphicsRectItem(x,y,width,height,parent), m_isSelected(false), m_lines(), m_paths()
{
    setPen(QPen(Qt::black));
    QBrush thebrush = brush();
    thebrush.setColor(QColor(Qt::gray).lighter());
    thebrush.setStyle(Qt::SolidPattern);
    setBrush(thebrush);
}

void ValidateViewBox::mousePressEvent(QGraphicsSceneMouseEvent *event)
{
    Q_UNUSED(event)
    setPen(QPen(Qt::blue));
    QBrush thebrush = brush();
    thebrush.setColor(QColor(Qt::blue).lighter());
    setBrush(thebrush);
    m_isSelected = true;
    foreach(QGraphicsLineItem *item, m_lines) {
        item->setPen(QPen(Qt::blue));
        item->update();
    }
    foreach(QGraphicsPathItem *item, m_paths) {
        item->setPen(QPen(Qt::blue));
        item->update();
    }
    update();

    //QGraphicsItem::mousePressEvent(event);
}

void ValidateViewBox::mouseReleaseEvent(QGraphicsSceneMouseEvent *event)
{
    setPen(QPen(Qt::black));
    QBrush thebrush = brush();
    thebrush.setColor(QColor(Qt::gray).lighter());
    setBrush(thebrush);
    m_isSelected = false;
    foreach(QGraphicsLineItem *item, m_lines) {
        item->setPen(QPen(Qt::green));
        item->update();
    }
    foreach(QGraphicsPathItem *item, m_paths) {
        item->setPen(QPen(Qt::green));
        item->update();
    }
    update();
    QGraphicsItem::mouseReleaseEvent(event);
}
