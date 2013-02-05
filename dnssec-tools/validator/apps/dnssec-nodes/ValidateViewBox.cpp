#include "ValidateViewBox.h"

#include <QPen>
#include <QBrush>
#include <qdebug.h>

ValidateViewBox::ValidateViewBox(qreal x, qreal y, qreal width, qreal height, QGraphicsItem *parent) :
    QGraphicsRectItem(x,y,width,height,parent)
{
    setPen(QPen(Qt::black));
    QBrush thebrush = brush();
    thebrush.setColor(QColor(Qt::gray).lighter());
    thebrush.setStyle(Qt::SolidPattern);
    setBrush(thebrush);
}

void ValidateViewBox::mousePressEvent(QGraphicsSceneMouseEvent *event)
{
    setPen(QPen(Qt::blue));
    QBrush thebrush = brush();
    thebrush.setColor(QColor(Qt::blue).lighter());
    setBrush(thebrush);
    update();
    //QGraphicsItem::mousePressEvent(event);
}

void ValidateViewBox::mouseReleaseEvent(QGraphicsSceneMouseEvent *event)
{
    setPen(QPen(Qt::black));
    QBrush thebrush = brush();
    thebrush.setColor(QColor(Qt::gray).lighter());
    setBrush(thebrush);
    update();
    QGraphicsItem::mouseReleaseEvent(event);
}
