#include "ValidateViewBox.h"

#include <QPen>
#include <QBrush>

ValidateViewBox::ValidateViewBox(qreal x, qreal y, qreal width, qreal height, QGraphicsItem *parent) :
    QGraphicsRectItem(x,y,width,height,parent)
{
    setPen(QPen(Qt::black));
    QBrush thebrush = brush();
    thebrush.setColor(QColor(Qt::gray).lighter());
    thebrush.setStyle(Qt::SolidPattern);
    setBrush(thebrush);
}
