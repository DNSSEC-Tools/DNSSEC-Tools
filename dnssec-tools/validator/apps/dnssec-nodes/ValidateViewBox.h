#ifndef VALIDATEVIEWBOX_H
#define VALIDATEVIEWBOX_H

#include <QGraphicsRectItem>

class ValidateViewBox : public QGraphicsRectItem
{
public:
    ValidateViewBox ( qreal x, qreal y, qreal width, qreal height, QGraphicsItem * parent = 0 );
    void mousePressEvent(QGraphicsSceneMouseEvent *event);
    void mouseReleaseEvent(QGraphicsSceneMouseEvent *event);
};

#endif // VALIDATEVIEWBOX_H
