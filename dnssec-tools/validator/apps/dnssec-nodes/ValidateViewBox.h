#ifndef VALIDATEVIEWBOX_H
#define VALIDATEVIEWBOX_H

#include <QGraphicsRectItem>
#include <QList>

class ValidateViewBox : public QGraphicsRectItem
{
public:
    ValidateViewBox ( qreal x, qreal y, qreal width, qreal height, QGraphicsItem * parent = 0 );
    void mousePressEvent(QGraphicsSceneMouseEvent *event);
    void mouseReleaseEvent(QGraphicsSceneMouseEvent *event);

    bool isSelected() const { return m_isSelected; }
    void addLineObject(QGraphicsLineItem *item) { m_lines.append(item); }
    void addPathObject(QGraphicsPathItem *item) { m_paths.append(item); }

private:
    bool m_isSelected;
    QList<QGraphicsLineItem *> m_lines;
    QList<QGraphicsPathItem *> m_paths;

};

#endif // VALIDATEVIEWBOX_H
