#include "ValidateViewBox.h"

#include <QPen>
#include <QBrush>
#include <qdebug.h>

ValidateViewBox::ValidateViewBox(qreal x, qreal y, qreal width, qreal height, GraphWidget *graph, QGraphicsItem *parent) :
    QGraphicsRectItem(x,y,width,height,parent), m_isSelected(false), m_graph(graph), m_lines(), m_paths()
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
    if (m_graph->useToggledValidationBoxes() && m_isSelected)
        m_isSelected = false;
    else
        m_isSelected = true;
    updateColorsFromSelection();
    //QGraphicsItem::mousePressEvent(event);
}

void ValidateViewBox::mouseReleaseEvent(QGraphicsSceneMouseEvent *event)
{
    Q_UNUSED(event)
    if (!m_graph->useToggledValidationBoxes())
        m_isSelected = false;
    updateColorsFromSelection();
    //QGraphicsItem::mouseReleaseEvent(event);
}

void ValidateViewBox::updateColorsFromSelection() {
    QPen pen(m_isSelected ? Qt::blue : Qt::black);
    QPen linePen(m_isSelected ? Qt::blue : Qt::green);
    setPen(pen);
    QBrush thebrush = brush();
    thebrush.setColor(QColor(m_isSelected ? Qt::blue : Qt::gray).lighter());
    setBrush(thebrush);
    m_isSelected = true;
    foreach(LineItemPair *item, m_lines) {
        linePen.setWidth(m_isSelected ? 6 : 1);
        item->first->setPen(linePen);
        item->first->setZValue(m_isSelected ? 5 : 0);
        item->first->update();
    }
    foreach(PathItemPair *item, m_paths) {
        linePen.setWidth(m_isSelected ? 6 : 1);
        item->first->setPen(linePen);
        item->first->setZValue(m_isSelected ? 5 : 0);
        item->first->update();
    }
    update();
}
