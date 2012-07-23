#include "ValidateViewWidget.h"

#include <QtGui/QGraphicsRectItem>

ValidateViewWidget::ValidateViewWidget(QString nodeName, QString recordType, QWidget *parent) :
    QGraphicsView(parent), m_nodeName(nodeName), m_recordType(recordType)
{
    myScene = new QGraphicsScene(this);
    myScene->setItemIndexMethod(QGraphicsScene::NoIndex);
    myScene->setSceneRect(0, 0, 600, 600);
    setScene(myScene);
    setCacheMode(CacheBackground);
    setViewportUpdateMode(BoundingRectViewportUpdate);
    setRenderHint(QPainter::Antialiasing);
    setTransformationAnchor(AnchorUnderMouse);
    setDragMode(QGraphicsView::ScrollHandDrag);
    setWindowTitle(tr("Validation of %1 for %2").arg(nodeName).arg(recordType));
    //scaleWindow();

    QGraphicsRectItem *rect;
    myScene->addItem(rect = new QGraphicsRectItem(10,10,100,100));
    rect->setPen(QPen(Qt::black));

    scaleView(.5);
    ensureVisible(rect);
}

void ValidateViewWidget::scaleView(qreal scaleFactor)
{
    qreal factor = transform().scale(scaleFactor, scaleFactor).mapRect(QRectF(0, 0, 1, 1)).width();
    if (factor < 0.07 || factor > 100)
        return;

    scale(scaleFactor, scaleFactor);
}
