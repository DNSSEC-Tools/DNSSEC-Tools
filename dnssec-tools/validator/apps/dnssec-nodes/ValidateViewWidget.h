#ifndef VALIDATEVIEWWIDGET_H
#define VALIDATEVIEWWIDGET_H

#include <QGraphicsView>

class ValidateViewWidget : public QGraphicsView
{
    Q_OBJECT
public:
    explicit ValidateViewWidget(QString nodeName, QString recordType, QWidget *parent = 0);
    
signals:
    
public slots:

private:
    void scaleView(qreal scaleFactor);

    QGraphicsScene *myScene;
    QString         m_nodeName;
    QString         m_recordType;
};

#endif // VALIDATEVIEWWIDGET_H
