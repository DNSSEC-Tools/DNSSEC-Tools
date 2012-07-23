#ifndef VALIDATEVIEWWIDGET_H
#define VALIDATEVIEWWIDGET_H

#include <QGraphicsView>
#include <QtCore/QMap>

class ValidateViewWidget : public QGraphicsView
{
    Q_OBJECT
public:
    explicit ValidateViewWidget(QString nodeName, QString recordType, QWidget *parent = 0);

    void validateSomething(QString name, QString type);

signals:
    
public slots:

private:
    void scaleView(qreal scaleFactor);
    void drawArrow(int fromX, int fromY, int toX, int toY);

    QGraphicsScene *myScene;
    QString         m_nodeName;
    QString         m_recordType;

    QMap<int, QString> m_typeToName;
};

#endif // VALIDATEVIEWWIDGET_H
