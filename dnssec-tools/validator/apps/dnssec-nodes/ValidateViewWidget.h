#ifndef VALIDATEVIEWWIDGET_H
#define VALIDATEVIEWWIDGET_H

#include <QGraphicsView>
#include <QtCore/QMap>
#include <QtGui/QColor>

class ValidateViewWidget : public QGraphicsView
{
    Q_OBJECT
public:
    explicit ValidateViewWidget(QString nodeName, QString recordType, QWidget *parent = 0);

    void validateSomething(QString name, QString type);

signals:
    
public slots:
    void validateDefault();

private:
    void scaleView(qreal scaleFactor);
    void drawArrow(int fromX, int fromY, int toX, int toY, QColor color = Qt::black, int horizRaiseMultiplier = 4);

    QGraphicsScene *myScene;
    QString         m_nodeName;
    QString         m_recordType;

    QMap<int, QString> m_typeToName;
    QMap<QString, int> m_nameToType;
    QMap<int, QString> m_statusToName;
    QMap<int, QColor>  m_statusColors;
    QMap<int, QString> m_algorithmToName;
    QMap<int, QString> m_digestToName;
};

#endif // VALIDATEVIEWWIDGET_H
