#ifndef VALIDATEVIEWWIDGET_H
#define VALIDATEVIEWWIDGET_H

#include <QGraphicsView>
#include <QtCore/QMap>
#include <QtGui/QColor>
#include <QWidget>
#include <QGraphicsLineItem>

#include "NodeList.h"
#include "graphwidget.h"
#include "qtauto_properties.h"
#include "ValidateViewBox.h"

class ValidateViewWidget : public QGraphicsView
{
    Q_OBJECT
public:
    explicit ValidateViewWidget(QString nodeName, QString recordType, GraphWidget *graphWidget, QWidget *parent = 0);

    void validateSomething(QString name, QString type);
    virtual void wheelEvent(QWheelEvent *event);

signals:
    
public slots:
    void validateDefault();
    void zoomIn();
    void zoomOut();

private:
    void scaleView(qreal scaleFactor);
    void drawArrow(int fromX, int fromY, int toX, int toY, QColor color = Qt::black, ValidateViewBox *box = 0, int horizRaiseMultiplier = 4);

    QGraphicsScene *myScene;
    GraphWidget    *m_graphWidget;
    NodeList       *m_nodeList;
    QString         m_nodeName;
    QString         m_recordType;

    QMap<int, QString> m_statusToName;
    QMap<int, QColor>  m_statusColors;
    QMap<int, QString> m_algorithmToName;
    QMap<int, QString> m_digestToName;

    QTAUTO_GET_SET_SIGNAL(bool, useStraightLines);

    // QTAUTO_HERE
    /* AGST */ Q_PROPERTY(bool useStraightLines READ useStraightLines WRITE setUseStraightLines NOTIFY useStraightLinesChanged) public: const bool &useStraightLines() const { return m_useStraightLines; } signals: void useStraightLinesChanged(); void useStraightLinesChanged(bool); public slots: void setUseStraightLines(const bool &newval) { if (newval != m_useStraightLines) { QTAUTO_DEBUG("setting new value for " << QTAUTO_STRING(useStraightLines) << " " << m_useStraightLines << " => " << newval); m_useStraightLines = newval; emit useStraightLinesChanged(); emit useStraightLinesChanged(newval); } } private: bool m_useStraightLines;

};

#endif // VALIDATEVIEWWIDGET_H
