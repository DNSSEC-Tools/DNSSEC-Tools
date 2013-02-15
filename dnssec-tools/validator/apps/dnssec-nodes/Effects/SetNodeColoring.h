#ifndef SETBorderColor_H
#define SETBorderColor_H

#include <QColor>
#include <QLabel>

#include "Effect.h"

#include "qtauto_properties.h"

class SetNodeColoring : public Effect
{
    Q_OBJECT
public:
    SetNodeColoring(QColor borderColor = QColor(), QColor nodeColor = QColor(), QObject *parent = 0);

    virtual void    applyToNode(Node *node);
    virtual void    resetNode(Node *node);
    virtual QString name() { return tr("Change the Node's Coloring"); }
    void configWidgets(QHBoxLayout *hbox);
    void updateLabelColor();

public slots:
    void            selectNewBorderColor();
    void            selectNewNodeColor();

private:
    QLabel *m_currentBorderColor, *m_currentNodeColor;
    QTAUTO_GET_SET_SIGNAL(QColor, borderColor);
    QTAUTO_GET_SET_SIGNAL(QColor, nodeColor);

    // QTAUTO_HERE
    /* AGST */ Q_PROPERTY(QColor borderColor READ borderColor WRITE setBorderColor NOTIFY borderColorChanged) public: const QColor &borderColor() const { return m_borderColor; } signals: void borderColorChanged(); void borderColorChanged(QColor); public slots: void setBorderColor(const QColor &newval) { if (newval != m_borderColor) { QTAUTO_DEBUG("setting new value for " << QTAUTO_STRING(borderColor) << " " << m_borderColor << " => " << newval); m_borderColor = newval; emit borderColorChanged(); emit borderColorChanged(newval); } } private: QColor m_borderColor;
    /* AGST */ Q_PROPERTY(QColor nodeColor READ nodeColor WRITE setNodeColor NOTIFY nodeColorChanged) public: const QColor &nodeColor() const { return m_nodeColor; } signals: void nodeColorChanged(); void nodeColorChanged(QColor); public slots: void setNodeColor(const QColor &newval) { if (newval != m_nodeColor) { QTAUTO_DEBUG("setting new value for " << QTAUTO_STRING(nodeColor) << " " << m_nodeColor << " => " << newval); m_nodeColor = newval; emit nodeColorChanged(); emit nodeColorChanged(newval); } } private: QColor m_nodeColor;

public:
};

#endif // SETBorderColor_H
