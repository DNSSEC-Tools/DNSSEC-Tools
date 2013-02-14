#ifndef SETBorderColor_H
#define SETBorderColor_H

#include <QColor>
#include <QLabel>

#include "Effect.h"

#include "qtauto_properties.h"

class SetBorderColor : public Effect
{
    Q_OBJECT
public:
    SetBorderColor(QColor borderColor = Qt::red, QObject *parent = 0);

    virtual void    applyToNode(Node *node);
    virtual void    resetNode(Node *node);
    virtual QString name() { return "Change the Border Color"; }
    void configWidgets(QHBoxLayout *hbox);
    void updateLabelColor();

public slots:
    void            selectNewColor();

private:
    QLabel *m_currentColor;
    QTAUTO_GET_SET_SIGNAL(QColor, borderColor);

    // QTAUTO_HERE
    /* AGST */ Q_PROPERTY(QColor borderColor READ borderColor WRITE setBorderColor NOTIFY borderColorChanged) public: const QColor &borderColor() const { return m_borderColor; } signals: void borderColorChanged(); void borderColorChanged(QColor); public slots: void setBorderColor(const QColor &newval) { if (newval != m_borderColor) { QTAUTO_DEBUG("setting new value for " << QTAUTO_STRING(borderColor) << " " << m_borderColor << " => " << newval); m_borderColor = newval; emit borderColorChanged(); emit borderColorChanged(newval); } } private: QColor m_borderColor;

public:
};

#endif // SETBorderColor_H
