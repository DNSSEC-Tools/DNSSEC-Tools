#ifndef SETALPHAEFFECT_H
#define SETALPHAEFFECT_H

#include "Effect.h"

#include "qtauto_properties.h"

class SetAlphaEffect : public Effect
{
    Q_OBJECT
public:
    SetAlphaEffect(int alpha, QObject *parent = 0);


    virtual void    applyToNode(Node *node);
    virtual void    resetNode(Node *node);
    virtual QString name() { return "Set Alpha Value"; }
    virtual void    configWidgets(QHBoxLayout *hbox);

private:
    QTAUTO_GET_SET_SIGNAL(int, alpha);

    // QTAUTO_HERE
    /* AGST */ Q_PROPERTY(int alpha READ alpha WRITE setAlpha NOTIFY alphaChanged) public: const int &alpha() const { return m_alpha; } signals: void alphaChanged(); void alphaChanged(int); public slots: void setAlpha(const int &newval) { if (newval != m_alpha) { QTAUTO_DEBUG("setting new value for " << QTAUTO_STRING(alpha) << " " << m_alpha << " => " << newval); m_alpha = newval; emit alphaChanged(); emit alphaChanged(newval); } } private: int m_alpha;
public:
};

#endif // SETALPHAEFFECT_H
