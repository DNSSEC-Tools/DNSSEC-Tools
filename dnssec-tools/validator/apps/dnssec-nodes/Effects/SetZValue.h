#ifndef SETZVALUE_H
#define SETZVALUE_H

#include "Effect.h"

#include "qtauto_properties.h"

class SetZValue : public Effect
{
    Q_OBJECT
public:
    SetZValue(int zvalue, QObject *parent = 0);

    virtual void    applyToNode(Node *node);
    virtual void    resetNode(Node *node);
    virtual QString name() { return "Raise or Lower the Node"; }
    virtual void    configWidgets(QHBoxLayout *hbox);

private:
    QTAUTO_GET_SET_SIGNAL(int, zvalue);

    // QTAUTO_HERE
    /* AGST */ Q_PROPERTY(int zvalue READ zvalue WRITE setZvalue NOTIFY zvalueChanged) public: const int &zvalue() const { return m_zvalue; } signals: void zvalueChanged(); void zvalueChanged(int); public slots: void setZvalue(const int &newval) { if (newval != m_zvalue) { QTAUTO_DEBUG("setting new value for " << QTAUTO_STRING(zvalue) << " " << m_zvalue << " => " << newval); m_zvalue = newval; emit zvalueChanged(); emit zvalueChanged(newval); } } private: int m_zvalue;

public:
};

#endif // SETZVALUE_H
