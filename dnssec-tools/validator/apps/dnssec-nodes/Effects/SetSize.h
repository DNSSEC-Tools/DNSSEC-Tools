#ifndef SETSIZE_H
#define SETSIZE_H

#include "Effect.h"

#include "qtauto_properties.h"

class SetSize : public Effect
{
    Q_OBJECT
public:
    SetSize(int size, QObject *parent = 0);

    virtual void    applyToNode(Node *node);
    virtual void    resetNode(Node *node);
    virtual QString name() { return "Raise or Lower the Node"; }
    virtual void    configWidgets(QHBoxLayout *hbox);

private:
    QTAUTO_GET_SET_SIGNAL(int, size);

    // QTAUTO_HERE
    /* AGST */ Q_PROPERTY(int size READ size WRITE setSize NOTIFY sizeChanged) public: const int &size() const { return m_size; } signals: void sizeChanged(); void sizeChanged(int); public slots: void setSize(const int &newval) { if (newval != m_size) { QTAUTO_DEBUG("setting new value for " << QTAUTO_STRING(size) << " " << m_size << " => " << newval); m_size = newval; emit sizeChanged(); emit sizeChanged(newval); } } private: int m_size;

public:
};
#endif // SETSIZE_H
