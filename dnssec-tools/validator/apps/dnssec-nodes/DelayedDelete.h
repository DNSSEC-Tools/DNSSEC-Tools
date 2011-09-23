#ifndef DELAYEDDELETE_H
#define DELAYEDDELETE_H

#include <QObject>

template <typename T>
class DelayedDelete : public QObject
{
public:
    explicit DelayedDelete(T *&item) : m_item(item)
    {
        item = 0;
        deleteLater();
    }
    virtual ~DelayedDelete()
    {
        delete m_item;
    }
private:
    T *m_item;
};

#endif // DELAYEDDELETE_H
