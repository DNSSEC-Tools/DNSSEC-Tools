#ifndef DNSSECCHECKTHREAD_H
#define DNSSECCHECKTHREAD_H

#include <QThread>
#include <QtCore/QList>
#include "DNSSECTest.h"
#include "DNSSECCheckThreadHandler.h"

class DNSSECCheckThreadHandler;

class DNSSECCheckThread : public QThread
{
    Q_OBJECT
public:
    explicit DNSSECCheckThread() : m_handler(0) { }
    void run();
    DNSSECCheckThreadHandler *handler() { return m_handler; }

signals:
    void handlerReady(DNSSECCheckThreadHandler *);

private:
    DNSSECCheckThreadHandler *m_handler;
};

#endif // DNSSECCHECKTHREAD_H
