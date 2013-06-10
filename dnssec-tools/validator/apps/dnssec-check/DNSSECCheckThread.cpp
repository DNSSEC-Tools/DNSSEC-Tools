#include "DNSSECCheckThread.h"

#include <qdebug.h>

void DNSSECCheckThread::run()
{
    m_handler = new DNSSECCheckThreadHandler();
    emit handlerReady(m_handler);
    exec();
}
