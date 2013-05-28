#include "DNSSECCheckThreadHandler.h"

#include "DNSSECTest.h"

DNSSECCheckThreadHandler::DNSSECCheckThreadHandler(QObject *parent) :
    QObject(parent)
{
}

void DNSSECCheckThreadHandler::startTest(CheckFunction *checkFunction, char *serverAddress, bool async)
{
    int rc;

    if (!checkFunction || !serverAddress)
        return;

    DNSSECCheckThreadData *data = new DNSSECCheckThreadData();

    data->m_serverAddress = serverAddress;
    data->m_checkFunction = checkFunction;
    data->m_result_status = DNSSECTest::TESTINGNOW;
    rc = (*checkFunction)(data->m_serverAddress, data->m_msgBuffer, sizeof(data->m_msgBuffer), &data->m_result_status);
    if (async) {
        m_dataList.push_back(data);
        emit asyncTestSubmitted();
        return;
    }
    emit testResult(checkFunction, serverAddress, data->m_result_status, QString(data->m_msgBuffer));
    delete data;
}

void DNSSECCheckThreadHandler::checkStatus()
{
    foreach(DNSSECCheckThreadData *data, m_dataList) {
        if (DNSSECTest::rcToStatus(data->m_result_status) != DNSSECTest::TESTINGNOW && DNSSECTest::rcToStatus(data->m_result_status) != DNSSECTest::UNKNOWN) {
            emit testResult(data->m_checkFunction, data->m_serverAddress, data->m_result_status, QString(data->m_msgBuffer));
            m_dataList.removeOne(data);
        }
    }
}
