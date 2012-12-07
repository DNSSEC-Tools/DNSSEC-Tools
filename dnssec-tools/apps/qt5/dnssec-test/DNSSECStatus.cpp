#include "DNSSECStatus.h"

#include <QtCore/QString>

const QString unknownString = "unknown";

DNSSECStatus::DNSSECStatus(HostData *hostData,
                           QTableWidget *table, int rowNum, QTableWidget *problemTable,
                           QWidget *parent) :
    QLabel(parent), m_table(table), m_rowNum(rowNum),
    m_problemTable(problemTable), m_socket(0)
{
    m_hostData = *hostData;
}

void DNSSECStatus::updateText(QString fromText)
{
    m_hostData.hostName = fromText;
}

void DNSSECStatus::updateStatus()
{
    m_table->setItem(m_rowNum, 3, new QTableWidgetItem(tr("looking up...")));
    QHostInfo::lookupHost(m_hostData.hostName, this, SLOT(lookupResponse(QHostInfo)));
}

void DNSSECStatus::lookupResponse(QHostInfo response)
{
    if (response.error() == QHostInfo::NoError)
        m_table->setItem(m_rowNum, 1, new QTableWidgetItem(QString().number(response.addresses().count())));
    else
        m_table->setItem(m_rowNum, 1, new QTableWidgetItem(""));

    m_table->setItem(m_rowNum, 2, new QTableWidgetItem(QString().number(response.error())));

    QTableWidgetItem *errorDescription = new QTableWidgetItem((response.error() == QHostInfo::NoError ? tr("Trusted Answer") : response.errorString()));

    if ((response.error() == QHostInfo::NoError && m_hostData.expectFail) ||
        (response.error() != QHostInfo::NoError && !m_hostData.expectFail)) {
        errorDescription->setBackground(QBrush(QColor(Qt::red).lighter()));

        int row = m_problemTable->rowCount();
        m_problemTable->setRowCount(row+1);
        m_problemTable->setItem(row, 0, new QTableWidgetItem(m_hostData.hostName));
        m_problemTable->setItem(row, 1, new QTableWidgetItem(response.error() == QHostInfo::NoError ? QString().number(response.addresses().count()) : QString("")));
        m_problemTable->setItem(row, 2, new QTableWidgetItem(QString().number(response.error())));
        QTableWidgetItem *errorDescription2 = new QTableWidgetItem((response.error() == QHostInfo::NoError ? tr("Trusted Answer") : response.errorString()));
        errorDescription2->setBackground(QBrush(QColor(Qt::red).lighter()));
        m_problemTable->setItem(row, 3, errorDescription2);

        m_problemTable->resizeColumnsToContents();
        m_problemTable->resizeRowsToContents();
    } else {
        errorDescription->setBackground(QBrush(QColor(Qt::green).lighter()));
    }

    m_table->setItem(m_rowNum, 3, errorDescription);

    emit dataChanged();
}

void DNSSECStatus::initConnection(int port) {
    m_socket = new QTcpSocket(this);
    connect(m_socket, SIGNAL(error(QAbstractSocket::SocketError)), this, SLOT(tcpError(QAbstractSocket::SocketError)));
    connect(m_socket, SIGNAL(connected()), this, SLOT(tcpNoError()));
    m_socket->connectToHost(m_hostData.hostName, port);
    m_table->setItem(m_rowNum, 3, new QTableWidgetItem(tr("Connecting...")));
}

void DNSSECStatus::tcpError(QAbstractSocket::SocketError error)
{
    m_table->setItem(m_rowNum, 2, new QTableWidgetItem(QString().number(error)));
    m_table->setItem(m_rowNum, 3, new QTableWidgetItem(tr("Failed TCP Connection")));
}

void DNSSECStatus::tcpNoError()
{
    m_socket->close();
    m_table->setItem(m_rowNum, 3, new QTableWidgetItem(tr("Connected Successfully")));
}
