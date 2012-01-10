#ifndef DNSSECSTATUS_H
#define DNSSECSTATUS_H

#include <QLabel>
#include <QtCore/QString>
#include <QtNetwork/QHostInfo>
#include <QtGui/QTableWidget>
#include <QtNetwork/QTcpSocket>

#include <QtGui/QTableWidgetItem>

typedef struct HostData_s {
    QString hostName;
    short recordType;
    bool expectFail;
} HostData;

class DNSSECStatus : public QLabel
{
    Q_OBJECT

public:
    explicit DNSSECStatus(HostData *data,
                          QTableWidget *table, int rowNum, QTableWidget *problemTable  = 0,
                          QWidget *parent = 0);

signals:
    void dataChanged();

public slots:
    void updateText(QString fromText);
    void updateStatus();
    void lookupResponse(QHostInfo response);
    void tcpError(QAbstractSocket::SocketError error);
    void tcpNoError();
    void initConnection(int port = 80);

private:
    HostData          m_hostData;
    QTableWidget     *m_problemTable;

    QTableWidget     *m_table;
    int               m_rowNum;

    QTcpSocket       *m_socket;
};

#endif // DNSSECSTATUS_H
