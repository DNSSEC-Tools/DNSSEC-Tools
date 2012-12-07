#include "MainWindow.h"
#include "ui_MainWindow.h"
#include "DNSSECStatus.h"

#include <QtGui/QLabel>
#include <QtGui/QLineEdit>
#include <QtGui/QGridLayout>
#include <QtCore/QStringList>
#include <QtCore/QTimer>
#include <QtCore/QFile>
#include <QtGui/QMessageBox>
#include <QtGui/QPushButton>

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent)
{
    QVBoxLayout *vbox = new QVBoxLayout();
    QWidget *widget = new QWidget();
    setCentralWidget(widget);
    widget->setLayout(vbox);

    vbox->addWidget(new QLabel(tr("Problems Found")));
    m_problemTable = new QTableWidget(this);
    vbox->addWidget(m_problemTable);

    vbox->addWidget(new QLabel(tr("Detailed Results")));
    m_table = new QTableWidget(this);
    vbox->addWidget(m_table);

    QList<HostData> startingHosts;
    HostData hostData;
    hostData.expectFail = false; // this should succeed
    hostData.recordType = 1; // A
    hostData.hostName = "good-a.test.dnssec-tools.org";
    startingHosts << hostData;
    hostData.expectFail = true; // these should fail
    hostData.hostName = "badsign-a.test.dnssec-tools.org";
    startingHosts << hostData;

    loadHosts(startingHosts);
}

void MainWindow::loadHosts(QList<HostData> hosts) {
    DNSSECStatus *status;
    QTableWidgetItem *count;
    QTableWidgetItem *errorNum;
    QTableWidgetItem *errorDescription;

    QLineEdit *edit;

    int row = 0;
    m_table->clear();
    m_table->setRowCount(hosts.count());
    m_table->setColumnCount(5);
    m_table->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    m_problemTable->clear();
    m_problemTable->setColumnCount(4);
    m_problemTable->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);

    foreach(HostData hostData, hosts) {
        status = new DNSSECStatus(&hostData,
                                  m_table, row, m_problemTable, this);
        QPushButton *button = new QPushButton("->");

        m_table->setCellWidget(row, 0, edit = new QLineEdit(hostData.hostName, this));
        m_table->setItem(row, 1, count);
        m_table->setItem(row, 2, errorNum);
        m_table->setItem(row, 3, errorDescription);
        m_table->setCellWidget(row, 4, button);

        connect(button, SIGNAL(clicked()), status, SLOT(initConnection()));
        connect(edit, SIGNAL(textChanged(QString)), status, SLOT(updateText(QString)));
        connect(edit, SIGNAL(returnPressed()), status, SLOT(updateStatus()));
        connect(status, SIGNAL(dataChanged()), this, SLOT(resizeToData()));

        status->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
        edit->setMinimumWidth(400);
        QTimer::singleShot(1000, status, SLOT(updateStatus()));

        row++;
    }

    QStringList labels;
    labels << "Name" << "Address Count" << "Status" << "Status Description" << "Try TCP";
    m_table->setHorizontalHeaderLabels(labels);
    m_problemTable->setHorizontalHeaderLabels(labels);
    resizeToData();

    setMinimumSize(800,600);
}

void
MainWindow::LoadFile(QString fileName) {
    QList<HostData> hostDataList;

    QFile file(fileName);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox msg;
        msg.setText(QString(tr("Failed to open the host file: %1").arg(fileName)));
        msg.exec();
        return;
    }

    HostData hostData;
    hostData.recordType = 1;
    hostData.expectFail = true;

    QTextStream stream(&file);
    while(!stream.atEnd()) {
        QString line = stream.readLine();
        QStringList parts = line.split(',');
        hostData.hostName = parts.at(0);

        hostData.recordType = (parts.count() > 1 && parts.at(1).length() > 0) ? parts.at(1).toShort() : 1;
        hostData.expectFail = (parts.count() > 2 && parts.at(2).length() > 0) ? (parts.at(2) == "true" ? true : false) : true;
        hostDataList << hostData;
    }

    loadHosts(hostDataList);
}

MainWindow::~MainWindow()
{
}

void
MainWindow::resizeToData()
{
    m_table->resizeColumnsToContents();
    m_table->resizeRowsToContents();
}
