#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QtWidgets/QMainWindow>
#include <QtWidgets/QTableWidget>
#include "DNSSECStatus.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    void loadHosts(QList<HostData> hosts);
    void LoadFile(QString fileName);

public slots:
    void resizeToData();

private:
    QTableWidget *m_table;
    QTableWidget *m_problemTable;
};

#endif // MAINWINDOW_H
