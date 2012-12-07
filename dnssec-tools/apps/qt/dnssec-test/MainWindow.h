#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QtGui/QMainWindow>
#include <QtGui/QTableWidget>
#include "DNSSECStatus.h"

namespace Ui {
    class MainWindow;
}

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
    Ui::MainWindow *ui;
    QTableWidget *m_table;
    QTableWidget *m_problemTable;
};

#endif // MAINWINDOW_H
