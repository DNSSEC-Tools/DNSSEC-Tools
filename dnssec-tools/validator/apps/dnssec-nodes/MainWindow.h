#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtGui/QVBoxLayout>
#include <QtGui/QLineEdit>
#include <QtGui/QMenuBar>

#include "graphwidget.h"
#include "TypeMenu.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(const QString &fileName = "", QWidget *parent = 0);
    
signals:
    
public slots:
    
};

#endif // MAINWINDOW_H
