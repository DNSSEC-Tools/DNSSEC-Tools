#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QtGui/QVBoxLayout>
#include <QtGui/QLineEdit>
#include <QtGui/QMenuBar>
#include <QtGui/QTabWidget>

#include "graphwidget.h"
#include "TypeMenu.h"

class MainWindow : public QMainWindow
{
    Q_OBJECT
public:
    explicit MainWindow(const QString &fileName = "", QWidget *parent = 0);

    GraphWidget *graphWidget() { return m_graphWidget; }
    
signals:
    
public slots:
    void closeTab(int tabIndex);

private:
    QTabWidget *tabs;
    GraphWidget *m_graphWidget;
    
};

#endif // MAINWINDOW_H
