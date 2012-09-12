#ifndef DETAILSVIEWER_H
#define DETAILSVIEWER_H

#include <QDialog>
#include <QObject>
#include <QtGui/QVBoxLayout>
#include <QtGui/QDialogButtonBox>
#include <QtCore/QSignalMapper>
#include <QtGui/QTabWidget>
#include "node.h"

class DetailsViewer : public QWidget
{
    Q_OBJECT
public:
    explicit DetailsViewer(Node *node, QTabWidget *tabs = 0, QWidget *parent = 0);

signals:

public slots:
    void validateNode(QString nodeType);

private:
    Node          *m_node;
    QSignalMapper *m_mapper;
    QTabWidget    *m_tabs;
};

#endif // DETAILSVIEWER_H
