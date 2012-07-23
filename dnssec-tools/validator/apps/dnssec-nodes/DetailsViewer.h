#ifndef DETAILSVIEWER_H
#define DETAILSVIEWER_H

#include <QDialog>
#include <QtGui/QVBoxLayout>
#include <QtGui/QDialogButtonBox>
#include <QtCore/QSignalMapper>
#include <QtGui/QTabWidget>
#include "node.h"

class DetailsViewer : public QDialog
{
    Q_OBJECT
public:
    explicit DetailsViewer(Node *node, QWidget *parent = 0);

signals:

public slots:
    void validateNode(QString nodeName);

private:
    Node          *m_node;
    QVBoxLayout   *m_layout;
    QSignalMapper *m_mapper;
    QTabWidget    *m_tabs;
};

#endif // DETAILSVIEWER_H
