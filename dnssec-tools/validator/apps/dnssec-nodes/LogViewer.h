#ifndef LOGVIEWER_H
#define LOGVIEWER_H

#include <QDialog>
#include <QtGui/QVBoxLayout>
#include <QtGui/QDialogButtonBox>
#include "node.h"

class LogViewer : public QDialog
{
    Q_OBJECT
public:
    explicit LogViewer(Node *node, QWidget *parent = 0);

signals:

public slots:

private:
    Node        *m_node;
    QVBoxLayout *m_layout;
};

#endif // LOGVIEWER_H
