#ifndef DETAILSVIEWER_H
#define DETAILSVIEWER_H

#include <QDialog>
#include <QtGui/QVBoxLayout>
#include <QtGui/QDialogButtonBox>
#include "node.h"

class DetailsViewer : public QDialog
{
    Q_OBJECT
public:
    explicit DetailsViewer(Node *node, QWidget *parent = 0);

signals:

public slots:

private:
    Node        *m_node;
    QVBoxLayout *m_layout;
};

#endif // DETAILSVIEWER_H
