#ifndef DETAILSVIEWER_H
#define DETAILSVIEWER_H

#include <QDialog>
#include <QObject>
#include <QtGui/QVBoxLayout>
#include <QtGui/QDialogButtonBox>
#include <QtCore/QSignalMapper>
#include <QtGui/QTabWidget>
#include <QtGui/QTableWidgetItem>
#include "node.h"

struct NodeWidgets {
    QTableWidgetItem *label;
    QTableWidgetItem *status;
};

class DetailsViewer : public QWidget
{
    Q_OBJECT
public:
    explicit DetailsViewer(Node *node, QTabWidget *tabs = 0, QWidget *parent = 0);
    void setStatus(DNSData data, QString recordType);
    void addRow(QString recordType, const DNSData &data);

signals:

public slots:
    void validateNode(QString nodeType);

private:
    Node          *m_node;
    QSignalMapper *m_mapper;
    QTabWidget    *m_tabs;
    QMap<QString, NodeWidgets *> m_rows;
    int            m_rowCount;

    QTableWidget  *m_table;
};

#endif // DETAILSVIEWER_H
