#ifndef NODELIST_H
#define NODELIST_H

#include <QObject>
#include "node.h"
#include "edge.h"
#include "graphwidget.h"

class GraphWidget;

const QString ROOT_NODE_NAME = "<root>";

class NodeList : public QObject
{
    Q_OBJECT
public:
    explicit NodeList(GraphWidget *parent = 0);

    Node * node(const QString &nodeName);
    Node * addNodes(const QString &nodeName);
    Node * addNode(const QString &nodeName, const QString &parentName, int depth);

    Node * centerNode() { return m_centerNode; }
    void   setCenterNode(Node *newCenter);

    int    edgeCount();
    int    nodeCount();

    int    maxNodes() { return m_maxNodes; }
    void   setMaxNodes(int max) { m_maxNodes = max; }

signals:

public slots:
    void clear();

private:
    GraphWidget                          *m_graphWidget;
    Node                                 *m_centerNode;
    QMap<QString, Node *>                 m_nodes;
    QMap<QPair<QString, QString>, Edge *> m_edges;

    int                                   m_maxNodes;
};

#endif // NODELIST_H
