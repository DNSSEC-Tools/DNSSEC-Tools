#include "NodeList.h"

#include <qdebug.h>

NodeList::NodeList(GraphWidget *parent) :
    QObject(parent), m_graphWidget(parent), m_centerNode(0), m_nodes(), m_edges()
{
}

Node *NodeList::node(const QString &nodeName) {
    if (! m_nodes.contains(nodeName))
        m_nodes[nodeName] = new Node(m_graphWidget, nodeName);
    return m_nodes[nodeName];
}

Node *NodeList::addNodes(const QString &nodeName) {
    int count = 1;
    Node *returnNode = 0;

    QStringList nodeNameList = nodeName.split(".");
    QString completeString = QString("");

    QStringList::iterator node = nodeNameList.end();
    QStringList::iterator firstItem = nodeNameList.begin();

    while (node != firstItem) {
        node--;
        //qDebug() << "  doing node (" << nodeName << "): " << *node << "/" << completeString << " at " << count;
        if (! m_nodes.contains(*node + "." + completeString)) {
            //qDebug() << "    " << (*node + "." + completeString) << " DNE!";
            returnNode = addNode(*node, completeString, count);
        } else {
            returnNode = m_nodes[*node + "." + completeString];
        }
        completeString = *node + "." + completeString;
        count++;
    }
    return returnNode;
}

Node *NodeList::addNode(const QString &nodeName, const QString &parentName, int depth) {
    Edge *edge;
    QString parentString("<root>");
    QString suffixString(".");

    if (parentName.length() != 0) {
        parentString = parentName;
        suffixString = "." + parentName;
    }

    Node *newNode = m_nodes[nodeName + suffixString] = new Node(m_graphWidget, nodeName, depth);
    Node *parent = node(parentString);
    newNode->setPos(parent->pos() + QPointF(50 - qrand() % 101, 50 - qrand() % 101));
    m_graphWidget->addItem(newNode);
    m_graphWidget->addItem(edge = new Edge(newNode, parent));
    m_edges[QPair<QString, QString>(parentName, nodeName)] = edge;
    parent->addChild(newNode);
    newNode->addParent(parent);
    return newNode;
}

void NodeList::clear()
{
    foreach(Node *aNode, m_nodes) {
        delete aNode;
    }

    foreach(Edge *anEdge, m_edges) {
        delete anEdge;
    }

    m_nodes.clear();
    m_edges.clear();

    // add back in the starting node
    m_graphWidget->createStartingNode();
}

void  NodeList::setCenterNode(Node *newCenter) {
    qDebug() << "setting center";
    if (m_centerNode) {
        if (m_nodes.contains(ROOT_NODE_NAME))
            m_nodes.remove(ROOT_NODE_NAME);
        delete m_centerNode;
    }

    m_centerNode = newCenter;
    m_nodes[ROOT_NODE_NAME] = newCenter;
    qDebug() << "here after: " << m_nodes.count();
}
