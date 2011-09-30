#include "NodeList.h"
#include "DelayedDelete.h"

#include <qdebug.h>

NodeList::NodeList(GraphWidget *parent) :
    QObject(parent), m_graphWidget(parent), m_centerNode(0), m_nodes(), m_edges(),
    m_timer(this), m_maxNodes(0), m_accessCounter(0), m_accessDropOlderThan(0), m_selectedNode(0)
{
    connect(&m_timer, SIGNAL(timeout()), this, SLOT(limit()));
    m_timer.start(5000); /* clear things out every 5 seconds or so */
}

Node *NodeList::node(const QString &nodeName) {
    if (! m_nodes.contains(nodeName)) {
        return addNodes(nodeName);
    }

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
            //qDebug() << "    adding: " << (*node + "." + completeString) << " DNE!";
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
    QString fqdn;

    if (parentName.length() != 0) {
        parentString = parentName;
        suffixString = "." + parentName;
    }

    fqdn = nodeName + suffixString;

    // create a new node, and find a parent for it
    Node *newNode = m_nodes[fqdn] = new Node(m_graphWidget, nodeName, fqdn, depth);
    Node *parent = node(parentString);

    // define the graphics charactistics
    newNode->setPos(parent->pos() + QPointF(50 - qrand() % 101, 50 - qrand() % 101));
    m_graphWidget->addItem(newNode);

    // define the arrow from parent to child
    m_graphWidget->addItem(edge = new Edge(parent, newNode));
    m_edges[QPair<QString, QString>(fqdn, parentName)] = edge;

    // define the relationship
    parent->addChild(newNode);
    newNode->addParent(parent);

    // define the access counts
    newNode->setAccessCount(m_accessCounter++);
    newNode->setAccessTime(time(NULL));

    filterNode(newNode);

    return newNode;
}

int NodeList::nodeCount() {
    return m_nodes.count();
}

int NodeList::edgeCount() {
    return m_edges.count();
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

void NodeList::limit()
{
    if (!m_enableMaxNodes || !m_enableMaxTime)
        return;

    m_accessDropOlderThan = m_accessCounter - m_maxNodes;
    m_timeDropOlderThan = time(NULL) - m_maxTime;

    // walk through our list of nodes and drop everything "older"
    bool haveLimited = limitChildren(m_centerNode);

    qDebug() << "Done limiting (" << haveLimited << ") using maxNodes(" << m_enableMaxNodes << ")=" << m_maxNodes << ", maxTime(" << m_enableMaxTime << ")=" << m_maxTime;

    if (haveLimited)
        emit dataChanged();
}

bool NodeList::limitChildren(Node *node) {
    bool haveLimited = false;

    foreach (Node *child, node->children()) {
        if (limitChildren(child))
            haveLimited = true;
    }

    if (node->children().count() == 0 && node->nodeName() != ROOT_NODE_NAME) {
        if ((m_enableMaxNodes && node->accessCount() < m_accessDropOlderThan) ||
            (m_enableMaxTime && node->accessTime() < m_timeDropOlderThan)) {
            // drop this node because it has no children left and is safe to remove
            qDebug() << "removing: " << node->fqdn() << " #" << node->accessCount() << " / " << m_accessDropOlderThan;

            Node *parent = node->parent();

            // remove it from various lists
            m_graphWidget->removeItem(node);
            m_nodes.remove(node->fqdn());

            // remove the edge too
            if (node && parent) {
                QPair<QString, QString> edgeNames(node->fqdn(), parent->fqdn());
                Edge *edge = m_edges[edgeNames];
                m_graphWidget->removeItem(edge);
                m_edges.remove(edgeNames);

                if (parent)
                    parent->removeEdge(edge);
                new DelayedDelete<Edge>(edge);
            }

            // delete the relationship
            if (parent)
                parent->removeChild(node);

            haveLimited = true;

            if (m_selectedNode == node) {
                m_selectedNode = 0;
                m_graphWidget->hideInfo();
            }

            new DelayedDelete<Node>(node);
        }
    }
    return haveLimited;
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

void NodeList::setFilter(FilterType filterType) {
    // reset stuff
    m_filterBox->hide();

    m_filterType = filterType;
    applyFilter();
}

void NodeList::applyFilter() {
    // Reset the current Z values first
    foreach (Node *node, m_nodes) {
        node->setZValue(-1);
        node->setAlpha(255);
    }

    if (m_filterType != NONE) {
        // Apply the selected filter
        foreach (Node *node, m_nodes) {
            filterNode(node);
        }
    }
}

void NodeList::setFilterFQDNExpression(QString regexp) {
    m_nameRegexp = QRegExp(regexp);
    applyFilter();
}

inline void NodeList::filterNode(Node *node) {
    switch(m_filterType) {
    case TOPBAD:
        if (node->DNSSECValidity() & DNSData::FAILED) {
            node->setZValue(1);
        }
        break;

    case BYNAME:
        if (m_nameRegexp.isEmpty() || m_nameRegexp.indexIn(node->fqdn()) != -1) {
            node->setAlpha(255);
            node->setZValue(1);
        } else {
            node->setAlpha(64);
            node->setZValue(-1);
        }

    default:
        break;
    }
}

void NodeList::filterByName() {
    setFilter(BYNAME);
    m_filterBox->show();
}

void NodeList::setFilterWidget(QWidget *filterBox)
{
    m_filterBox = filterBox;
}

void NodeList::setSelectedNode(Node *node)
{
    m_selectedNode = node;
}

Node * NodeList::selectedNode()
{
    return m_selectedNode;
}

