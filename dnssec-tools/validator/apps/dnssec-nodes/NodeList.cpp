#include "NodeList.h"
#include "DelayedDelete.h"

#include "filtersAndEffects.h"

#include "graphwidget.h"

#include <qdebug.h>

#include <sys/time.h>

NodeList::NodeList(GraphWidget *parent) :
    QObject(parent), m_graphWidget(parent), m_centerNode(0), m_nodes(), m_edges(),
    m_timer(this), m_maxNodes(0), m_accessCounter(0), m_accessDropOlderThan(0), m_selectedNode(0),
    m_filtersAndEffects(), m_filterEditor(0)
{
    connect(&m_timer, SIGNAL(timeout()), this, SLOT(limit()));
    m_timer.start(5000); /* clear things out every 5 seconds or so */
}

QString NodeList::removeTrailingDots(const QString &from) {
    QString maybeToLong(from);
    while (maybeToLong.endsWith("."))
        maybeToLong.chop(1);
    if (maybeToLong.length() == 0)
        maybeToLong = "<root>";
    return maybeToLong;
}

Node *NodeList::node(const QString &nodeName) {
    QString maybeToLong = nodeName; //removeTrailingDots(nodeName);
    if (maybeToLong == "")
        maybeToLong = ROOT_NODE_NAME;

    if (! m_nodes.contains(maybeToLong)) {
        return addNodes(maybeToLong);
    }

    return m_nodes[maybeToLong];
}

Node *NodeList::addNodes(const QString &nodeName) {
    int count = 1;
    Node *returnNode = 0;
    QString newNodeName = removeTrailingDots(nodeName);


    QStringList nodeNameList = newNodeName.split(".");
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
    emit dataChanged();
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

    m_centerNode = 0;

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
    if (m_centerNode) {
        if (m_nodes.contains(ROOT_NODE_NAME))
            m_nodes.remove(ROOT_NODE_NAME);
        delete m_centerNode;
    }

    m_centerNode = newCenter;
    m_nodes[ROOT_NODE_NAME] = newCenter;
}

void NodeList::resetEffects() {
    foreach (FilterEffectPair *pair, m_filtersAndEffects) {
        foreach (Node *node, m_nodes) {
            pair->second->resetNode(node);
        }
    }
}

void NodeList::deleteFiltersAndEffects() {
    resetEffects(); // Make sure we clear out what was done before forgetting how to undo it
    foreach(FilterEffectPair *pair, m_filtersAndEffects) {
        delete pair->first;
        delete pair->second;
    }
    m_filtersAndEffects.clear();
}

void NodeList::applyFilters() {
    resetEffects();

    foreach (FilterEffectPair *pair, m_filtersAndEffects) {
        foreach (Node *node, m_nodes) {
            if (pair->first->matches(node)) {
                pair->second->applyToNode(node);
            }
        }
    }
}

void NodeList::resetNode(Node *node) {
    foreach (FilterEffectPair *pair, m_filtersAndEffects) {
        pair->second->resetNode(node);
    }
}

void NodeList::filterNode(Node *node) {
    foreach (FilterEffectPair *pair, m_filtersAndEffects) {
        if (pair->first->matches(node)) {
            pair->second->applyToNode(node);
        }
    }
}

void NodeList::reApplyFiltersTo(Node *node) {
    resetNode(node);
    filterNode(node);
}

void NodeList::clearAllFiltersAndEffects()
{
    deleteFiltersAndEffects();
    setupFilterBox(0);
}

void NodeList::addNodesSlot(QString nodeName)
{
    addNodes(nodeName);
}

void NodeList::addNodesData(QString nodeName, DNSData nodeData, QString optionalLogMessage)
{
    addNodes(nodeName);
    Node *theNode = node(nodeName);
    theNode->addSubData(nodeData);
    if (optionalLogMessage.length() > 0)
        theNode->addLogMessage(optionalLogMessage);
}

Effect *NodeList::createDefaultEffect() {
    MultiEffect *effect = new MultiEffect();
    effect->addEffect(new SetZValue(-5));
    effect->addEffect(new SetAlphaEffect(64));
    effect->addEffect(new SetNodeColoring(Qt::gray));
    return effect;
}

void NodeList::filterByName() {
    deleteFiltersAndEffects();

    Effect *effect = createDefaultEffect();
    Filter *filter = new NotFilter(new NameFilter(""));
    setupFilterBox(filter);

    addFilterAndEffect(filter, effect);

    applyFilters();
}

void NodeList::filterByDataType()
{
    Filter *filter;

    deleteFiltersAndEffects();

    Effect *effect = createDefaultEffect();

    addFilterAndEffect(filter = new NotFilter(new TypeFilter("A")), effect);

    setupFilterBox(filter);
    applyFilters();
}

void NodeList::filterBadToTop()
{
    Filter *filter;

    deleteFiltersAndEffects();

    Effect *effect = createDefaultEffect();

    addFilterAndEffect(filter = new NotFilter(new DNSSECStatusFilter(DNSData::FAILED)), effect);

    setupFilterBox(filter);
    applyFilters();
}

void NodeList::filterEditor()
{
    if (m_filterEditor) {
        m_filterEditor->raise();
        return;
    }
    m_filterEditor = new FilterEditorWindow(this);
    m_filterEditor->show();
    connect(m_filterEditor, SIGNAL(destroyed()), this, SLOT(closeEditor()));
}

void NodeList::closeEditor()
{
    m_filterEditor = 0;
}


void NodeList::setFilterBox(QHBoxLayout *filterBox)
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

void NodeList::addFilterAndEffect(Filter *filter, Effect *effect)
{
    m_filtersAndEffects.push_back(new FilterEffectPair(filter, effect));
    connect(filter, SIGNAL(filterChanged()), this, SLOT(applyFilters()));
    connect(effect, SIGNAL(effectChanged()), this, SLOT(applyFilters()));
}

void NodeList::clearLayout(QLayout *layout) {
    QLayoutItem *item;
    while((item = layout->takeAt(0))) {
        if (item->layout()) {
            clearLayout(item->layout());
            delete item->layout();
        }
        if (item->widget()) {
            delete item->widget();
        }
        // XXX: item->deleteLater();
    }
}

void NodeList::setupFilterBox(Filter *filter)
{

    // Delete the current items
    clearLayout(m_filterBox);

    if (filter) {
        filter->configWidgets(m_filterBox);
    }
    //filterEditBox->connect(filterEditBox, SIGNAL(textChanged(QString)), graphWidget->nodeList(), SLOT(setFilterFQDNExpression(QString)));
}


