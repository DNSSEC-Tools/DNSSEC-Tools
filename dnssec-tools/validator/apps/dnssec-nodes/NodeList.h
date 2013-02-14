#ifndef NODELIST_H
#define NODELIST_H

#include <QObject>
#include <QtCore/QTimer>
#include "node.h"
#include "edge.h"

#include "Effects/Effect.h"
#include "Filters/Filter.h"
#include "FilterEditorWindow.h"

#include <QtGui/QHBoxLayout>

class GraphWidget;
class DNSData;
class Effect;
class Filter;

const QString ROOT_NODE_NAME = "<root>";

typedef QPair<Filter *, Effect *> FilterEffectPair;

class FilterEditorWindow;
class NodeList : public QObject
{
    Q_OBJECT
public:
    explicit NodeList(GraphWidget *parent = 0);

    enum FilterType { NONE, TOPBAD, BYNAME };

    Node * node(const QString &nodeName);
    Node * addNodes(const QString &nodeName);
    Node * addNode(const QString &nodeName, const QString &parentName, int depth);

    Node * centerNode() { return m_centerNode; }
    void   setCenterNode(Node *newCenter);

    int    edgeCount();
    int    nodeCount();

    int    maxNodes() { return m_maxNodes; }
    void   setMaxNodes(int max) { m_maxNodes = max; }
    void   setEnableMaxNodes(bool enabled) { m_enableMaxNodes = enabled; }

    int    maxTime() { return m_maxTime; }
    void   setMaxTime(int max) { m_maxTime = max; }
    void   setEnableMaxTime(bool enabled) { m_enableMaxTime = enabled; }

    bool   limitChildren(Node *node);

    void   filterNode(Node *node);
    void   resetNode(Node *node);
    void   reApplyFiltersTo(Node *node);
    void   setFilterBox(QHBoxLayout *filterBox);

    void   setSelectedNode(Node *node);
    Node  *selectedNode();

    void   addFilterAndEffect(Filter *filter, Effect *effect);
    void   setupFilterBox(Filter *filter = 0);
    static void   clearLayout(QLayout *layout);
    QList< FilterEffectPair *> filtersAndEffects() { return m_filtersAndEffects; }

    Effect *createDefaultEffect();

    QString removeTrailingDots(const QString &from);

signals:
    void   dataChanged();

public slots:
    void clear();
    void limit();

    void applyFilters();
    void resetEffects();
    void deleteFiltersAndEffects();

    void filterBadToTop();
    void filterByDataType();
    void filterByName();
    void clearAllFiltersAndEffects();
    void filterEditor();
    void closeEditor();

    void addNodesSlot(QString nodeName);
    void addNodesData(QString nodeName, DNSData nodeData, QString optionalLogMessage = "");

private:
    GraphWidget                          *m_graphWidget;
    Node                                 *m_centerNode;
    QMap<QString, Node *>                 m_nodes;
    QMap<QPair<QString, QString>, Edge *> m_edges;

    QTimer                                m_timer;

    bool                                  m_enableMaxNodes;
    int                                   m_maxNodes;
    int                                   m_accessCounter;
    int                                   m_accessDropOlderThan;

    bool                                  m_enableMaxTime;
    int                                   m_maxTime;
    time_t                                m_timeDropOlderThan;

    FilterType                            m_filterType;
    QRegExp                               m_nameRegexp;
    QHBoxLayout                          *m_filterBox;

    Node                                 *m_selectedNode;

    QList< FilterEffectPair *>            m_filtersAndEffects;

    FilterEditorWindow                   *m_filterEditor;
};

#endif // NODELIST_H
