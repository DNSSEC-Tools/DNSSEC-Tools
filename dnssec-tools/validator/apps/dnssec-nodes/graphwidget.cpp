/****************************************************************************
**
** Copyright (C) 2010 Nokia Corporation and/or its subsidiary(-ies).
** All rights reserved.
** Contact: Nokia Corporation (qt-info@nokia.com)
**
** This file is part of the examples of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:BSD$
** You may use this file under the terms of the BSD license as follows:
**
** "Redistribution and use in source and binary forms, with or without
** modification, are permitted provided that the following conditions are
** met:
**   * Redistributions of source code must retain the above copyright
**     notice, this list of conditions and the following disclaimer.
**   * Redistributions in binary form must reproduce the above copyright
**     notice, this list of conditions and the following disclaimer in
**     the documentation and/or other materials provided with the
**     distribution.
**   * Neither the name of Nokia Corporation and its Subsidiary(-ies) nor
**     the names of its contributors may be used to endorse or promote
**     products derived from this software without specific prior written
**     permission.
**
** THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
** "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
** LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
** A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
** OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
** SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
** LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
** DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
** THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
** (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
** OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
** $QT_END_LICENSE$
**
****************************************************************************/

#include <QMessageBox>

#include "graphwidget.h"
#include "edge.h"
#include "node.h"
#include "DNSData.h"
#include "NodesPreferences.h"
#include "DetailsViewer.h"
#include "LogFilePicker.h"

#include "LogWatcher.h"
#include "NodeList.h"
#ifdef WITH_PCAP
#include "PcapWatcher.h"
#endif
#include "DNSData.h"

#include "DNSResources.h"

#include <QtGui>
#include <qdebug.h>

#include <math.h>

#ifdef __WIN32__
#include <winsock2.h>
#include <windns.h>
#include <ws2tcpip.h>
#define ns_t_a   DNS_TYPE_A
#define ns_c_in  1
#endif

#ifndef __WIN32__
#include <arpa/inet.h>
#include <arpa/nameser.h>
#endif /* __WIN32__ */
#include <validator/resolver.h>
#include <validator/validator.h>
#include <sys/types.h>
#ifndef __WIN32__
#include <sys/socket.h>
#include <netdb.h>
#endif /* __WIN32__ */

#ifdef __WIN32__
void WSAAPI freeaddrinfo (struct addrinfo*);
#endif

#include <QTimer>

const int maxHistory = 10;

static QStringList val_log_strings;
void val_collect_logs(struct val_log *logp, int level, const char *buf)
{
    Q_UNUSED(logp);
    Q_UNUSED(level);
    val_log_strings.push_back(buf);
}

GraphWidget::GraphWidget(QWidget *parent, QLineEdit *editor, QTabWidget *tabs, const QString &fileName, QHBoxLayout *infoBox)
    : QGraphicsView(parent), timerId(0), m_editor(editor),
      m_nodeScale(2), m_localScale(false), m_lockNodes(false), m_shownsec3(false),
      m_timer(0),
      m_layoutType(springyLayout), m_childSize(30), m_lookupType(1), m_animateNodeMovements(true),
      m_updateLineEditAlways(false), m_autoValidateServFails(false),
      m_infoBox(infoBox), m_infoLabel(0), m_infoMoreButton(0), m_nodeInfoLabel(0), m_previousFileMenu(0), m_mapper(),
      m_nodeList(new NodeList(this)), m_logWatcher(new LogWatcher(this)), m_legend(0), m_tabs(tabs), m_useStraightValidationLines(false),
      m_useToggledValidationBoxes(false), m_startingNode(ROOT_NODE_NAME)
#ifdef WITH_PCAP
    , m_pcapWatcher(new PcapWatcher())
#endif
{
    myScene = new QGraphicsScene(this);
    myScene->setItemIndexMethod(QGraphicsScene::NoIndex);
    myScene->setSceneRect(-300, -300, 600, 600);
    setScene(myScene);
    setCacheMode(CacheBackground);
    setViewportUpdateMode(BoundingRectViewportUpdate);
    setRenderHint(QPainter::Antialiasing);
    setTransformationAnchor(AnchorUnderMouse);
    setDragMode(QGraphicsView::ScrollHandDrag);
    setWindowTitle(tr("DNSSEC Nodes"));
    scaleWindow();

    createStartingNode();

    m_infoBox->addWidget(m_nodeInfoLabel = new QLabel(tr("Node Information: ")));
    m_nodeInfoLabel->setSizePolicy(QSizePolicy::Minimum, QSizePolicy::Minimum);
    m_infoBox->addWidget(m_infoLabel = new QLabel(""));
    m_infoLabel->setSizePolicy(QSizePolicy::MinimumExpanding, QSizePolicy::Minimum);
    m_infoBox->addWidget(m_infoMoreButton = new QPushButton("Details..."));
    connect(m_infoMoreButton, SIGNAL(clicked()), this, SLOT(moreInfoButton()));
//    m_infoMoreButton->hide();
//    m_nodeInfoLabel->hide();

    // m_logWatcher->parseLogFile();

    setLayoutType(circleLayout);

    connect(m_editor, SIGNAL(returnPressed()), this, SLOT(doLookupFromLineEdit()));
    connect(m_logWatcher, SIGNAL(dataChanged()), this, SLOT(reLayout()));
    connect(m_nodeList, SIGNAL(dataChanged()), this, SLOT(reLayout()));

    connect(this, SIGNAL(useStraightValidationLinesChanged()), this, SLOT(saveUseStraightValidationLinesPref()));
    connect(this, SIGNAL(useToggledValidationBoxesChanged()), this, SLOT(saveUseToggledValidationBoxes()));

    val_log_add_cb(NULL, 99, &val_collect_logs);

    setPrefs();

    if (!fileName.isEmpty())
        m_logWatcher->parseLogFile(fileName);

#ifdef WITH_PCAP
    connect(m_pcapWatcher, SIGNAL(addNode(QString)), m_nodeList, SLOT(addNodesSlot(QString)));
    connect(m_pcapWatcher, SIGNAL(addNodeData(QString, DNSData, QString)), m_nodeList, SLOT(addNodesData(QString,DNSData, QString)));
    connect(m_pcapWatcher, SIGNAL(addNodeData(QString,DNSData,QString)), this, SLOT(doLookupFromServFail(QString,DNSData,QString)));
    connect(this, SIGNAL(openPcapDevice()), m_pcapWatcher, SLOT(openDevice()));
    m_pcapWatcher->start();
#endif
}

void GraphWidget::resetStartingNode() {
    setStartingNode(ROOT_NODE_NAME);
}

void GraphWidget::addItem(QGraphicsItem *newItem) {
    myScene->addItem(newItem);
}

void GraphWidget::removeItem(QGraphicsItem *removeThis)
{
    myScene->removeItem(removeThis);
}

void GraphWidget::resizeEvent(QResizeEvent *event) {
    Q_UNUSED(event);
    scaleWindow();
}

void GraphWidget::scaleWindow() {

    if (m_localScale)
        return;

    // get rid of the current scale
    qreal oldScale = 1.0 / transform().mapRect(QRectF(0, 0, 1, 1)).height();
    scale(oldScale, oldScale);

    // calculate the new scale
    QSize windowSize = size();
    qreal newscale = qMin(windowSize.width() / myScene->sceneRect().width(), windowSize.height() / myScene->sceneRect().width());

    // apply it
    scale(1.2 * newscale, 1.2 * newscale);
}

void GraphWidget::doLookupFromServFail(QString nodeName, DNSData nodeData, QString optionalLogMessage) {
    Q_UNUSED(optionalLogMessage)
    if (autoValidateServFails())
        doActualLookup(nodeName, DNSResources::RRNameToType(nodeData.recordType()));
}

void GraphWidget::doLookupFromLineEdit() {
    doLookup(m_editor->text());
    reLayout();
}

void GraphWidget::setLineEditValue(const QString &value) {
    m_editor->setText(value);
}

void GraphWidget::maybeSetLineEditValue(const QString &value) {
    if (m_updateLineEditAlways)
        setLineEditValue(value);
}

void GraphWidget::itemMoved()
{
    if (!m_lockNodes && !timerId)
        timerId = startTimer(1000 / 25);
}

void GraphWidget::keyPressEvent(QKeyEvent *event)
{
    Node *centerNode = m_nodeList->centerNode();

    switch (event->key()) {
    case Qt::Key_Up:
        centerNode->moveBy(0, -20);
        break;
    case Qt::Key_Down:
        centerNode->moveBy(0, 20);
        break;
    case Qt::Key_Left:
        centerNode->moveBy(-20, 0);
        break;
    case Qt::Key_Right:
        centerNode->moveBy(20, 0);
        break;
    case Qt::Key_Plus:
        zoomIn();
        break;
    case Qt::Key_Minus:
        zoomOut();
        break;
    case Qt::Key_Space:
    case Qt::Key_Enter:
        shuffle();
        break;
    default:
        QGraphicsView::keyPressEvent(event);
    }
}

void GraphWidget::timerEvent(QTimerEvent *event)
{
    Q_UNUSED(event);

    if (m_lockNodes)
        return;

    QList<Node *> nodes;
    foreach (QGraphicsItem *item, scene()->items()) {
        if (Node *node = qgraphicsitem_cast<Node *>(item))
            nodes << node;
    }

    if (m_layoutType == springyLayout)
        foreach (Node *node, nodes)
            node->calculateForces();

    bool itemsMoved = false;
    foreach (Node *node, nodes) {
        if (node->advance()) {
            itemsMoved = true;
        }
    }

    if (!itemsMoved) {
        killTimer(timerId);
        timerId = 0;
    }
}

void GraphWidget::wheelEvent(QWheelEvent *event)
{
    scaleView(pow((double)2, -event->delta() / 240.0));
}

void GraphWidget::drawBackground(QPainter *painter, const QRectF &rect)
{
    // Shadow
    QRectF sceneRect = QRectF(mapToScene(0, 0), mapToScene(width(), height())); //scene()->sceneRect();

    // Fill
    QLinearGradient gradient(sceneRect.topLeft(), sceneRect.bottomRight());
    gradient.setColorAt(0, Qt::white);
    gradient.setColorAt(1, Qt::lightGray);
    painter->fillRect(rect.intersected(sceneRect), gradient);
    painter->setBrush(Qt::NoBrush);
    painter->drawRect(sceneRect);
}

void GraphWidget::scaleView(qreal scaleFactor)
{
    qreal factor = transform().scale(scaleFactor, scaleFactor).mapRect(QRectF(0, 0, 1, 1)).width();
    if (factor < 0.07 || factor > 100)
        return;

    scale(scaleFactor, scaleFactor);
}

void GraphWidget::shuffle()
{
    foreach (QGraphicsItem *item, scene()->items()) {
        if (qgraphicsitem_cast<Node *>(item))
            item->setPos(-150 + qrand() % 300, -150 + qrand() % 300);
    }
}

void GraphWidget::zoomIn()
{
    m_localScale = true;
    scaleView(qreal(1.2));
}

void GraphWidget::zoomOut()
{
    m_localScale = true;
    scaleView(1 / qreal(1.2));
}

void GraphWidget::reLayout() {
    if (m_lockNodes)
        return;

    switch(m_layoutType) {
    case treeLayout:
        layoutInTree();
        break;
    case circleLayout:
        layoutInCircles();
        break;
    default:
        break;
    }

    itemMoved();
}

void GraphWidget::switchToTree() {
    itemMoved();
    layoutInTree();
}


void GraphWidget::switchToCircles() {
    itemMoved();
    layoutInCircles();
}

void GraphWidget::layoutInTree() {
    m_layoutType = treeLayout;
    QRectF rect = myScene->sceneRect();
    int farRightX = layoutTreeNode(m_nodeList->node("<root>"), rect.left() + m_childSize, rect.top() + m_childSize);

    if (farRightX > myScene->sceneRect().right()) {
        myScene->setSceneRect(rect.left(), rect.top(), farRightX - rect.left(), rect.height());
        scaleWindow();
    }
}

int GraphWidget::layoutTreeNode(Node *node, int minX, int minY) {
    if (!scene() || scene()->mouseGrabberItem() == node) {
        return minX;
    }

    QSet<Node *> childNodes = node->children();
    int runningMinX = minX;

    foreach(Node *child, childNodes) {
        runningMinX = layoutTreeNode(child, runningMinX, minY + m_childSize) + m_childSize;
    }
    if (childNodes.count() > 0)
        runningMinX -= m_childSize;

    QPointF newpos(minX + (runningMinX - minX)/2, minY);
    node->setNewPos(newpos);
    if (! m_animateNodeMovements)
        node->setPos(newpos);
    return runningMinX;
}

void GraphWidget::layoutInCircles() {
    const int childSize = 30;
    QRectF sceneRect(-150,-150,150,150);
    m_layoutType = circleLayout;
    Node *startingNode = m_nodeList->node(m_startingNode);
    layoutCircleNode(startingNode, 0, 0, 0, 2*3.1415, sceneRect, startingNode);
    sceneRect.setBottom(sceneRect.bottom() + childSize);
    sceneRect.setTop(sceneRect.top() - childSize);
    sceneRect.setLeft(sceneRect.left() - childSize);
    sceneRect.setRight(sceneRect.right() + childSize);
    myScene->setSceneRect(sceneRect);
    // XXX: test growth size into borders
}

void GraphWidget::layoutCircleNode(Node *node, qreal startX, qreal startY, qreal startingDegrees, qreal maxDegrees, QRectF &sceneRect, Node *upwardFromThis) {
    QSet<Node *> childNodes = node->children();
    const int childSize = 30;
    int numChildren = childNodes.count();
    if (upwardFromThis && node->parent())
        numChildren++;

    qreal degreesPerChild;
    if (numChildren > 0) {
        degreesPerChild = maxDegrees / (numChildren);

        startingDegrees = startingDegrees - maxDegrees/2 + maxDegrees/(numChildren+1);
        foreach(Node *child, childNodes) {
            if (upwardFromThis == 0 || upwardFromThis != child) {
                qreal childX = startX + childSize*2*cos(startingDegrees);
                qreal childY = startY + childSize*2*sin(startingDegrees);
                layoutCircleNode(child, childX, childY, startingDegrees, degreesPerChild, sceneRect);
                startingDegrees += degreesPerChild;
            }
        }
        if (upwardFromThis && node->parent()){
            qreal childX = startX + childSize*2*cos(startingDegrees);
            qreal childY = startY + childSize*2*sin(startingDegrees);
            layoutCircleNode(node->parent(), childX, childY, startingDegrees, degreesPerChild, sceneRect, node);
            startingDegrees += degreesPerChild;
        }
    }

    if (scene() && scene()->mouseGrabberItem() == node) {
        return;
    }

    sceneRect.setTopLeft(QPointF(qMin(sceneRect.left(), startX), qMin(sceneRect.top(), startY)));
    sceneRect.setBottomRight(QPointF(qMax(sceneRect.right(), startX), qMax(sceneRect.bottom(), startY)));
    QPointF newpos(startX, startY);
    node->setNewPos(newpos);
    if (! m_animateNodeMovements)
        node->setPos(newpos);
}

void GraphWidget::doLookup(QString src) {
    doActualLookup(src, m_lookupType);
}

void GraphWidget::addRootNode(QString newNode) {
    myScene->addItem(new Node(this, newNode));
}

void GraphWidget::doActualLookup(const QString &lookupString, int lookupType)
{
    val_status_t val_status;
    struct addrinfo *aitop = NULL;
    int ret;
    u_char buf[4096];
    Node *node = 0;

    busy();

    // perform the lookup
    ret = val_res_query(NULL, lookupString.toUtf8(), 1,
                        lookupType, buf, sizeof(buf), &val_status);

    // do something with the results
    if (ret <= 0) {
        // XXX: indicate an error somehow

        if (!val_istrusted(val_status)) {
            // untrusted error for host
        }
        if (!val_istrusted(val_status)) {
            // untrusted for ip address
        }

        //setSecurityStatus(val_status);
    } else {
        QColor color;
        node = m_nodeList->node(lookupString);
        DNSData::Status result;

        if (val_isvalidated(val_status)) {
            result = DNSData::VALIDATED;
        } else if (val_istrusted(val_status)) {
            result = DNSData::TRUSTED;
        } else {
            result = DNSData::FAILED;
        }

        QStringList dataThere = DNSResources::dnsDataToQStringList((char *) buf, ret);

        node->addSubData(DNSData(DNSResources::typeToRRName(lookupType), result, dataThere));
    }

    QString lastInterestingString;

    foreach(QString logMessage, val_log_strings) {
        m_logWatcher->parseLogMessage(logMessage);
    }
    val_log_strings.clear();
    if (node)
        m_nodeList->reApplyFiltersTo(node);

    if (aitop)
        val_freeaddrinfo(aitop);
    unbusy();
}

void GraphWidget::setShowNSEC3Records(bool newVal) {
    m_shownsec3 = newVal;
}

void GraphWidget::unbusy() {
    viewport()->setCursor(Qt::ArrowCursor);
}

void GraphWidget::busy() {
    viewport()->setCursor(Qt::WaitCursor);
    viewport()->repaint();
}

void GraphWidget::setLockedNodes(bool newVal) {
    m_lockNodes = newVal;
    if (!m_lockNodes)
        itemMoved();
}

void GraphWidget::toggleLockedNodes() {
    m_lockNodes = !m_lockNodes;
    if (!m_lockNodes)
        itemMoved();
}

void GraphWidget::setLayoutType(LayoutType layoutType)
{
    m_layoutType = layoutType;
    reLayout();
}

void GraphWidget::setInfo(const QString &text)
{
    m_nodeInfoLabel->show();
    m_infoMoreButton->show();
    m_infoMoreButton->setEnabled(true);
    m_infoLabel->setText(text);
}

void GraphWidget::hideInfo()
{
    m_nodeInfoLabel->hide();
    m_infoLabel->setText("");
    m_infoMoreButton->setEnabled(false);
}

void GraphWidget::setInfo(Node *node) {
    QString buildString;
    Node *nodeIterator = node;
    while (nodeIterator && nodeIterator->nodeName() != "<root>") {
        buildString = (buildString.isEmpty() ? "" : buildString + ".") + nodeIterator->nodeName();
        nodeIterator = nodeIterator->parent();
    }
#ifdef ADD_ADDITIONAL_INFO_IN
    if (node->additionalInfo().length() > 0) {
        buildString += " (" + node->additionalInfo() + ")";
    }
    buildString += + "[" + node->getSubData() + "]";
#endif
    setInfo(buildString);
    m_nodeList->setSelectedNode(node);
}

void GraphWidget::moreInfoButton() {
    if (m_nodeList->selectedNode()) {
        Node *node = m_nodeList->selectedNode();
        node->displayDetailsMenu(m_infoMoreButton->mapToGlobal(QPoint(0,0)));
    }
}

void GraphWidget::createStartingNode()
{
    Node *centerNode = new Node(this, "<root>", 0);
    m_nodeList->setCenterNode(centerNode);
    scene()->addItem(centerNode);
    centerNode->addSubData(DNSData("DNSKEY", DNSData::TRUSTED));
}

void GraphWidget::openPreviousLogFile(int which) {
    if (which > m_previousFiles.count()) {
        QMessageBox uhoh;
        uhoh.setText("Critical Error: I can't find which file to open.  Please report this bug.");
        uhoh.exec();
        return;
    }

    QString whichFile = m_previousFiles[which];
    selectAndOpenLogFile(whichFile);
}

void GraphWidget::openThisLogFile(QString logFile, bool skipToEnd) {
    QSettings settings("DNSSEC-Tools", "dnssec-nodes");

    settings.setValue("logFile", logFile);
    if (logFile.length() > 0) {
        bool oldAnimate = m_animateNodeMovements;
        m_animateNodeMovements = false;
        m_logWatcher->parseLogFile(logFile, skipToEnd);
        m_animateNodeMovements = oldAnimate;
    }

    m_previousFiles.removeAll(logFile);
    m_previousFiles.push_front(logFile);

    while (m_previousFiles.count() > maxHistory) {
        m_previousFiles.pop_back();
    }

    settings.beginWriteArray("previousLogFiles", m_previousFiles.count());
    int i = 0;
    foreach (QString fileName, m_previousFiles) {
        settings.setArrayIndex(i++);
        settings.setValue("previousFile", fileName);
    }
    settings.endArray();

    setPreviousFileList();
}

void GraphWidget::setPreviousFileList(QMenu *menu) {
    QSettings settings("DNSSEC-Tools", "dnssec-nodes");
    QAction   *action;
    m_previousFiles.clear();

    // default to the previously saved menu
    if (!menu && m_previousFileMenu)
        menu = m_previousFileMenu;
    if (menu)
        menu->clear();

    int size = settings.beginReadArray("previousLogFiles");
    for(int i = 0; i < size; i++) {
        settings.setArrayIndex(i);
        m_previousFiles.push_back(settings.value("previousFile").toString());
        if (menu) {
            action = menu->addAction(m_previousFiles.last());
            connect(action, SIGNAL(triggered()), &m_mapper, SLOT(map()));
            m_mapper.setMapping(action, i);
        }
    }

    // save for future reloading
    if (!m_previousFileMenu) {
        connect(&m_mapper, SIGNAL(mapped(int)), this, SLOT(openPreviousLogFile(int)));
    }
    m_previousFileMenu = menu;
}

#ifdef WITH_PCAP
PcapWatcher *GraphWidget::pcapWatcher()
{
    return m_pcapWatcher;
}
#endif

void GraphWidget::openLogFile() {
    selectAndOpenLogFile();
}

void GraphWidget::selectAndOpenLogFile(QString defaultLogFile) {
    if (defaultLogFile.isEmpty()) {
        QSettings settings("DNSSEC-Tools", "dnssec-nodes");
        defaultLogFile = settings.value("logFile", QString("/var/log/libval.log")).toString();
    }

    LogFilePicker filePicker(defaultLogFile);
    if (!filePicker.exec())
        return;

    openThisLogFile(filePicker.file(), filePicker.skipToEnd());

}

void GraphWidget::showPrefs()
{
    QSettings settings("DNSSEC-Tools", "dnssec-nodes");
    NodesPreferences prefs(&settings);
    prefs.exec();
    if (prefs.result() == QDialog::Accepted) {
        setPrefs();
    }
}

void GraphWidget::setPrefs()
{
    QSettings settings("DNSSEC-Tools", "dnssec-nodes");
    m_nodeList->setMaxNodes(settings.value("maxNodes", 1).toInt());
    m_nodeList->setEnableMaxNodes(settings.value("enableTimeNodes", false).toBool());

    m_nodeList->setMaxTime(settings.value("maxTime", 1).toInt());
    m_nodeList->setEnableMaxTime(settings.value("enableMaxNodes", false).toBool());

    m_animateNodeMovements = settings.value("animateNodes", true).toBool();
    m_autoValidateServFails = settings.value("autoValidateServFails", false).toBool();
    m_updateLineEditAlways = settings.value("updateLineEdit", false).toBool();

    setUseStraightValidationLines(settings.value("useStraightValidationLines", false).toBool());
    setUseToggledValidationBoxes(settings.value("useToggledValidationBoxes", false).toBool());
}

void GraphWidget::saveUseStraightValidationLinesPref() {
    QSettings settings("DNSSEC-Tools", "dnssec-nodes");
    settings.setValue("useStraightValidationLines", useStraightValidationLines());
}

void GraphWidget::saveUseToggledValidationBoxes() {
    QSettings settings("DNSSEC-Tools", "dnssec-nodes");
    settings.setValue("useToggledValidationBoxes", useToggledValidationBoxes());
}

void GraphWidget::setAnimateNodeMovements(bool newValue) {
    m_animateNodeMovements = newValue;
    QSettings settings("DNSSEC-Tools", "dnssec-nodes");
    settings.setValue("animateNodes", newValue);
}

void GraphWidget::setUpdateLineEditAlways(bool newValue) {
    m_updateLineEditAlways = newValue;
    QSettings settings("DNSSEC-Tools", "dnssec-nodes");
    settings.setValue("updateLineEdit", newValue);
}

void GraphWidget::setAutoValidateServFails(bool newValue) {
    m_autoValidateServFails = newValue;
    QSettings settings("DNSSEC-Tools", "dnssec-nodes");
    settings.setValue("autoValidateServFails", newValue);
}

bool GraphWidget::animateNodeMovements() {
    return m_animateNodeMovements;
}

bool GraphWidget::updateLineEditAlways() {
    return m_updateLineEditAlways;
}

bool GraphWidget::autoValidateServFails() {
    return m_autoValidateServFails;
}

void GraphWidget::about()
{
    QMessageBox msgBox;
    msgBox.setWindowTitle("About DNSSEC-Nodes");
    msgBox.setText("<img src=\":/icons/dnssec-nodes-64x64.png\" style=\"float: right\"/>"
                   "<h1>DNSSEC-Nodes</h1><p><i>A component of the DNSSEC-Tools Project</i></p><p>For more information, please visit http://www.dnssec-tools.org/.</i></p>"
                   "<p>DNSSEC-Tools Version: 2.2</p>");
    msgBox.setStandardButtons(QMessageBox::Close);
    msgBox.exec();
}

void GraphWidget::help()
{
    QMessageBox msgBox;
    msgBox.setWindowTitle("DNSSEC-Nodes Help");
    msgBox.setText("<img src=\":/icons/dnssec-nodes-64x64.png\" style=\"float: right\"/>"
                   "<h1>DNSSEC-Nodes Help</h1><p>The DNSSEC-Nodes application is a DNS debugging and visualizing tool.  This tool will allow you to:"
                   "<ul><li>Load and analyize DNSSEC-Tools and Bind log files<li>"
                   "<li>Visually display and interact with collected DNS Data<li>"
                   "<li>Filter DNS nodes based on its status or name</li>"
                   "</ul>"
                   "<p>For a full list of features and usage instructions, please visit DNSSEC-Nodes section of the DNSSEC-Tools Wiki Page at: <br />"
                   "https://www.dnssec-tools.org/wiki/index.php?title=DNSSEC-Nodes</p>"
                   );
    msgBox.setStandardButtons(QMessageBox::Close);
    msgBox.exec();
}

void GraphWidget::legend()
{
    if (!m_legend)
        m_legend = new Legend(this);
    m_legend->show();
}

void GraphWidget::setLookupType(int type)
{
    m_lookupType = type;
    doLookupFromLineEdit();
}
