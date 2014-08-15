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

#ifndef GRAPHWIDGET_H
#define GRAPHWIDGET_H

#include <QGraphicsView>
#include <QLineEdit>
#include <QHBoxLayout>
#include <QLabel>
#include <QString>
#include <QRegExp>
#include <QMap>
#include <QPair>
#include <QTextStream>
#include <QFile>
#include <QList>
#include <QSignalMapper>
#include <QPushButton>
#include <QTableWidget>
#include <QWidget>

#include <sys/time.h>

#include "Legend.h"
#include "DNSData.h"
#include "qtauto_properties.h"

class Node;
class Edge;
class LogWatcher;
class NodeList;
class PcapWatcher;
class DNSData;

//! [0]
class GraphWidget : public QGraphicsView
{
    Q_OBJECT

public:
    GraphWidget(QWidget *parent = 0, QLineEdit *editor = 0, QTabWidget *tabs = 0, const QString &fileName = "", QHBoxLayout *infoBox = 0);

    enum LayoutType { springyLayout, treeLayout, circleLayout };

    void itemMoved();

    void createStartingNode();
    Node *addNode(const QString &nodeName, const QString &parentName = "", int depth=0);

    void busy();
    void unbusy();
    void doActualLookup(const QString &lookupString, int lookupType = 1); // default is type "A"

    void addItem(QGraphicsItem *newItem);
    void removeItem(QGraphicsItem *removeThis);

    void parseLogMessage(QString logMessage);

    qreal nodeScale() { return m_nodeScale; }
    bool isLocked() { return m_lockNodes; }

    int layoutTreeNode(Node *node, int minX, int minY);
    void layoutCircleNode(Node *node, qreal startX, qreal startY, qreal startingDegrees, qreal maxDegrees, QRectF &sceneRect, Node *upwardFromThis = 0);

    LayoutType layoutType() { return m_layoutType; }
    void setLayoutType(LayoutType layoutType);

    void setInfo(const QString &text);
    void setInfo(Node *node);
    void hideInfo();

    LogWatcher *logWatcher() { return m_logWatcher; }
    NodeList   *nodeList() { return m_nodeList; }

    void setPrefs();
    bool animateNodeMovements();

    void openThisLogFile(QString logFile, bool skipToEnd = false);
    void setPreviousFileList(QMenu *menu = 0);

    QTabWidget *tabs() { return m_tabs; }

#ifdef WITH_PCAP
    PcapWatcher *pcapWatcher();
#endif

    bool updateLineEditAlways();
    bool autoValidateServFails();

public slots:
    void shuffle();
    void zoomIn();
    void zoomOut();

    void reLayout();
    void layoutInTree();
    void layoutInCircles();
    void switchToTree();
    void switchToCircles();

    void addRootNode(QString newNode);
    void resetStartingNode();
    void doLookupFromLineEdit();
    void doLookup(QString lookupString);
    void doLookupFromServFail(QString nodeName, DNSData nodeData, QString optionalLogMessage);
    void setLookupType(int type);
    void scaleWindow();
    void resizeEvent(QResizeEvent *event);
    void openLogFile();
    void selectAndOpenLogFile(QString defaultLogFile = "");
    void openPreviousLogFile(int which);

    void toggleLockedNodes();
    void setLockedNodes(bool newVal);
    void setShowNSEC3Records(bool newVal);
    void setAnimateNodeMovements(bool newValue);

    void setUpdateLineEditAlways(bool newValue);
    void setAutoValidateServFails(bool newValue);
    void setLineEditValue(const QString &value);
    void maybeSetLineEditValue(const QString &value);

    void saveUseStraightValidationLinesPref();
    void saveUseToggledValidationBoxes();

    bool showNsec3() { return m_shownsec3; }

    void showPrefs();
    void moreInfoButton();

    void legend();
    void about();
    void help();

signals:
    void openPcapDevice();

protected:
    void keyPressEvent(QKeyEvent *event);
    void timerEvent(QTimerEvent *event);
    void wheelEvent(QWheelEvent *event);
    void drawBackground(QPainter *painter, const QRectF &rect);

    void scaleView(qreal scaleFactor);

private:
    int timerId;

    QGraphicsScene *myScene;
    QLineEdit   *m_editor;
    QString      m_libValDebugLog;
    qreal        m_nodeScale;
    bool         m_localScale;
    bool         m_lockNodes;
    bool         m_shownsec3;
    QTimer      *m_timer;
    LayoutType   m_layoutType;
    int          m_childSize;
    int          m_lookupType;
    bool         m_animateNodeMovements;
    bool         m_updateLineEditAlways;
    bool         m_autoValidateServFails;

    QHBoxLayout *m_infoBox;
    QLabel      *m_infoLabel;
    QPushButton *m_infoMoreButton;
    QLabel      *m_nodeInfoLabel;
    QMenu       *m_previousFileMenu;
    QSignalMapper m_mapper;

    // NodeList *MUST* come before LogWatcher in init calls
    NodeList    *m_nodeList;
    LogWatcher  *m_logWatcher;

    QStringList  m_previousFiles;

    Legend      *m_legend;



    QTabWidget  *m_tabs;

    QTAUTO_GET_SET_SIGNAL(bool, useStraightValidationLines);
    QTAUTO_GET_SET_SIGNAL(bool, useToggledValidationBoxes);
    QTAUTO_GET_SET_SIGNAL(QString, startingNode);

    // QTAUTO_HERE
    /* AGST */ Q_PROPERTY(bool useStraightValidationLines READ useStraightValidationLines WRITE setUseStraightValidationLines NOTIFY useStraightValidationLinesChanged) public: const bool &useStraightValidationLines() const { return m_useStraightValidationLines; } signals: void useStraightValidationLinesChanged(); void useStraightValidationLinesChanged(bool); public slots: void setUseStraightValidationLines(const bool &newval) { if (newval != m_useStraightValidationLines) { QTAUTO_DEBUG("setting new value for " << QTAUTO_STRING(useStraightValidationLines) << " " << m_useStraightValidationLines << " => " << newval); m_useStraightValidationLines = newval; emit useStraightValidationLinesChanged(); emit useStraightValidationLinesChanged(newval); } } private: bool m_useStraightValidationLines;
    /* AGST */ Q_PROPERTY(bool useToggledValidationBoxes READ useToggledValidationBoxes WRITE setUseToggledValidationBoxes NOTIFY useToggledValidationBoxesChanged) public: const bool &useToggledValidationBoxes() const { return m_useToggledValidationBoxes; } signals: void useToggledValidationBoxesChanged(); void useToggledValidationBoxesChanged(bool); public slots: void setUseToggledValidationBoxes(const bool &newval) { if (newval != m_useToggledValidationBoxes) { QTAUTO_DEBUG("setting new value for " << QTAUTO_STRING(useToggledValidationBoxes) << " " << m_useToggledValidationBoxes << " => " << newval); m_useToggledValidationBoxes = newval; emit useToggledValidationBoxesChanged(); emit useToggledValidationBoxesChanged(newval); } } private: bool m_useToggledValidationBoxes;
    /* AGST */ Q_PROPERTY(QString startingNode READ startingNode WRITE setStartingNode NOTIFY startingNodeChanged) public: const QString &startingNode() const { return m_startingNode; } signals: void startingNodeChanged(); void startingNodeChanged(QString); public slots: void setStartingNode(const QString &newval) { if (newval != m_startingNode) { QTAUTO_DEBUG("setting new value for " << QTAUTO_STRING(startingNode) << " " << m_startingNode << " => " << newval); m_startingNode = newval; emit startingNodeChanged(); emit startingNodeChanged(newval); } } private: QString m_startingNode;

#ifdef WITH_PCAP
    PcapWatcher *m_pcapWatcher;
#endif
public:
};
//! [0]

#endif
