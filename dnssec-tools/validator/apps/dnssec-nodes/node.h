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

#ifndef NODE_H
#define NODE_H

#include <QtGui/QGraphicsItem>
#include <QtCore/QList>
#include <QtCore/QSet>

#include "DNSData.h"

class Edge;
class GraphWidget;
QT_BEGIN_NAMESPACE
class QGraphicsSceneMouseEvent;
QT_END_NAMESPACE

//! [0]
class Node : public QGraphicsItem
{
public:
    Node(GraphWidget *graphWidget, const QString &nodeName = "", const QString &fqdn = "", int depth = 0);

    void addEdge(Edge *edge);
    QSet<Edge *> edges() const;
    void removeEdge(Edge *edge);

    void addChild(Node *child);
    QSet<Node *> children();
    bool hasChildren();
    void removeChild(Node *child);

    void addParent(Node *parent);
    Node *parent();

    void addLogMessage(const QString logMessage);
    QStringList logMessages();

    enum { Type = UserType + 1 };
    int type() const { return Type; }
    QString nodeName() { return m_nodeName; }
    QString fqdn() { return m_fqdn; }

    void setNewPos(QPointF pos);
    void calculateForces();
    bool advance();

    QRectF boundingRect() const;
    QPainterPath shape() const;
    void paint(QPainter *painter, const QStyleOptionGraphicsItem *option, QWidget *widget);

    void setColor(const QColor &color);
    void setAdditionalInfo(const QString &info);
    QString additionalInfo() const;

    void addSubData(const DNSData &data);
    QString getSubData();

    int accessCount() { return m_accessCount; }
    void setAccessCount(int accessCount) { m_accessCount = accessCount; }

    time_t accessTime() { return m_accessTime; }
    void setAccessTime(time_t newTime) { m_accessTime = newTime; }

protected:
    QVariant itemChange(GraphicsItemChange change, const QVariant &value);

    void mousePressEvent(QGraphicsSceneMouseEvent *event);
    void mouseReleaseEvent(QGraphicsSceneMouseEvent *event);
    
private:
    QSet<Edge *> edgeList;
    QSet<Node *> m_children;
    Node         *m_parent;
    QPointF newPos;
    GraphWidget *graph;
    QString      m_nodeName;
    QString      m_fqdn;
    int          m_depth;
    QColor       m_color;
    QStringList  m_logMessages;
    QString      m_additionalInfo;
    QMap<QString, DNSData>  m_subData;
    int            m_accessCount;
    time_t         m_accessTime;
};
//! [0]

#endif
