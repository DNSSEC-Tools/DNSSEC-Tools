#include "ValidateViewWidget.h"

#include <QtGui/QGraphicsRectItem>
#include <QtGui/QGraphicsSimpleTextItem>

#include <validator/validator-config.h>
#include <validator/validator.h>

#include <qdebug.h>

ValidateViewWidget::ValidateViewWidget(QString nodeName, QString recordType, QWidget *parent) :
    QGraphicsView(parent), m_nodeName(nodeName), m_recordType(recordType)
{
    myScene = new QGraphicsScene(this);
    myScene->setItemIndexMethod(QGraphicsScene::NoIndex);
    myScene->setSceneRect(0, 0, 600, 600);
    setScene(myScene);
    setCacheMode(CacheBackground);
    setViewportUpdateMode(BoundingRectViewportUpdate);
    setRenderHint(QPainter::Antialiasing);
    setTransformationAnchor(AnchorUnderMouse);
    setDragMode(QGraphicsView::ScrollHandDrag);
    setWindowTitle(tr("Validation of %1 for %2").arg(nodeName).arg(recordType));
    //scaleWindow();

    m_typeToName[1] = "A";
    m_typeToName[2] = "NS";
    m_typeToName[5] = "CNAME";
    m_typeToName[6] = "SOA";
    m_typeToName[12] = "PTR";
    m_typeToName[15] = "MX";
    m_typeToName[16] = "TXT";
    m_typeToName[28] = "AAAA";
    m_typeToName[33] = "SRV";
    m_typeToName[255] = "ANY";

    m_typeToName[43] = "DS";
    m_typeToName[46] = "RRSIG";
    m_typeToName[47] = "NSEC";
    m_typeToName[48] = "DNSKEY";
    m_typeToName[50] = "NSEC3";
    m_typeToName[32769] = "DLV";

    m_typeToName[3] = "MD";
    m_typeToName[4] = "MF";
    m_typeToName[7] = "MB";
    m_typeToName[8] = "MG";
    m_typeToName[9] = "MR";
    m_typeToName[10] = "NULL";
    m_typeToName[11] = "WKS";
    m_typeToName[13] = "HINFO";
    m_typeToName[14] = "MINFO";
    m_typeToName[17] = "RP";
    m_typeToName[18] = "AFSDB";
    m_typeToName[19] = "X25";
    m_typeToName[20] = "ISDN";
    m_typeToName[21] = "RT";
    m_typeToName[22] = "NSAP";
    m_typeToName[23] = "NSAP_PTR";
    m_typeToName[24] = "SIG";
    m_typeToName[25] = "KEY";
    m_typeToName[26] = "PX";
    m_typeToName[27] = "GPOS";
    m_typeToName[29] = "LOC";
    m_typeToName[30] = "NXT";
    m_typeToName[31] = "EID";
    m_typeToName[32] = "NIMLOC";
    m_typeToName[34] = "ATMA";
    m_typeToName[35] = "NAPTR";
    m_typeToName[36] = "KX";
    m_typeToName[37] = "CERT";
    m_typeToName[38] = "A6";
    m_typeToName[39] = "DNAME";
    m_typeToName[40] = "SINK";
    m_typeToName[41] = "OPT";
    m_typeToName[250] = "TSIG";
    m_typeToName[251] = "IXFR";
    m_typeToName[252] = "AXFR";
    m_typeToName[253] = "MAILB";
    m_typeToName[254] = "MAILA";

    scaleView(.5);
    validateSomething(m_nodeName, m_recordType);
}

void ValidateViewWidget::scaleView(qreal scaleFactor)
{
    qreal factor = transform().scale(scaleFactor, scaleFactor).mapRect(QRectF(0, 0, 1, 1)).width();
    if (factor < 0.07 || factor > 100)
        return;

    scale(scaleFactor, scaleFactor);
}

void ValidateViewWidget::validateSomething(QString name, QString type) {
    val_result_chain                *results = 0;
    struct val_authentication_chain *vrcptr = 0;

    int ret;
    ret = val_resolve_and_check(NULL, name.toAscii().data(), 1, ns_t_a,
                                VAL_QUERY_RECURSE | VAL_QUERY_AC_DETAIL |
                                VAL_QUERY_SKIP_CACHE,
                                &results);
    qDebug() << "got here: result = " << ret;

    int spot = 0;
    QGraphicsRectItem        *rect = 0;
    QGraphicsSimpleTextItem  *text;
    for(vrcptr = results->val_rc_answer->val_ac_trust; vrcptr; vrcptr = vrcptr->val_ac_trust) {
        qDebug() << "chain: " << vrcptr->val_ac_rrset->val_rrset_name << " -> " << vrcptr->val_ac_rrset->val_rrset_type;

        rect = new QGraphicsRectItem(10,spot+10,100,100);
        rect->setPen(QPen(Qt::black));
        myScene->addItem(rect);

        if (m_typeToName.contains(vrcptr->val_ac_rrset->val_rrset_type))
            text = new QGraphicsSimpleTextItem(m_typeToName[vrcptr->val_ac_rrset->val_rrset_type]);
        else
            text = new QGraphicsSimpleTextItem("(type unknown)");
        text->setPen(QPen(Qt::black));
        text->setPos(20,spot+50);
        text->setScale(2.0);
        myScene->addItem(text);

        text = new QGraphicsSimpleTextItem(vrcptr->val_ac_rrset->val_rrset_name);
        text->setPen(QPen(Qt::black));
        text->setPos(20,spot+20);
        text->setScale(2.0);
        myScene->addItem(text);

        if (spot != 0) {
            // add an arrow
            QGraphicsLineItem *line = new QGraphicsLineItem(10+100/2, spot-150+100+10, 10+100/2, spot+10);
            myScene->addItem(line);

            QPolygon polygon;
            polygon << QPoint(10+100/2, spot+10)
                    << QPoint(10+100/2 - 10, spot)
                    << QPoint(10+100/2 + 10, spot);
            QGraphicsPolygonItem *polyItem = new QGraphicsPolygonItem(polygon);
            polyItem->setBrush(QBrush(Qt::black));
            polyItem->setFillRule(Qt::OddEvenFill);
            myScene->addItem(polyItem);
        }

        spot += 150;
    }

    myScene->setSceneRect(0, 0, 600, spot);
    if (rect)
        ensureVisible(rect);
}

#ifdef maybe
QPair<QGraphicsRectItem *, QGraphicsSimpleTextItem *>
ValidateViewWidget::createRecordBox(struct val_authentication_chain *auth_chain, int spot) {
    QGraphicsRectItem        *rect = new QGraphicsRectItem(10,spot,100,100);
    QGraphicsSimpleTextItem  *text = new QGraphicsSimpleTextItem(auth_chain->val_rrset_name);
    return
}
#endif
