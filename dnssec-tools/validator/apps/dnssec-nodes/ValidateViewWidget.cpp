#include "ValidateViewWidget.h"

#include <QtGui/QGraphicsRectItem>
#include <QtGui/QGraphicsSimpleTextItem>

#include <validator/validator-config.h>
#include <validator/validator.h>

#include <qdebug.h>

ValidateViewWidget::ValidateViewWidget(QString nodeName, QString recordType, QWidget *parent) :
    QGraphicsView(parent), m_nodeName(nodeName), m_recordType(recordType), m_typeToName()
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

    const int spacing = 50;
    const int boxWidth = 400;
    const int boxHeight = 100;
    const int boxTopMargin = 10;
    const int boxLeftMargin = 10;
    const int verticalBoxDistance = spacing + boxHeight;
    const int boxHorizMiddle = boxLeftMargin + boxWidth/2;
    const int arrowHalfWidth = 10;


    int ret;
    ret = val_resolve_and_check(NULL, name.toAscii().data(), 1, ns_t_a,
                                VAL_QUERY_RECURSE | VAL_QUERY_AC_DETAIL |
                                VAL_QUERY_SKIP_CACHE,
                                &results);
    qDebug() << "got here: result = " << ret;
    if (ret != 0 || !results) {
        qWarning() << "failed to get results..."; // XXX: display SOMETHING!
        return;
    }

    int spot = 0;
    int maxWidth = 0;
    QGraphicsRectItem        *rect = 0;
    QGraphicsSimpleTextItem  *text;
    struct val_rr_rec *rrrec;

    // for each authentication record, display a horiz row of data
    for(vrcptr = results->val_rc_answer->val_ac_trust; vrcptr; vrcptr = vrcptr->val_ac_trust) {
        int horizontalSpot = boxLeftMargin;

        // for each rrset in an auth record, display a box
        for(rrrec = vrcptr->val_ac_rrset->val_rrset_data; rrrec; rrrec = rrrec->rr_next) {
            qDebug() << "chain: " << vrcptr->val_ac_rrset->val_rrset_name << " -> " << vrcptr->val_ac_rrset->val_rrset_type;

            rect = new QGraphicsRectItem(horizontalSpot, spot+boxTopMargin, boxWidth, boxHeight);
            rect->setPen(QPen(Qt::black));
            myScene->addItem(rect);

            if (m_typeToName.contains(vrcptr->val_ac_rrset->val_rrset_type))
                text = new QGraphicsSimpleTextItem(m_typeToName[vrcptr->val_ac_rrset->val_rrset_type]);
            else
                text = new QGraphicsSimpleTextItem("(type unknown)");
            text->setPen(QPen(Qt::black));
            text->setPos(boxLeftMargin + horizontalSpot, spot+boxHeight/2);
            text->setScale(2.0);
            myScene->addItem(text);

            text = new QGraphicsSimpleTextItem(vrcptr->val_ac_rrset->val_rrset_name);
            text->setPen(QPen(Qt::black));
            text->setPos(boxLeftMargin + horizontalSpot, spot + boxTopMargin * 2);
            text->setScale(2.0);
            myScene->addItem(text);

            if (spot != 0) {
                // add an arrow
                int polyVertStartSpot = spot + boxHeight + spacing + boxTopMargin;

                QGraphicsLineItem *line = new QGraphicsLineItem(boxLeftMargin + boxWidth/2,
                                                                spot + boxHeight + boxTopMargin,
                                                                boxLeftMargin + boxWidth/2, polyVertStartSpot);
                myScene->addItem(line);

                QPolygon polygon;
                polygon << QPoint(boxHorizMiddle, polyVertStartSpot)
                        << QPoint(boxHorizMiddle - arrowHalfWidth, polyVertStartSpot - arrowHalfWidth)
                        << QPoint(boxHorizMiddle + arrowHalfWidth, polyVertStartSpot - arrowHalfWidth);
                QGraphicsPolygonItem *polyItem = new QGraphicsPolygonItem(polygon);
                polyItem->setBrush(QBrush(Qt::black));
                polyItem->setFillRule(Qt::OddEvenFill);
                myScene->addItem(polyItem);
            }

            horizontalSpot += boxWidth + boxLeftMargin;
            maxWidth = qMax(maxWidth, horizontalSpot);
        }

        spot -= verticalBoxDistance;
    }

    myScene->setSceneRect(0, spot + boxHeight, maxWidth, -spot + boxHeight);
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
