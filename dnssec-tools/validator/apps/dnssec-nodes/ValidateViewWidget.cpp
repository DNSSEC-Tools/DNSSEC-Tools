#include "ValidateViewWidget.h"

#include <QGraphicsRectItem>
#include <QGraphicsSimpleTextItem>
#include <QTimer>

#include <validator/validator-config.h>
#include <validator/validator.h>

#include <qdebug.h>

#include "DNSResources.h"
#include "DNSData.h"
#include <math.h>
#include <QWheelEvent>
#include <QApplication>

#define RES_GET16(s, cp) do { \
        register const u_char *t_cp = (const u_char *)(cp); \
        (s) = ((u_int16_t)t_cp[0] << 8) \
            | ((u_int16_t)t_cp[1]) \
            ; \
        (cp) += NS_INT16SZ; \
} while (0)

#define RES_GET32(l, cp) do { \
        register const u_char *t_cp = (const u_char *)(cp); \
        (l) = ((u_int32_t)t_cp[0] << 24) \
            | ((u_int32_t)t_cp[1] << 16) \
            | ((u_int32_t)t_cp[2] << 8) \
            | ((u_int32_t)t_cp[3]) \
            ; \
        (cp) += NS_INT32SZ; \
} while (0)

// from ns_print.c
extern "C" {
u_int16_t id_calc(const u_char * key, const int keysize);
}

ValidateViewWidget::ValidateViewWidget(QString nodeName, QString recordType, GraphWidget *graphWidget, QWidget *parent) :
    QGraphicsView(parent), m_graphWidget(graphWidget), m_nodeName(nodeName), m_recordType(recordType), m_statusToName(),
    m_useStraightLines(false)
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

    m_statusToName[VAL_AC_UNSET] = "UNSET";
    m_statusToName[VAL_AC_CAN_VERIFY] = "CAN_VERIFY";
    m_statusToName[VAL_AC_WAIT_FOR_TRUST] = "WAIT_FOR_TRUST";
    m_statusToName[VAL_AC_WAIT_FOR_RRSIG] = "WAIT_FOR_RRSIG";
    m_statusToName[VAL_AC_TRUST_NOCHK] = "TRUST_NOCHK";
    m_statusToName[VAL_AC_INIT] = "INIT";
    m_statusToName[VAL_AC_NEGATIVE_PROOF] = "NEGATIVE_PROOF";
    m_statusToName[VAL_AC_DONT_GO_FURTHER] = "DONT_GO_FURTHER";
    m_statusToName[VAL_AC_IGNORE_VALIDATION] = "IGNORE_VALIDATION";
    m_statusToName[VAL_AC_UNTRUSTED_ZONE] = "UNTRUSTED_ZONE";
    m_statusToName[VAL_AC_PINSECURE] = "PINSECURE";
    m_statusToName[VAL_AC_BARE_RRSIG] = "BARE_RRSIG";
    m_statusToName[VAL_AC_NO_LINK] = "NO_LINK";
    m_statusToName[VAL_AC_TRUST_ANCHOR] = "TRUST_ANCHOR";
    m_statusToName[VAL_AC_TRUST] = "TRUST";
    m_statusToName[VAL_AC_LAST_STATE] = "LAST_STATE";
    m_statusToName[VAL_AC_ERROR_BASE] = "ERROR_BASE";
    m_statusToName[VAL_AC_RRSIG_MISSING] = "RRSIG_MISSING";
    m_statusToName[VAL_AC_DNSKEY_MISSING] = "DNSKEY_MISSING";
    m_statusToName[VAL_AC_DS_MISSING] = "DS_MISSING";
    m_statusToName[VAL_AC_LAST_ERROR] = "LAST_ERROR";
    m_statusToName[VAL_AC_BAD_BASE] = "BAD_BASE";
    m_statusToName[VAL_AC_DATA_MISSING] = "DATA_MISSING";
    m_statusToName[VAL_AC_DNS_ERROR] = "DNS_ERROR";
    m_statusToName[VAL_AC_LAST_BAD] = "LAST_BAD";
    m_statusToName[VAL_AC_FAIL_BASE] = "FAIL_BASE";
    m_statusToName[VAL_AC_NOT_VERIFIED] = "NOT_VERIFIED";
    m_statusToName[VAL_AC_WRONG_LABEL_COUNT] = "WRONG_LABEL_COUNT";
    m_statusToName[VAL_AC_INVALID_RRSIG] = "INVALID_RRSIG";
    m_statusToName[VAL_AC_RRSIG_NOTYETACTIVE] = "RRSIG_NOTYETACTIVE";
    m_statusToName[VAL_AC_RRSIG_EXPIRED] = "RRSIG_EXPIRED";
    m_statusToName[VAL_AC_RRSIG_VERIFY_FAILED] = "RRSIG_VERIFY_FAILED";
    m_statusToName[VAL_AC_RRSIG_ALGORITHM_MISMATCH] = "RRSIG_ALGORITHM_MISMATCH";
    m_statusToName[VAL_AC_DNSKEY_NOMATCH] = "DNSKEY_NOMATCH";
    m_statusToName[VAL_AC_UNKNOWN_DNSKEY_PROTOCOL] = "UNKNOWN_DNSKEY_PROTOCOL";
    m_statusToName[VAL_AC_DS_NOMATCH] = "DS_NOMATCH";
    m_statusToName[VAL_AC_INVALID_KEY] = "INVALID_KEY";
    m_statusToName[VAL_AC_INVALID_DS] = "INVALID_DS";
    m_statusToName[VAL_AC_ALGORITHM_NOT_SUPPORTED] = "ALGORITHM_NOT_SUPPORTED";
    m_statusToName[VAL_AC_LAST_FAILURE] = "LAST_FAILURE";
    m_statusToName[VAL_AC_VERIFIED] = "VERIFIED";
    m_statusToName[VAL_AC_RRSIG_VERIFIED] = "RRSIG_VERIFIED";
    m_statusToName[VAL_AC_WCARD_VERIFIED] = "WCARD_VERIFIED";
    m_statusToName[VAL_AC_RRSIG_VERIFIED_SKEW] = "RRSIG_VERIFIED_SKEW";
    m_statusToName[VAL_AC_WCARD_VERIFIED_SKEW] = "WCARD_VERIFIED_SKEW";
    m_statusToName[VAL_AC_TRUST_POINT] = "TRUST_POINT";
    m_statusToName[VAL_AC_SIGNING_KEY] = "SIGNING_KEY";
    m_statusToName[VAL_AC_VERIFIED_LINK] = "VERIFIED_LINK";
    m_statusToName[VAL_AC_UNKNOWN_ALGORITHM_LINK] = "UNKNOWN_ALGORITHM_LINK";

    m_statusColors[VAL_AC_RRSIG_VERIFIED] = Qt::green;

    // DS digest types
    m_digestToName[1] = "SHA-1";
    m_digestToName[2] = "SHA-256";
    m_digestToName[3] = "GOST R 34.11-94";
    m_digestToName[4] = "SHA-384";

    // DNSKEY algorithm types
    m_algorithmToName[1] = "RSA/MD5";
    m_algorithmToName[2] = "DH";
    m_algorithmToName[3] = "DSA/SHA1";
    m_algorithmToName[4] = "ECC";
    m_algorithmToName[5] = "RSA/SHA-1";
    m_algorithmToName[6] = "DSA-NSEC3-SHA1";
    m_algorithmToName[7] = "RSASHA1-NSEC3-SHA1";
    m_algorithmToName[8] = "RSA/SHA-256";
    m_algorithmToName[9] = "Unassigned";
    m_algorithmToName[10] = "RSA/SHA-512";
    m_algorithmToName[11] = "Unassigned";
    m_algorithmToName[12] = "ECC-GOST";
    m_algorithmToName[13] = "ECDSAP256SHA256";
    m_algorithmToName[14] = "ECDSAP384SHA384";

    scaleView(.4);

    viewport()->setCursor(Qt::WaitCursor);
    QTimer::singleShot(1, this, SLOT(validateDefault()));

    // XXX: these don't work - somewhere there is a missing piece
    connect(this, SIGNAL(useStraightLinesChanged()), this, SLOT(invalidateScene()));
    connect(this, SIGNAL(useStraightLinesChanged()), myScene, SLOT(invalidate()));
    connect(this, SIGNAL(useStraightLinesChanged()), myScene, SLOT(update()));
}

void ValidateViewWidget::scaleView(qreal scaleFactor)
{
    qreal factor = transform().scale(scaleFactor, scaleFactor).mapRect(QRectF(0, 0, 1, 1)).width();
    if (factor < 0.07 || factor > 100)
        return;

    scale(scaleFactor, scaleFactor);
}

void ValidateViewWidget::drawArrow(int fromX, int fromY, int toX, int toY, QColor color,
                                   ValidateViewBox *box, int horizRaiseMultiplier) {
    const int arrowHalfWidth = 10;

    QBrush brush(color);
    QPen   pen(color);


    if (fromY == toY) {
        // draw horizontal lines differently...  up -> across -> down
        if (useStraightLines()) {
            QGraphicsLineItem *line = new QGraphicsLineItem(fromX, fromY - horizRaiseMultiplier*arrowHalfWidth, toX, toY - horizRaiseMultiplier*arrowHalfWidth);
            line->setPen(pen);
            myScene->addItem(line);
            if (box)
                box->addLineObject(line, color);

            line = new QGraphicsLineItem(fromX, fromY, fromX, fromY - horizRaiseMultiplier*arrowHalfWidth);
            line->setPen(pen);
            myScene->addItem(line);
            if (box)
                box->addLineObject(line, color);

            line = new QGraphicsLineItem(toX, toY - horizRaiseMultiplier*arrowHalfWidth, toX, toY - arrowHalfWidth);
            line->setPen(pen);
            myScene->addItem(line);
            if (box)
                box->addLineObject(line, color);
        } else {
            QGraphicsPathItem *pathItem = new QGraphicsPathItem();
            QPainterPath path;
            path.moveTo(fromX, fromY);
            path.lineTo(fromX, fromY - arrowHalfWidth*2);
            path.quadTo(fromX, fromY - horizRaiseMultiplier*arrowHalfWidth, toX - (toX - fromX)/2, toY - horizRaiseMultiplier*arrowHalfWidth);
            path.quadTo(toX, toY - horizRaiseMultiplier*arrowHalfWidth, toX, toY - arrowHalfWidth*2);
            pathItem->setPen(pen);
            pathItem->setPath(path);
            myScene->addItem(pathItem);
            if (box)
                box->addPathObject(pathItem, color);
        }
    } else {
        if (useStraightLines()) {
            // draw line in 3 segments, two vertical stubs to make the arrow to triangle look better
            QGraphicsLineItem *line = new QGraphicsLineItem(fromX, fromY + 2*arrowHalfWidth, toX, toY - 2*arrowHalfWidth);
            line->setPen(pen);
            myScene->addItem(line);
            if (box)
                box->addLineObject(line, color);

            line = new QGraphicsLineItem(fromX, fromY, fromX, fromY + 2*arrowHalfWidth);
            line->setPen(pen);
            myScene->addItem(line);
            if (box)
                box->addLineObject(line, color);

            line = new QGraphicsLineItem(toX, toY - 2*arrowHalfWidth, toX, toY - arrowHalfWidth);
            line->setPen(pen);
            myScene->addItem(line);
            if (box)
                box->addLineObject(line, color);
        } else {
            QGraphicsPathItem *pathItem = new QGraphicsPathItem();
            QPainterPath path;
            path.moveTo(fromX, fromY);
            path.quadTo(fromX, fromY + (toY-fromY)/2, fromX + (toX-fromX)/2, fromY + (toY-fromY)/2);
            path.quadTo(toX, fromY + (toY-fromY)/2, toX, toY - arrowHalfWidth*2);

            pathItem->setPen(pen);
            pathItem->setPath(path);
            if (box)
                box->addPathObject(pathItem, color);
            myScene->addItem(pathItem);
        }
    }

    QPolygon polygon;
    polygon << QPoint(toX, toY)
            << QPoint(toX - arrowHalfWidth, toY - arrowHalfWidth*2)
            << QPoint(toX + arrowHalfWidth, toY - arrowHalfWidth*2);
    QGraphicsPolygonItem *polyItem = new QGraphicsPolygonItem(polygon);
    polyItem->setPen(pen);
    polyItem->setBrush(brush);
    polyItem->setFillRule(Qt::OddEvenFill);
    myScene->addItem(polyItem);
    if (box)
        box->addPathObject(polyItem, color);
}

void ValidateViewWidget::validateDefault() {
    validateSomething(m_nodeName, m_recordType);
}

void ValidateViewWidget::validateSomething(QString name, QString type) {
    val_result_chain                *results = 0;
    struct val_authentication_chain *vrcptr = 0;

    const int boxWidth = 500;
    const int boxHeight = 120;
    const int spacing = boxHeight*2;
    const int boxTopMargin = 10;
    const int boxLeftMargin = 10;
    const int boxHorizontalSpacing = 30;
    const int verticalBoxDistance = spacing + boxHeight;

    int ret;
    // XXX: use the type string to look up a user defined type
    ret = val_resolve_and_check(NULL, name.toLatin1().data(), 1, DNSResources::RRNameToType(type),
                                VAL_QUERY_ITERATE | VAL_QUERY_AC_DETAIL |
                                VAL_QUERY_SKIP_CACHE,
                                &results);
    if (ret != 0 || !results) {
        qWarning() << "failed to get results..."; // XXX: display SOMETHING!
        viewport()->setCursor(Qt::ArrowCursor);
        return;
    }

    m_graphWidget->nodeList()->node(name)->addSubData(DNSData(type, DNSData::getStatusFromValStatus(results->val_rc_status)));

    int spot = 0;
    int maxWidth = 0;
    ValidateViewBox          *rect = 0;
    QGraphicsSimpleTextItem  *text;
    struct val_rr_rec *rrrec;
    const u_char * rdata;

    QMap<int, QPair<int, int> > dnskeyIdToLocation;
    QMap<int, ValidateViewBox *> dnskeyIdToBox;
    QMap<QPair<int, int>, QPair<int, int> > dsIdToLocation;
    QMap<QPair<int, int>, ValidateViewBox *> dsIdToBox;
    QMap<int, int> dnsKeyToStatus;
    QMap<QPair<QString, int>, QList< QPair<int, int> > > nameAndTypeToLocation;
    QMap<QPair<QString, int>, QList<QPair<int, int> > > signedByList;

    // for each authentication record, display a horiz row of data
    for(vrcptr = results->val_rc_answer; vrcptr; vrcptr = vrcptr->val_ac_trust) {
        int horizontalSpot = boxLeftMargin;

        // for each rrset in an auth record, display a box
        // qDebug() << "chain: " << vrcptr->val_ac_rrset->val_rrset_name << " -> " << vrcptr->val_ac_rrset->val_rrset_type;

        // sort the data ahead of time to order them on the line in the best way possible (eg, put KSKs first)
        QList<struct val_rr_rec *> records;

        // add ksk keys first
        for(rrrec = vrcptr->val_ac_rrset->val_rrset_data; rrrec; rrrec = rrrec->rr_next) {
            if (vrcptr->val_ac_rrset->val_rrset_type == ns_t_dnskey && rrrec->rr_rdata[1] & 0x1) {
                if (rrrec->rr_status == VAL_AC_VERIFIED_LINK || rrrec->rr_status == VAL_AC_TRUST_POINT) // more interesting
                    records.push_front(rrrec);
                else
                    records.push_back(rrrec);
            }
        }

        // add zone keys that are used, followed by ones that aren't
        for(rrrec = vrcptr->val_ac_rrset->val_rrset_data; rrrec; rrrec = rrrec->rr_next) {
            if (vrcptr->val_ac_rrset->val_rrset_type == ns_t_dnskey && !(rrrec->rr_rdata[1] & 0x1)) {
                if (rrrec->rr_status == VAL_AC_DS_NOMATCH)
                    records.push_back(rrrec);
            }
        }
        for(rrrec = vrcptr->val_ac_rrset->val_rrset_data; rrrec; rrrec = rrrec->rr_next) {
            if (vrcptr->val_ac_rrset->val_rrset_type == ns_t_dnskey && !(rrrec->rr_rdata[1] & 0x1)) {
                if (rrrec->rr_status != VAL_AC_DS_NOMATCH)
                    records.push_back(rrrec);
            }
        }

        // add any other records
        for(rrrec = vrcptr->val_ac_rrset->val_rrset_data; rrrec; rrrec = rrrec->rr_next) {
            if (vrcptr->val_ac_rrset->val_rrset_type != ns_t_dnskey) {
                records.push_back(rrrec);
            }
        }

        foreach(struct val_rr_rec *rrrec, records) {
            QString nextLineText;

            rdata = rrrec->rr_rdata;

            // draw the bounding box of the record
            rect = new ValidateViewBox(horizontalSpot, spot+boxTopMargin, boxWidth, boxHeight, m_graphWidget);
            myScene->addItem(rect);

            //
            // draw the record type and status text
            //
            nextLineText = "%1 %2";
            // add the type-line
            nextLineText = nextLineText.arg(DNSResources::typeToRRName(vrcptr->val_ac_rrset->val_rrset_type));

            if (rrrec->rr_status == VAL_AC_UNSET)
                nextLineText = nextLineText.arg("");
            else if (m_statusToName.contains(rrrec->rr_status))
                nextLineText = nextLineText.arg("(" + m_statusToName[rrrec->rr_status] + ")");
            else
                nextLineText = nextLineText.arg("(unknown status)");

            text = new QGraphicsSimpleTextItem(nextLineText);
            text->setPen(QPen(Qt::black));
            text->setPos(boxLeftMargin + horizontalSpot, spot + boxTopMargin*2);
            text->setScale(2.0);
            myScene->addItem(text);

            //
            // add the domain line
            //
            QString rrsetName = vrcptr->val_ac_rrset->val_rrset_name;
            if (horizontalSpot == boxLeftMargin) {
                text = new QGraphicsSimpleTextItem(rrsetName == "." ? "<root>" : rrsetName);
                text->setPen(QPen(Qt::black));
                text->setPos(boxLeftMargin + horizontalSpot, spot + boxHeight + 20);
                text->setScale(2.0);
                myScene->addItem(text);
            }

            //
            // update the validation records in any existing data
            //
            m_graphWidget->nodeList()->node(rrsetName)->addSubData(DNSData(DNSResources::typeToRRName(vrcptr->val_ac_rrset->val_rrset_type), DNSData::getStatusFromValAStatus(rrrec->rr_status)));

            //
            // add any additional info
            //
            int     keyId;
            u_int   keyflags, protocol, algorithm, digest_type;
            QString algName;

            nextLineText = "";
            switch (vrcptr->val_ac_rrset->val_rrset_type) {
            case ns_t_dnskey:
                if (rrrec->rr_rdata_length < 0U + NS_INT16SZ + NS_INT8SZ + NS_INT8SZ)
                    break;

                /* grab the KeyID */
                keyId = id_calc(rrrec->rr_rdata, rrrec->rr_rdata_length);

                /* get the flags */
                RES_GET16(keyflags, rrrec->rr_rdata);
                protocol = *rdata++;
                algorithm = *rdata++;

                if (m_algorithmToName.contains(algorithm))
                    algName = m_algorithmToName[algorithm];
                else
                    algName = QString(tr("alg: %1")).arg(algorithm);

                nextLineText = QString(tr("%1, id: %2, proto: %3, %4"))
                        .arg((keyflags & 0x1) ? "KSK" : "ZSK")
                        .arg(keyId)
                        .arg(protocol)
                        .arg(algName);
                dnskeyIdToLocation[keyId] = QPair<int,int>(horizontalSpot, spot + boxTopMargin);
                dnsKeyToStatus[keyId] = rrrec->rr_status;                
                dnskeyIdToBox[keyId] = rect;
                break;

            case ns_t_ds:
                RES_GET16(keyId, rdata);
                algorithm = *rdata++ & 0xF;
                digest_type = *rdata++ & 0xF;

                QString digestName;
                if (m_digestToName.contains(digest_type))
                    digestName = m_digestToName[digest_type];
                else
                    digestName = QString(tr("digest: ")).arg(digest_type);

                if (m_algorithmToName.contains(algorithm))
                    algName = m_algorithmToName[algorithm];
                else
                    algName = QString(tr("alg: %1")).arg(algorithm);

                nextLineText = QString(tr("id: %1, %2, %3"))
                        .arg(keyId)
                        .arg(algName)
                        .arg(digestName);
                dsIdToLocation[QPair<int, int>(keyId, digest_type)] = QPair<int,int>(horizontalSpot, spot + boxTopMargin);
                dsIdToBox[QPair<int, int>(keyId, digest_type)] = rect;
                break;
            }

            QPair<QString, int> index = QPair<QString, int>(rrsetName, vrcptr->val_ac_rrset->val_rrset_type);
            if (! nameAndTypeToLocation.contains(index))
                nameAndTypeToLocation[index] = QList<QPair<int, int> >();
            nameAndTypeToLocation[index].push_back(QPair<int,int>(horizontalSpot, spot + boxTopMargin));


            if (nextLineText.length() > 0) {
                text = new QGraphicsSimpleTextItem(nextLineText);
                text->setPen(QPen(Qt::black));
                text->setPos(boxLeftMargin + horizontalSpot, spot + boxHeight - boxTopMargin*3);
                text->setScale(2.0);
                myScene->addItem(text);
            }

            horizontalSpot += boxWidth + boxHorizontalSpacing;
            maxWidth = qMax(maxWidth, horizontalSpot);
        }

        for(rrrec = vrcptr->val_ac_rrset->val_rrset_sig; rrrec; rrrec = rrrec->rr_next) {
            int type;
            u_long tmp;
            Q_UNUSED(tmp);
            unsigned short keyId;
            u_char algorithm;
            Q_UNUSED(algorithm);
            rdata = rrrec->rr_rdata;

            if (rrrec->rr_rdata_length < 22U)
                continue;

            /** Type covered, Algorithm, Label count, Original TTL.  */
            RES_GET16(type, rdata);
            algorithm = *rdata++;

            /** labels */
            *rdata++;
            //if (labels > (u_int) dn_count_labels(name))
            //    goto formerr;

            /* original TTL */
            RES_GET32(tmp, rdata);

            /** Signature expiration.  */
            RES_GET32(tmp, rdata);
            //len = SPRINTF((tmp, "%s ", p_secstodate(t)));

            /** Time signed (inception).  */
            RES_GET32(tmp, rdata);
            //len = SPRINTF((tmp, "%s ", p_secstodate(t)));

            /** keytag  */
            RES_GET16(keyId, rdata);
            //len = SPRINTF((tmp, "%u ", footprint));

            /** Signer's name.  */
            //if (dn_expand(rdata, rdata+something, vrcptr->val_ac_rrset->val_rrset_name, namebuf, sizeof(namebuf)) == -1)
            //    continue;

            /** Signature bits follow....  */

            //qDebug() << vrcptr->val_ac_rrset->val_rrset_name << " of type " << type << " signed by key #" << keyId << ", status = " << rrrec->rr_status << "=" << m_statusToName[rrrec->rr_status];
            if (! signedByList.contains(QPair<QString, int>(vrcptr->val_ac_rrset->val_rrset_name, type)))
                signedByList[QPair<QString, int>(vrcptr->val_ac_rrset->val_rrset_name, type)] = QList<QPair<int, int> >();
            signedByList[QPair<QString, int>(vrcptr->val_ac_rrset->val_rrset_name, type)].push_back(QPair<int, int>(keyId, rrrec->rr_status));
        }

        spot -= verticalBoxDistance;
    }

    // loop through all the DS records and have them point to the keys they're referencing
    QMap<QPair<int, int>, QPair<int, int> >::iterator dsIter, dsEnd = dsIdToLocation.end();
    for(dsIter = dsIdToLocation.begin(); dsIter != dsEnd; dsIter++) {
        QPair<int, int> dsLocation = dsIter.value();
        QPair<int, int> dnskeyLocation = dnskeyIdToLocation[dsIter.key().first];
        QColor arrowColor = Qt::black;
        if (dnsKeyToStatus[dsIter.key().first] == VAL_AC_VERIFIED_LINK)
            arrowColor = Qt::green;
        else
            arrowColor = Qt::yellow;
        drawArrow(dsLocation.first + boxWidth/2, dsLocation.second + boxHeight,
                  dnskeyLocation.first, dnskeyLocation.second, arrowColor, dsIdToBox[dsIter.key()]);
    }

    // loop through all the signatures and draw arrows for them
    QMap<QPair<QString, int>, QList<QPair<int, int> > >::const_iterator rrsigIter, rrsigEnd = signedByList.constEnd();

    // for each signature we saw...
    for (rrsigIter = signedByList.constBegin(); rrsigIter != rrsigEnd; rrsigIter++) {
        QPair<QString, int> nameAndType = rrsigIter.key();
        int raiseMultiplier = 4;
        int widthOffset = 20;

        // ...there is a key that created the signature, which signed...
        QList<QPair<int, int> >::const_iterator keyIter, keyEnd = (*rrsigIter).constEnd();
        for(keyIter = rrsigIter->constBegin(); keyIter != keyEnd; keyIter++) {
            int keyId = keyIter->first;
            int status = keyIter->second;
            QPair<int, int> dnsKeyLocation = dnskeyIdToLocation[keyId];

            // ... an rrset keyed by a name and record type
            QList<QPair<int, int> >::const_iterator listIter, listEnd = nameAndTypeToLocation[nameAndType].constEnd();
            for(listIter = nameAndTypeToLocation[nameAndType].constBegin(); listIter != listEnd; listIter++) {
                QColor arrowColor;
                if (status == VAL_AC_RRSIG_VERIFIED) {
                    arrowColor = Qt::green;
                } else if (status == VAL_AC_UNSET){
                    arrowColor = Qt::black;
                } else {
                    arrowColor = Qt::red;
                }
                if (dnsKeyLocation.second == (*listIter).second) {
                    // signing something in the same row (another key)

                    widthOffset = abs(dnsKeyLocation.first - (*listIter).first) * 40 / (boxWidth + boxHorizontalSpacing);
                    raiseMultiplier = widthOffset / 10;
                    if (widthOffset == 0) {
                        // signing itself
                        widthOffset = boxWidth / 3;
                        raiseMultiplier = 5;
                    }
                    if (dnsKeyLocation.first > (*listIter).first) {
                        // the thing being signed is to the key's left
                        drawArrow(dnsKeyLocation.first + widthOffset, dnsKeyLocation.second,
                                  (*listIter).first + boxWidth - widthOffset, (*listIter).second, arrowColor,
                                  dnskeyIdToBox[keyId], raiseMultiplier);



                    } else {
                        // the thing being signed is to the key's right
                        drawArrow(dnsKeyLocation.first + boxWidth - widthOffset, dnsKeyLocation.second,
                                  (*listIter).first + widthOffset, (*listIter).second, arrowColor,
                                  dnskeyIdToBox[keyId], raiseMultiplier);
                    }
                    // old adjustment values before using calculated positions
                    // widthOffset += 20;
                    // raiseMultiplier += 2;
                } else {
                    // signing something in a different row (DNSKEY signing the final record or a DS)
                    drawArrow(dnsKeyLocation.first + boxWidth/2, dnsKeyLocation.second + boxHeight,
                              (*listIter).first, (*listIter).second, arrowColor,
                              dnskeyIdToBox[keyId]);
                }

                // update the graph's data
#ifdef FIXME
                m_graphWidget->nodeList()->node();
#endif
            }
        }
    }

    // add text hint
    text = new QGraphicsSimpleTextItem("Click on a box to highlight it's arrows");
    text->setPen(QPen(Qt::gray));
    text->setPos(5, spot + 3*boxHeight/2);
    text->setScale(2.0);
    myScene->addItem(text);

    myScene->setSceneRect(0, spot + boxHeight, maxWidth, -spot + boxHeight);
    if (rect)
        ensureVisible(rect);

    viewport()->setCursor(Qt::ArrowCursor);
}

void ValidateViewWidget::wheelEvent(QWheelEvent *event)
{
    scaleView(pow((double)2, -event->delta() / 240.0));
}

void ValidateViewWidget::zoomIn()
{
    scaleView(qreal(1.2));
}

void ValidateViewWidget::zoomOut()
{
    scaleView(1 / qreal(1.2));
}
