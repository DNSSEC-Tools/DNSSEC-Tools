#include "ValidateViewWidget.h"

#include <QtGui/QGraphicsRectItem>
#include <QtGui/QGraphicsSimpleTextItem>
#include <QtCore/QTimer>

#include <validator/validator-config.h>
#include <validator/validator.h>

#include <qdebug.h>

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

ValidateViewWidget::ValidateViewWidget(QString nodeName, QString recordType, QWidget *parent) :
    QGraphicsView(parent), m_nodeName(nodeName), m_recordType(recordType), m_typeToName(), m_statusToName()
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

    QMap<int, QString>::const_iterator mapIter, mapEnd = m_typeToName.constEnd();
    for(mapIter = m_typeToName.constBegin(); mapIter != mapEnd; mapIter++) {
        m_nameToType[mapIter.value()] = mapIter.key();
    }

    scaleView(.5);
    QTimer::singleShot(1, this, SLOT(validateDefault()));
}

void ValidateViewWidget::scaleView(qreal scaleFactor)
{
    qreal factor = transform().scale(scaleFactor, scaleFactor).mapRect(QRectF(0, 0, 1, 1)).width();
    if (factor < 0.07 || factor > 100)
        return;

    scale(scaleFactor, scaleFactor);
}

void ValidateViewWidget::drawArrow(int fromX, int fromY, int toX, int toY, QColor color, int horizRaiseMultiplier) {
    const int arrowHalfWidth = 10;

    QBrush brush(color);
    QPen   pen(color);


    if (fromY == toY) {
        // draw horizontal lines differently...  up -> across -> down
        QGraphicsLineItem *line = new QGraphicsLineItem(fromX, fromY - horizRaiseMultiplier*arrowHalfWidth, toX, toY - horizRaiseMultiplier*arrowHalfWidth);
        line->setPen(pen);
        myScene->addItem(line);

        line = new QGraphicsLineItem(fromX, fromY, fromX, fromY - horizRaiseMultiplier*arrowHalfWidth);
        line->setPen(pen);
        myScene->addItem(line);

        line = new QGraphicsLineItem(toX, toY - horizRaiseMultiplier*arrowHalfWidth, toX, toY - arrowHalfWidth);
        line->setPen(pen);
        myScene->addItem(line);
    } else {
        // draw line in 3 segments, two vertical stubs to make the arrow to triangle look better
        QGraphicsLineItem *line = new QGraphicsLineItem(fromX, fromY + 2*arrowHalfWidth, toX, toY - 2*arrowHalfWidth);
        line->setPen(pen);
        myScene->addItem(line);

        line = new QGraphicsLineItem(fromX, fromY, fromX, fromY + 2*arrowHalfWidth);
        line->setPen(pen);
        myScene->addItem(line);

        line = new QGraphicsLineItem(toX, toY - 2*arrowHalfWidth, toX, toY - arrowHalfWidth);
        line->setPen(pen);
        myScene->addItem(line);
    }

    QPolygon polygon;
    polygon << QPoint(toX, toY)
            << QPoint(toX - arrowHalfWidth, toY - arrowHalfWidth)
            << QPoint(toX + arrowHalfWidth, toY - arrowHalfWidth);
    QGraphicsPolygonItem *polyItem = new QGraphicsPolygonItem(polygon);
    polyItem->setPen(pen);
    polyItem->setBrush(brush);
    polyItem->setFillRule(Qt::OddEvenFill);
    myScene->addItem(polyItem);
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
    ret = val_resolve_and_check(NULL, name.toAscii().data(), 1, m_nameToType[type],
                                VAL_QUERY_RECURSE | VAL_QUERY_AC_DETAIL |
                                VAL_QUERY_SKIP_CACHE,
                                &results);
    if (ret != 0 || !results) {
        qWarning() << "failed to get results..."; // XXX: display SOMETHING!
        return;
    }

    int spot = 0;
    int maxWidth = 0;
    QGraphicsRectItem        *rect = 0;
    QGraphicsSimpleTextItem  *text;
    struct val_rr_rec *rrrec;
    const u_char * rdata;

    QMap<int, QPair<int, int> > dnskeyIdToLocation;
    QMap<QPair<int, int>, QPair<int, int> > dsIdToLocation;
    QMap<int, int> dnsKeyToStatus;
    QMap<QPair<QString, int>, QList< QPair<int, int> > > nameAndTypeToLocation;
    QMap<QPair<QString, int>, QList<QPair<int, int> > > signedByList;

    // for each authentication record, display a horiz row of data
    for(vrcptr = results->val_rc_answer; vrcptr; vrcptr = vrcptr->val_ac_trust) {
        int horizontalSpot = boxLeftMargin;

        // for each rrset in an auth record, display a box
        // qDebug() << "chain: " << vrcptr->val_ac_rrset->val_rrset_name << " -> " << vrcptr->val_ac_rrset->val_rrset_type;

        for(rrrec = vrcptr->val_ac_rrset->val_rrset_data; rrrec; rrrec = rrrec->rr_next) {
            QString nextLineText;

            rdata = rrrec->rr_rdata;

            // draw the bounding box of the record
            rect = new QGraphicsRectItem(horizontalSpot, spot+boxTopMargin, boxWidth, boxHeight);
            rect->setPen(QPen(Qt::black));
            myScene->addItem(rect);

            nextLineText = "%1 %2";
            // add the type-line
            if (m_typeToName.contains(vrcptr->val_ac_rrset->val_rrset_type))
                nextLineText = nextLineText.arg(m_typeToName[vrcptr->val_ac_rrset->val_rrset_type]);
            else
                nextLineText = nextLineText.arg("(type unknown)");

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

            // add the domain line
            QString rrsetName = vrcptr->val_ac_rrset->val_rrset_name;
            text = new QGraphicsSimpleTextItem(rrsetName == "." ? "<root>" : rrsetName);
            text->setPen(QPen(Qt::black));
            text->setPos(boxLeftMargin + horizontalSpot, spot + boxHeight/2);
            text->setScale(2.0);
            myScene->addItem(text);

            int     keyId;
            u_int   keyflags, protocol, algorithm, digest_type;
            QString algName;

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
            unsigned short keyId;
            u_char algorithm;
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
        drawArrow(dsLocation.first + boxWidth/2, dsLocation.second + boxHeight,
                  dnskeyLocation.first + boxWidth/2, dnskeyLocation.second, arrowColor);
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
                    drawArrow(dnsKeyLocation.first + widthOffset, dnsKeyLocation.second,
                              (*listIter).first + boxWidth - widthOffset, (*listIter).second, arrowColor, raiseMultiplier);
                    raiseMultiplier += 2;
                    widthOffset += 20;
                } else {
                    // signing something in a different row (DNSKEY signing the final record or a DS)
                    drawArrow(dnsKeyLocation.first + boxWidth/2, dnsKeyLocation.second + boxHeight,
                              (*listIter).first + boxWidth/2, (*listIter).second, arrowColor);
                }
            }
        }
    }

    myScene->setSceneRect(0, spot + boxHeight, maxWidth, -spot + boxHeight);
    if (rect)
        ensureVisible(rect);
}
