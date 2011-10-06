#include "TypeFilter.h"

#include <QtGui/QLabel>
#include <QtGui/QMenu>

#include <qdebug.h>

TypeFilter::TypeFilter(QString type)
    : Filter(), m_type(type), m_menuButton(0), m_mapper(this)
{
}

bool TypeFilter::matches(Node *node)
{
    if (node->subDataExistsFor(m_type))
        return true;
    return false;
}

void TypeFilter::configWidgets(QHBoxLayout *hbox)
{
    QLabel *filterLabel = new QLabel("Highlight Nodes That This Record Type:");
    hbox->addWidget(filterLabel);

    m_menuButton = new QPushButton(m_type);
    hbox->addWidget(m_menuButton);

    createTypeMenu();
}

// This function "borrowed" from the DNSSEC-Tools lookup utility
void
TypeFilter::createTypeMenu() {
    //
    // create the QUERY TYPE menu
    //
    QMenu *querymenu = new QMenu(m_menuButton);
    m_menuButton->setMenu(querymenu);

    QMap<int, QString> valuemap, dnssecmap, othermap;

    valuemap[1] = "A";
    valuemap[2] = "NS";
    valuemap[5] = "CNAME";
    valuemap[6] = "SOA";
    valuemap[12] = "PTR";
    valuemap[15] = "MX";
    valuemap[16] = "TXT";
    valuemap[28] = "AAAA";
    valuemap[33] = "SRV";
    valuemap[255] = "ANY";

    dnssecmap[43]    = "DS";
    dnssecmap[46]    = "RRSIG";
    dnssecmap[47]    = "NSEC";
    dnssecmap[48]    = "DNSKEY";
    dnssecmap[50]    = "NSEC3";
    dnssecmap[32769] = "DLV";

    othermap[3] = "MD";
    othermap[4] = "MF";
    othermap[7] = "MB";
    othermap[8] = "MG";
    othermap[9] = "MR";
    othermap[10] = "NULL";
    othermap[11] = "WKS";
    othermap[13] = "HINFO";
    othermap[14] = "MINFO";
    othermap[17] = "RP";
    othermap[18] = "AFSDB";
    othermap[19] = "X25";
    othermap[20] = "ISDN";
    othermap[21] = "RT";
    othermap[22] = "NSAP";
    othermap[23] = "NSAP_PTR";
    othermap[24] = "SIG";
    othermap[25] = "KEY";
    othermap[26] = "PX";
    othermap[27] = "GPOS";
    othermap[29] = "LOC";
    othermap[30] = "NXT";
    othermap[31] = "EID";
    othermap[32] = "NIMLOC";
    othermap[34] = "ATMA";
    othermap[35] = "NAPTR";
    othermap[36] = "KX";
    othermap[37] = "CERT";
    othermap[38] = "A6";
    othermap[39] = "DNAME";
    othermap[40] = "SINK";
    othermap[41] = "OPT";
    othermap[250] = "TSIG";
    othermap[251] = "IXFR";
    othermap[252] = "AXFR";
    othermap[253] = "MAILB";
    othermap[254] = "MAILA";


    QAction *action;

    QMenu *submenu = querymenu->addMenu("Common");
    for(QMap<int, QString>::iterator iter = valuemap.begin();
        iter != valuemap.end();
        iter++) {

        action = submenu->addAction(iter.value());
        connect(action, SIGNAL(triggered()), &m_mapper, SLOT(map()));
        m_mapper.setMapping(action, iter.key());
        m_mapper.setMapping(action, iter.value());
    }

    submenu = querymenu->addMenu("DNSSEC");
    for(QMap<int, QString>::iterator iter = dnssecmap.begin();
        iter != dnssecmap.end();
        iter++) {

        action = submenu->addAction(iter.value());
        connect(action, SIGNAL(triggered()), &m_mapper, SLOT(map()));
        m_mapper.setMapping(action, iter.key());
        m_mapper.setMapping(action, iter.value());
    }

    submenu = querymenu->addMenu("Others");
    for(QMap<int, QString>::iterator iter = othermap.begin();
        iter != othermap.end();
        iter++) {

        action = submenu->addAction(iter.value());
        connect(action, SIGNAL(triggered()), &m_mapper, SLOT(map()));
        m_mapper.setMapping(action, iter.key());
        m_mapper.setMapping(action, iter.value());
    }

    connect(&m_mapper, SIGNAL(mapped(QString)),
            this, SLOT(setQueryType(QString)));
}

void TypeFilter::setQueryType(QString type)
{
    m_type = type;
    if (m_menuButton)
        m_menuButton->setText(type);
    emit filterChanged();
}
