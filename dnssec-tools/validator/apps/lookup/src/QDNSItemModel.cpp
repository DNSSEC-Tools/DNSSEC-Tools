#include <QWidget>
#include "QDNSItemModel.h"

QDNSItemModel::QDNSItemModel(QObject *parent) 
    : QStandardItemModel(parent), m_securityItem(0), m_istrusted(unknown)
{
}

QDNSItemModel::~QDNSItemModel()
{
}

void QDNSItemModel::setSecurityStatus(QStandardItem *item,
                                      securityStatus istrusted)
{
    m_securityItem = item;
    m_istrusted = istrusted;
}

QVariant QDNSItemModel::data(const QModelIndex &index, int role) const
{
#ifdef BROKENBACKGROUND
#define CHANGEROLE Qt::ForegroundRole
#else
#define CHANGEROLE Qt::BackgroundRole
#endif

    if (role == CHANGEROLE) {
        if (m_istrusted == validated)
            return QColor(150,255,150);
        if (m_istrusted == trusted)
            return QColor(255,255,150);
        if (m_istrusted == bad)
            return QColor(255,150,150);
        if (m_istrusted == unknown)
            return QColor(255,255,255);
    }

#ifndef BROKENBACKGROUND
    // we color the background specifically, so the font color must be dark
    if (role == Qt::ForegroundRole) {
        return QColor(0,0,0);
    }
#endif

    return QStandardItemModel::data(index, role);
}

void QDNSItemModel::emitChanges()
{
    emit layoutChanged();
}
