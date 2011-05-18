#ifndef QDNSITEMMODEL_H
#define QDNSITEMMODEL_H

#include <QtGui/QWidget>
#include <QtGui/QStandardItemModel>

#if (defined(Q_WS_MAEMO_5) || defined(MAEMO_CHANGES))
#define BROKENBACKGROUND 1
#endif

class QDNSItemModel : public QStandardItemModel
{
    Q_OBJECT

  public:
    QDNSItemModel(QObject *parent = 0);
    virtual ~QDNSItemModel();

    enum securityStatus { validated, trusted, bad, unknown };

    void setSecurityStatus(QStandardItem *item, securityStatus istrusted);
    QVariant data(const QModelIndex &index, int role) const;

public slots:
    void emitChanges();

  private:
    QStandardItem *m_securityItem;
    securityStatus m_istrusted;
};

#endif /* QDNSITEMMODEL_H */
