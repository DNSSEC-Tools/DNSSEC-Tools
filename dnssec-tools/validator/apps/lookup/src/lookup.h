#ifndef LOOKUP_H
#define LOOKUP_H

#include <QtCore/QString>
#include <QtGui/QWidget>
#include <QtGui/QLineEdit>
#include <QtGui/QLabel>
#include <QtGui/QTreeView>
#include <QtGui/QStandardItemModel>
#include <QtGui/QGridLayout>
#include <QtGui/QScrollArea>
#include <QtGui/QPushButton>
#include <QtCore/QSize>
#include <QtCore/QSignalMapper>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <validator-config.h>
#include <validator/resolver.h>
#include <validator/validator.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "QDNSItemModel.h"

class Lookup : public QWidget
{
    Q_OBJECT

  public:
    Lookup(QWidget *parent = 0);
    ~Lookup();

    protected slots:
    void dolookup();
    void setQueryType(int type);
    void setTypeText(const QString &label);
    QSize sizeHint();
    void entryTextChanged(const QString &newtext);

    void setSecurityStatus(int val_status);



  private:
    QLineEdit          *lookupline;
    QPushButton        *gobutton;
    QGridLayout        *gridLayout;
    QScrollArea        *scroller;
    QVBoxLayout        *vlayout;
    QTreeView          *m_answerView;
    QDNSItemModel      *m_answers;
    QStandardItem      *m_securityStatus;

    // Icons
    QPixmap             m_validated, m_trusted, m_bad, m_unknown;

  public:
    static const int  fields = 4;
    QLabel           *labels[fields];
    QLabel           *values[fields];
    QLabel            *m_resultsIcon;
    bool              found;
    QPushButton       *m_queryButton;
    int               m_queryType;
    QSignalMapper     *m_signalMapper;
public slots:
    void unbusy();
    void busy();
};

#endif
