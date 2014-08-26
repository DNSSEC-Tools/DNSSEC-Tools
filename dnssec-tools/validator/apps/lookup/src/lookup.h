#ifndef LOOKUP_H
#define LOOKUP_H

#include <QWidget>
#include <QString>
#include <QLineEdit>
#include <QLabel>
#include <QTreeView>
#include <QStandardItemModel>
#include <QGridLayout>
#include <QScrollArea>
#include <QPushButton>
#include <QSize>
#include <QSignalMapper>
#include <QMainWindow>

#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <validator/validator-config.h>
#include <validator/resolver.h>
#include <validator/validator.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "QDNSItemModel.h"

class Lookup : public QMainWindow
{
    Q_OBJECT

public:
    Lookup(QWidget *parent = 0);
    ~Lookup();

    void createMainWidgets();
    void createQueryMenu();
    void createMenus();
    void init_libval();

public slots:
    void unbusy();
    void busy();
    void showAbout();
    void showPreferences();
    void loadPreferences();

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

    static const int  fields = 4;
    QLabel           *labels[fields];
    QLabel           *values[fields];
    QLabel            *m_resultsIcon;
    bool              found;
    QPushButton       *m_queryButton;
    int               m_queryType;
    QSignalMapper     *m_signalMapper;

    // Settings
    QString            m_logLocation;

    // libval settings
    val_context_t *val_ctx;
};

#endif
