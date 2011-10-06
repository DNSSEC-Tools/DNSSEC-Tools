#ifndef TYPEMENU_H
#define TYPEMENU_H

#include <QObject>
#include <QtGui/QMenu>
#include <QtCore/QSignalMapper>
#include <QtGui/QPushButton>

class TypeMenu : public QObject
{
    Q_OBJECT
public:
    explicit TypeMenu(QPushButton *menuButton, QObject *parent = 0);

    void createTypeMenu();

signals:
    void typeSet(QString);
    void typeSet(int);

public slots:
    void setQueryType(QString type);

private:
    QPushButton  *m_menuButton;
    QSignalMapper m_mapper;
};

#endif // TYPEMENU_H
