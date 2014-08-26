#ifndef LOOKUPPREFS_H
#define LOOKUPPREFS_H

#include <QDialog>
#include <QtGui/QVBoxLayout>
#include <QtGui/QFormLayout>
#include <QtGui/QLineEdit>
#include <QWidget>

class LookupPrefs : public QDialog
{
    Q_OBJECT
public:
    explicit LookupPrefs(QWidget *parent = 0);

    void createLayout();
signals:

public slots:
    void savePrefs();

private:
    QVBoxLayout *topLayout;
    QFormLayout *formLayout;
    QLineEdit   *logLocation;
};

#endif // LOOKUPPREFS_H
