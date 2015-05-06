#ifndef SUBMITDIALOG_H
#define SUBMITDIALOG_H

#include <QDialog>
#include <QtWidgets/QVBoxLayout>
#include <QtWidgets/QLineEdit>

class SubmitDialog : public QDialog
{
    Q_OBJECT
public:
    explicit SubmitDialog(QWidget *parent = 0);
    QString locationDescription();

signals:

public slots:
private:
    QVBoxLayout *topLayout;
    QLineEdit   *m_locationDescription;
};

#endif // SUBMITDIALOG_H
