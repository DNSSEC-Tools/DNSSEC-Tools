#ifndef SUBMITDIALOG_H
#define SUBMITDIALOG_H

#include <QDialog>
#include <QtGui/QVBoxLayout>

class SubmitDialog : public QDialog
{
    Q_OBJECT
public:
    explicit SubmitDialog(QWidget *parent = 0);

signals:

public slots:
private:
    QVBoxLayout *topLayout;
};

#endif // SUBMITDIALOG_H
