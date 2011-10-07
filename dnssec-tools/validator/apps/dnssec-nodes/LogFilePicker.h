#ifndef LOGFILEPICKER_H
#define LOGFILEPICKER_H

#include <QDialog>
#include <QtGui/QHBoxLayout>
#include <QtGui/QVBoxLayout>
#include <QtGui/QLineEdit>
#include <QtCore/QString>
#include <QtGui/QCheckBox>

class LogFilePicker : public QDialog
{
    Q_OBJECT
public:
    explicit LogFilePicker(QString defaultFile = "", QWidget *parent = 0);

    QString file();
    bool skipToEnd();

signals:

public slots:
    void openBrowseWindow();

private:
    QLineEdit *m_fileEditBox;
    QCheckBox *m_skipToEnd;
};

#endif // LOGFILEPICKER_H
