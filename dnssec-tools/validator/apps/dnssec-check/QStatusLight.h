#ifndef QSTATUSLIGHT_H
#define QSTATUSLIGHT_H

#include <QPushButton>

typedef int (CheckFunction) (char *serveraddr, char *returnString, size_t returnStringSize);

class QStatusLight : public QPushButton
{
    Q_OBJECT
public:

    enum lightStatus { UNKNOWN, GOOD, WARNING, BAD };

    explicit QStatusLight(QWidget *parent = 0, CheckFunction *check_function = 0, const char *serverAddress = 0, const QString &checkName = "", int rowNumber = 0);

    lightStatus status();
    QString statusString();
    void setStatus(lightStatus newStatus);

    const QString message() const;
    void setMessage(const QString &message);

    const QString name() const;
    int rowNumber() const;

    const QString serverAddress() const;

    virtual QSize sizeHint();
    virtual QSize minimumSizeHint();

protected:
    virtual void 	paintEvent ( QPaintEvent * e );

signals:

public slots:
    void check();
    void showError();

private:
    lightStatus    m_status;
    CheckFunction *m_checkFunction;
    char           m_msgBuffer[4096];
    char          *m_serverAddress;
    QString        m_checkName;
    QList<QString> m_statusStrings;
    int            m_rowNumber;
};

#endif // QSTATUSLIGHT_H
