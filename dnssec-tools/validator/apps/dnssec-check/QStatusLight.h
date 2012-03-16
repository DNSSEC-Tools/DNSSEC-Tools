#ifndef QSTATUSLIGHT_H
#define QSTATUSLIGHT_H

#include <QPushButton>

#include "DNSSECTest.h"

typedef int (CheckFunction) (char *serveraddr, char *returnString, size_t returnStringSize, int *returnStatus);

class QStatusLight : public QPushButton
{
    Q_OBJECT
public:

    explicit QStatusLight(QWidget *parent = 0, CheckFunction *check_function = 0, const char *serverAddress = 0, const QString &checkName = "", int rowNumber = 0);

    virtual QSize sizeHint();
    virtual QSize minimumSizeHint();

    DNSSECTest *test();

    int rowNumber();

protected:
    virtual void 	paintEvent ( QPaintEvent * e );

signals:

public slots:
    void check();
    void showError();
    void reset();

private:
    DNSSECTest     m_dnssecTest;
    int            m_rowNumber;
};

#endif // QSTATUSLIGHT_H
