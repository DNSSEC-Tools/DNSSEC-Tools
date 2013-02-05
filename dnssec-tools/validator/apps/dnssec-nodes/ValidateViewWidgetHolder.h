#ifndef VALIDATEVIEWWIDGETHOLDER_H
#define VALIDATEVIEWWIDGETHOLDER_H

#include <QWidget>
#include "ValidateViewWidget.h"

class ValidateViewWidgetHolder : public QWidget
{
    Q_OBJECT
public:
    explicit ValidateViewWidgetHolder(const QString &nodeName, const QString &recordType,
                                      GraphWidget *graphWidget, QWidget *parent = 0);
    
signals:
    
public slots:

private:
    ValidateViewWidget *m_view;
    
};

#endif // VALIDATEVIEWWIDGETHOLDER_H
