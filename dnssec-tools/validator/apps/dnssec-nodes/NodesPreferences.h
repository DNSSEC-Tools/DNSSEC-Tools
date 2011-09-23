#ifndef NODESPREFERENCES_H
#define NODESPREFERENCES_H

#include <QDialog>
#include <QtGui/QVBoxLayout>
#include <QtGui/QFormLayout>
#include <QtGui/QSpinBox>
#include <QtCore/QSettings>

class NodesPreferences : public QDialog
{
    Q_OBJECT
public:
    explicit NodesPreferences(QSettings &settings, QWidget *parent = 0);
    int maxNodeCount();

signals:

public slots:
    void ok();

private:
    QVBoxLayout *m_vbox;
    QFormLayout *m_layout;
    QSpinBox    *m_maxNodes;

     QSettings  &m_settings;
};

#endif // NODESPREFERENCES_H
