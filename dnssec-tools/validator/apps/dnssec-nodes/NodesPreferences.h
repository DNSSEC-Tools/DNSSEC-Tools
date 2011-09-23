#ifndef NODESPREFERENCES_H
#define NODESPREFERENCES_H

#include <QDialog>
#include <QtGui/QVBoxLayout>
#include <QtGui/QFormLayout>
#include <QtGui/QSpinBox>
#include <QtCore/QSettings>
#include <QtGui/QCheckBox>

class NodesPreferences : public QDialog
{
    Q_OBJECT
public:
    enum dropOldReason { dontDrop, dropBasedOnNumbers, dropBasedOnTime };

    explicit NodesPreferences(QSettings *settings, QWidget *parent = 0);

    dropOldReason dropReason();
    int maxNodeCount();
    int maxTime();
    bool enableMaxNodes();
    bool enableTimeNodes();

signals:

public slots:
    void ok();

    void enableMaxNodesChanged(int value);
    void enableTimeNodesChanged(int value);

private:
    QVBoxLayout *m_vbox;
    QFormLayout *m_layout;
    QCheckBox   *m_enableMaxNodes;
    QSpinBox    *m_maxNodes;
    QCheckBox   *m_enableTimeNodes;
    QSpinBox    *m_maxTime;

    QSettings   *m_settings;
};

#endif // NODESPREFERENCES_H
