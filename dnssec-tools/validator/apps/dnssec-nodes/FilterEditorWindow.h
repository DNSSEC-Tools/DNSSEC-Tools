#ifndef FILTEREDITORWINDOW_H
#define FILTEREDITORWINDOW_H

#include <QDialog>

#include <QVBoxLayout>

#include "NodeList.h"
#include "filtersAndEffects.h"

class NodeList;
class FilterEditorWindow : public QDialog
{
    Q_OBJECT
public:
    explicit FilterEditorWindow(NodeList *nodeList, QWidget *parent = 0);
    
    void setupEditPanel();
signals:
    
public slots:

private:
    QWidget     *m_mainWidget;
    QVBoxLayout *m_mainLayout, *m_pairLayouts;
    NodeList    *m_nodeList;
    
};

#endif // FILTEREDITORWINDOW_H
