#ifndef FILTEREDITORWINDOW_H
#define FILTEREDITORWINDOW_H

#include <QDialog>

#include <QVBoxLayout>
#include <QScrollArea>

#include "NodeList.h"
#include "filtersAndEffects.h"

class NodeList;
class FilterEditorWindow : public QDialog
{
    Q_OBJECT
public:
    explicit FilterEditorWindow(NodeList *nodeList, QWidget *parent = 0);
    
    void setupEditPanel();
    void clearEditPanel();
signals:
    
public slots:
    void resetupEditPanel();
    void addNewFilterEffectPair();
    void eraseAllFilterEffectPairs();

private:
    QWidget     *m_mainWidget;
    QVBoxLayout *m_mainLayout, *m_pairLayouts;
    NodeList    *m_nodeList;
    QScrollArea *m_scrolled;
    QPushButton *m_addPairButton;
};

#endif // FILTEREDITORWINDOW_H
