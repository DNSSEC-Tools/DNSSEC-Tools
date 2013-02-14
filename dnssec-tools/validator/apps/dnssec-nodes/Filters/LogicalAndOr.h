#ifndef LOGICALANDOR_H
#define LOGICALANDOR_H

#include "Filter.h"
#include "filtersAndEffects.h"
#include "qtauto_properties.h"

#include <QPushButton>

class LogicalAndOr : public Filter
{
    Q_OBJECT

    enum LogicType { AND, OR };

public:
    explicit LogicalAndOr(QObject *parent = 0);

    virtual bool      matches(Node *node);
    virtual QString   name() { return "Logical AND/OR"; }
    virtual void      configWidgets(QHBoxLayout *hbox);

    virtual void      addFilter(Filter *newFilter);

signals:
    
public slots:
            void      toggleFilterType();
            void      showAddFilterMenu();

private:
    QList<Filter *>   m_filters;
    QPushButton      *m_filterTypeButton;
    QPushButton      *m_addFilterButton;

    QTAUTO_GET_SET_SIGNAL(LogicType, logicType);

    // QTAUTO_HERE
    /* AGST */ Q_PROPERTY(LogicType logicType READ logicType WRITE setLogicType NOTIFY logicTypeChanged) public: const LogicType &logicType() const { return m_logicType; } signals: void logicTypeChanged(); void logicTypeChanged(LogicType); public slots: void setLogicType(const LogicType &newval) { if (newval != m_logicType) { QTAUTO_DEBUG("setting new value for " << QTAUTO_STRING(logicType) << " " << m_logicType << " => " << newval); m_logicType = newval; emit logicTypeChanged(); emit logicTypeChanged(newval); } } private: LogicType m_logicType;

public:
    
};

#endif // LOGICALANDOR_H
