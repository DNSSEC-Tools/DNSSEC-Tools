#include "Filter.h"
#include "filtersAndEffects.h"

Filter::Filter(QObject *parent) : QObject(parent)
{
}

Filter *Filter::getNewFilterFromMenu(QPoint where) {
    QMenu *menu = new QMenu();

    menu->addAction(tr("Logical AND/OR Filter"));
    menu->addAction(tr("Logical Not Filter"));
    menu->addAction(tr("Filter By DNSSEC Status"));
    menu->addAction(tr("Filter By Name"));
    menu->addAction(tr("Filter By Type"));

    QAction *action = menu->exec(where);

    if (!action)
        return 0;

    QString menuChoice = action->text();
    if (menuChoice == tr("Filter By DNSSEC Status")) {
        return new DNSSECStatusFilter();
    } else if (menuChoice == tr("Filter By Name")) {
        return new NameFilter();
    } else if (menuChoice == tr("Filter By Type")) {
        return new TypeFilter();
    } else if (menuChoice == tr("Logical AND/OR Filter")) {
        return new LogicalAndOr();
    } else if (menuChoice == tr("Logical Not Filter")) {
        return new NotFilter();
    }

    qWarning() << "unknown Filter passed to create node!";
    return 0;
}
