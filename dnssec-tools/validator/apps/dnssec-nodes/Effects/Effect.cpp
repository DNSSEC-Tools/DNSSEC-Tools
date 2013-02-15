#include "Effect.h"
#include "filtersAndEffects.h"

Effect::Effect(QObject *parent)
    : QObject(parent)
{
}

Effect *Effect::getNewEffectFromMenu(QPoint where) {
    QMenu *menu = new QMenu();

    menu->addAction(tr("Set Alpha Effect"));
    menu->addAction(tr("Set Node Coloring"));
    menu->addAction(tr("Set Z Value"));
    menu->addAction(tr("Set Node Size"));

    QAction *action = menu->exec(where);

    if (!action)
        return 0;

    QString menuChoice = action->text();
    if (menuChoice == tr("Set Alpha Effect")) {
        return new SetAlphaEffect(128);
    } else if (menuChoice == tr("Set Node Coloring")) {
        return new SetNodeColoring();
    } else if (menuChoice == tr("Set Z Value")) {
        return new SetZValue(0);
    } else if (menuChoice == tr("Set Node Size")) {
        return new SetSize(20);
    }

    qWarning() << "unknown effect passed to create node!";
    return 0;
}
