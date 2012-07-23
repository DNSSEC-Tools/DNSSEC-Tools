#include "MainWindow.h"

MainWindow::MainWindow(const QString &fileName, QWidget *parent) :
    QMainWindow(parent)
{
    QWidget *mainWidget = new QWidget;
    QVBoxLayout *layout = new QVBoxLayout();
    QHBoxLayout *hbox = new QHBoxLayout();

    // Information Box at the Top
    QHBoxLayout *infoBox = new QHBoxLayout();
    layout->addLayout(infoBox);

    // Filter box, hidden by default
    QHBoxLayout *filterBox = new QHBoxLayout();
    layout->addLayout(filterBox);

    QLineEdit *editBox = new QLineEdit();


    // Main GraphWidget object
    GraphWidget *graphWidget = new GraphWidget(0, editBox, fileName, infoBox);



    // Edit box at the bottom
    QPushButton *lookupTypeButton = new QPushButton("A");
    TypeMenu *lookupType = new TypeMenu(lookupTypeButton);
    hbox->addWidget(new QLabel("Perform a Lookup:"));
    hbox->addWidget(editBox);
    hbox->addWidget(new QLabel("For Type:"));
    hbox->addWidget(lookupTypeButton);
    lookupType->connect(lookupType, SIGNAL(typeSet(int)), graphWidget, SLOT(setLookupType(int)));

    mainWidget->setLayout(layout);
    setCentralWidget(mainWidget);
    setWindowIcon(QIcon(":/icons/dnssec-nodes-64x64.png"));

    hbox->addWidget(new QLabel("Zoom Layout: "));
    QPushButton *button;
    hbox->addWidget(button = new QPushButton("+"));
    button->connect(button, SIGNAL(clicked()), graphWidget, SLOT(zoomIn()));

    hbox->addWidget(button = new QPushButton("-"));
    button->connect(button, SIGNAL(clicked()), graphWidget, SLOT(zoomOut()));

#ifdef ANDROID
    /* put the edit line on the top because the slide out keyboard covers it otherwise */
    layout->addLayout(hbox);
    layout->addWidget(graphWidget);
#else
    layout->addWidget(graphWidget);
    layout->addLayout(hbox);
#endif

    /* menu system */
    QMenuBar *menubar = menuBar();

    //
    // File Menu
    //
    QMenu *menu = menubar->addMenu("&File");

    menu->addSeparator();

    QAction *action = menu->addAction("&Clear Nodes");
    action->connect(action, SIGNAL(triggered()), graphWidget->nodeList(), SLOT(clear()));

    menu->addSeparator();

    action = menu->addAction("&Open and Watch A Log File");
    action->connect(action, SIGNAL(triggered()), graphWidget, SLOT(openLogFile()));

    action = menu->addAction("&ReRead All Log Files");
    action->connect(action, SIGNAL(triggered()), graphWidget->logWatcher(), SLOT(reReadLogFile()));

    QMenu *previousMenu = menu->addMenu("Previous Logs");
    graphWidget->setPreviousFileList(previousMenu);

#ifdef WITH_PCAP
    graphWidget->pcapWatcher()->setupDeviceMenu(menu);
#endif

    menu->addSeparator();

    action = menu->addAction("&Quit");
    action->connect(action, SIGNAL(triggered()), this, SLOT(close()));

    menu = menubar->addMenu("&Options");

    action = menu->addAction("Lock Nodes");
    action->setCheckable(true);
    action->connect(action, SIGNAL(triggered(bool)), graphWidget, SLOT(setLockedNodes(bool)));

    action = menu->addAction("Show NSEC3 Records");
    action->setCheckable(true);
    action->connect(action, SIGNAL(triggered(bool)), graphWidget, SLOT(setShowNSEC3Records(bool)));

    action = menu->addAction("Animate Node Movemets");
    action->setCheckable(true);
    action->setChecked(graphWidget->animateNodeMovements());
    action->connect(action, SIGNAL(toggled(bool)), graphWidget, SLOT(setAnimateNodeMovements(bool)));

    QMenu *layoutMenu = menu->addMenu("Layout");
    action = layoutMenu->addAction("tree");
    action->connect(action, SIGNAL(triggered()), graphWidget, SLOT(switchToTree()));
    action = layoutMenu->addAction("circle");
    action->connect(action, SIGNAL(triggered()), graphWidget, SLOT(switchToCircles()));

    //
    // Filter menu
    //
    QActionGroup *filterActions = new QActionGroup(this);
    QMenu *filterMenu = menu->addMenu("Filter");
    action = filterMenu->addAction("Do Net Filter");
    action->connect(action, SIGNAL(triggered()), graphWidget->nodeList(), SLOT(filterNone()));
    action->setCheckable(true);
    action->setChecked(true);
    action->setActionGroup(filterActions);
    filterMenu->addSeparator();

    action = filterMenu->addAction("Filter by Data Status");
    action->connect(action, SIGNAL(triggered()), graphWidget->nodeList(), SLOT(filterBadToTop()));
    action->setCheckable(true);
    action->setActionGroup(filterActions);

    action = filterMenu->addAction("Filter by Data Type");
    action->connect(action, SIGNAL(triggered()), graphWidget->nodeList(), SLOT(filterByDataType()));
    action->setCheckable(true);
    action->setActionGroup(filterActions);

    action = filterMenu->addAction("Filter by Name");
    action->connect(action, SIGNAL(triggered()), graphWidget->nodeList(), SLOT(filterByName()));
    action->setCheckable(true);
    action->setActionGroup(filterActions);
    graphWidget->nodeList()->setFilterBox(filterBox);

    menu->addSeparator();

    action = menu->addAction("Preferences");
    action->connect(action, SIGNAL(triggered()), graphWidget, SLOT(showPrefs()));

    //
    // Help Menu
    //
    menu = menubar->addMenu("&Help");
    action = menu->addAction("&About DNSSEC-Nodes");
    action->connect(action, SIGNAL(triggered()), graphWidget, SLOT(about()));

    action = menu->addAction("&Legend");
    action->connect(action, SIGNAL(triggered()), graphWidget, SLOT(legend()));

    action = menu->addAction("&Help");
    action->connect(action, SIGNAL(triggered()), graphWidget, SLOT(help()));

#if defined(Q_OS_SYMBIAN) || defined(Q_WS_MAEMO_5)
    menuBar()->addAction("Zoom In", graphWidget, SLOT(zoomIn()));
    menuBar()->addAction("Shuffle", graphWidget, SLOT(shuffle()));
    menuBar()->addAction("Zoom Out", graphWidget, SLOT(zoomOut()));
    showMaximized();
#else
    resize(1024,800);
    show();
#endif
}
