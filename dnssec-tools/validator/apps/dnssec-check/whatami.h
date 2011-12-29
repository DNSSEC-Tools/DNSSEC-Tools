#if defined(Q_WS_MAEMO_5) || defined(MAEMO_CHANGES)
#define IS_MAEMO 1
#endif

#if defined(__arm__) && !defined(IS_MAEMO)
#define IS_MEEGO 1
#endif

#ifdef IS_MEEGO
#define USE_QML 1
#endif
