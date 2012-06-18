/*
 * This header creates two useful definitions for using in C++ code:
 *
 * USE_QML:        defined to 1 if being compiled for a meego, android or symbian device
 *                 (these devices, in theory, look better when using a qml interface)
 * SMALL_DEVICE:   defined to 1 if on an android, meego, maemo5 or symbian device
 */

#if defined(Q_WS_MAEMO_5) || defined(MAEMO_CHANGES)
#define IS_MAEMO 1
#endif

 //#if defined(__arm__) && !defined(IS_MAEMO) && !defined(ANDROID)
#if defined(MEEGO_EDITION_HARMATTAN)
#define IS_MEEGO 1
#define IS_HARMATTAN
#endif

#if defined(ANDROID)
#define IS_ANDROID 1
#endif

#if defined(Q_OS_SYMBIAN)
#define IS_SYMBIAN 1
#endif

/* define whether or not we're on a "small screen" device, which should have a more
 * limited interface.  This decision is highly subjective and you may wish to tune it
 * according to local desire. */
#if defined(IS_MEEGO) || defined(ANDROID) || defined(Q_WS_MAEMO_5) || defined(IS_SYMBIAN)
#define SMALL_DEVICE 1
#endif


#if defined(IS_MEEGO) || defined(ANDROID) || defined(IS_SYMBIAN)
#define USE_QML 1
#endif
