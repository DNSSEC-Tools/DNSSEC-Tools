#ifndef QTAUTO_PARAMETERS_H
#define QTAUTO_PARAMETERS_H

/*
 * This file comes from the qtautoproperties package.  For more
 * information and usage, please see its github page:
 *
 *     http://github.com/hardaker/qtautoproperty
 */
   

#ifndef _QTAUTO_OPERATE

/* replacement macros so you don't have to comment them out */

#define QTAUTO_GET(autotype, lcname)
#define QTAUTO_GET_SIGNAL(autotype, lcname)
#define QTAUTO_GET_SET_SIGNAL(autotype, lcname)
#define QTAUTO_HERE

#ifdef QTAUTO_DEBUG_SIGNALS_SLOTS
#include <qdebug.h>
#define QTAUTO_STRING_NX(A) #A
#define QTAUTO_STRING(A) QTAUTO_STRING_NX(A)
#define QTAUTO_DEBUG(msg) do { qDebug() << msg; } while(0);
#else
#define QTAUTO_DEBUG(msg)
#endif

#else 

/* this is always the final macro so the terminating ; in the calling file
 * will properly terminate every experssion, allowing for more readable code.
 * IE: this deliberately doesn't have a trailing ';'
 */
#define _QTAUTO_TYPE(autotype, lcname)            \
    private:                                                \
         autotype m_ ## lcname;
                                                            

#define _QTAUTO_GET(autotype, lcname)         \
    public:                                                 \
         const autotype &lcname() const {                   \
              return m_ ## lcname;                          \
         }                                                  \

#define _QTAUTO_SIGNAL(autotype, lcname)                    \
    signals:                                                \
        void lcname ## Changed();                           \
        void lcname ## Changed(autotype);                   \

#define QTAUTO_GET(autotype, lcname)                          \
    Q_PROPERTY(autotype lcname READ lcname)                \
    _QTAUTO_GET(autotype, lcname)                             \
    _QTAUTO_TYPE(autotype, lcname)

#define QTAUTO_GET_SIGNAL(autotype, lcname)                        \
    Q_PROPERTY(autotype lcname READ lcname NOTIFY lcname ## Changed) \
    _QTAUTO_GET(autotype, lcname)                                       \
    _QTAUTO_SIGNAL(autotype, lcname)                                    \
    _QTAUTO_TYPE(autotype, lcname)


#define QTAUTO_GET_SET_SIGNAL(autotype, lcname, ucname)                   \
    Q_PROPERTY(autotype lcname READ lcname WRITE set ## ucname NOTIFY lcname ## Changed)                \
    _QTAUTO_GET(autotype, lcname)                                         \
    _QTAUTO_SIGNAL(autotype, lcname)                                      \
                                                                        \
    public slots:                                                       \
    void set ## ucname(const autotype &newval) {                        \
        if (newval != m_ ## lcname) {                                   \
            QTAUTO_DEBUG("setting new value for " << QTAUTO_STRING(lcname) << " " << m_ ## lcname << " => " << newval); \
            m_ ## lcname = newval;                                      \
            emit lcname ## Changed();                                   \
            emit lcname ## Changed(newval);                             \
        }                                                               \
    }                                                                   \
                                                                        \
    _QTAUTO_TYPE(autotype, lcname)

#endif /* _QTAUTO_OPERATE */
#endif /* QTAUTO_PARAMETERS_H */
