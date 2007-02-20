dnl @synopsis AC_PROMPT_USER_NO_DEFINE(VARIABLENAME,QUESTION,[DEFAULT])
dnl
dnl Asks a QUESTION and puts the results in VARIABLENAME with an optional
dnl DEFAULT value if the user merely hits return.
dnl
dnl @version 1.15
dnl @author Wes Hardaker <hardaker@users.sourceforge.net>
dnl
AC_DEFUN([AC_PROMPT_USER_NO_DEFINE],
dnl changequote(<<, >>) dnl
dnl <<
[
if test "x$defaults" = "xno"; then
echo $ECHO_N "$2 ($3): $ECHO_C"
read tmpinput
if test "$tmpinput" = "" -a "$3" != ""; then
  tmpinput="$3"
fi
eval $1=\"$tmpinput\"
else
tmpinput="$3"
eval $1=\"$tmpinput\"
fi
]
dnl >>
dnl changequote([, ])
) dnl done AC_PROMPT_USER

dnl @synopsis AC_PROMPT_USER(VARIABLENAME,QUESTION,[DEFAULT],QUOTED)
dnl
dnl Asks a QUESTION and puts the results in VARIABLENAME with an optional
dnl DEFAULT value if the user merely hits return.  Also calls 
dnl AC_DEFINE_UNQUOTED() on the VARIABLENAME for VARIABLENAMEs that should
dnl be entered into the config.h file as well.  If QUOTED is "quoted" then
dnl the result will be defined within quotes.
dnl
dnl @version 1.15
dnl @author Wes Hardaker <hardaker@users.sourceforge.net>
dnl
AC_DEFUN([AC_PROMPT_USER],
[
MSG_CHECK=`echo "$2" | tail -1`
AC_CACHE_CHECK($MSG_CHECK, ac_cv_user_prompt_$1,
[echo "" >&AC_FD_MSG
AC_PROMPT_USER_NO_DEFINE($1,[$2],$3)
eval ac_cv_user_prompt_$1=\$$1
echo $ECHO_N "setting $MSG_CHECK to...  $ECHO_C" >&AC_FD_MSG
])
if test "$ac_cv_user_prompt_$1" != "none"; then
  if test "x$4" = "xquoted" -o "x$4" = "xQUOTED"; then
    AC_DEFINE_UNQUOTED($1,"$ac_cv_user_prompt_$1")
  else
    AC_DEFINE_UNQUOTED($1,$ac_cv_user_prompt_$1)
  fi
fi
]) dnl

dnl @synopsis AC_CHECK_STRUCT_FOR(INCLUDES,STRUCT,MEMBER,DEFINE,[no])
dnl
dnl Checks STRUCT for MEMBER and defines DEFINE if found.
dnl
dnl @version 1.15
dnl @author Wes Hardaker <hardaker@users.sourceforge.net>
dnl
AC_DEFUN([AC_CHECK_STRUCT_FOR],[

ac_safe_struct=`echo "$2" | sed 'y%./+-%__p_%'`
ac_safe_member=`echo "$3" | sed 'y%./+-%__p_%'`
ac_safe_all="ac_cv_struct_${ac_safe_struct}_has_${ac_safe_member}"
changequote(, )dnl
  ac_uc_define=STRUCT_`echo "${ac_safe_struct}_HAS_${ac_safe_member}" | sed 'y%abcdefghijklmnopqrstuvwxyz./-%ABCDEFGHIJKLMNOPQRSTUVWXYZ___%'`
changequote([, ])dnl

AC_MSG_CHECKING([for $2.$3])
AC_CACHE_VAL($ac_safe_all,
[
if test "x$4" = "x"; then
  defineit="= 0"
elif test "x$4" = "xno"; then
  defineit=""
else
  defineit="$4"
fi
AC_TRY_COMPILE([
$1
],[
struct $2 testit; 
testit.$3 $defineit;
], eval "${ac_safe_all}=yes", eval "${ac_safe_all}=no" )
])

if eval "test \"x$`echo ${ac_safe_all}`\" = \"xyes\""; then
  AC_MSG_RESULT(yes)
  AC_DEFINE_UNQUOTED($ac_uc_define)
else
  AC_MSG_RESULT(no)
fi

])

dnl
dnl Add a search path to the LIBS and CFLAGS variables
dnl
AC_DEFUN([AC_ADD_SEARCH_PATH],[
  if test "x$1" != x -a -d $1; then
     if test -d $1/lib; then
       LDFLAGS="-L$1/lib $LDFLAGS"
     fi
     if test -d $1/include; then
	CPPFLAGS="-I$1/include $CPPFLAGS"
     fi
  fi
])

dnl
dnl Store information for displaying later.
dnl
AC_DEFUN([AC_MSG_CACHE_INIT],[
  rm -f configure-summary
])

AC_DEFUN([AC_MSG_CACHE_ADD],[
  cat >> configure-summary << EOF
  $1
EOF
])

AC_DEFUN([AC_MSG_CACHE_DISPLAY],[
  echo ""
  echo "---------------------------------------------------------"
  echo "       DNSSEC-Tool Validator configuration summary:"
  echo "---------------------------------------------------------"
  echo ""
  cat configure-summary
  echo ""
  echo "---------------------------------------------------------"
  echo ""
])

AC_DEFUN([AC_MSG_MODULE_DBG],
[
  if test $module_debug = 1; then
    echo $1 $2 $3 $4
  fi
]
)
