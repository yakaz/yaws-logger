dnl ------------------------------------------------------------------
dnl Autoconf initialization.
dnl ------------------------------------------------------------------
m4_define([VERSION_NUMBER], m4_esyscmd([. ./vsn.mk && printf '%s' ${YAWS_LOGGER_VSN}]))
AC_INIT([yaws_logger], VERSION_NUMBER)

AC_CONFIG_SRCDIR([src/yaws_logger_app.erl])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([ac-aux])

AM_INIT_AUTOMAKE([foreign])

AC_PREREQ([2.64])

ECHO=echo
COLORED_ECHO_INIT

dnl ------------------------------------------------------------------
dnl Internal functions for this configure script.
dnl ------------------------------------------------------------------

dnl Expand shell variables to have a nice output in the final report.
expand_var () {
	local v=`eval echo '$'[$]1`
	while test "`echo [$]v | grep [[$]] > /dev/null && echo nok`"; do
		v=`eval echo [$]v`
	done
	echo [$]v
}

dnl ------------------------------------------------------------------
dnl Compiler and other tools.
dnl ------------------------------------------------------------------
AM_SILENT_RULES([yes])
AC_PROG_INSTALL
AC_PROG_MAKE_SET
AC_PROG_SED

AM_SET_DEPDIR

dnl ------------------------------------------------------------------
dnl Erlang environment.
dnl ------------------------------------------------------------------
echo
COLORED_ECHO([%BErlang environment%b])

dnl Available flags.
AC_ARG_WITH([erlang],
	AC_HELP_STRING([--with-erlang=PREFIX],
        [prefix where build machine's Erlang is installed (optional)]),
	with_erlang=${withval%/},
	with_erlang="")

dnl erl(1) is used to compile Erlang modules.
if test "x${with_erlang}" = "x"; then
	AC_ERLANG_PATH_ERL
	AC_ERLANG_PATH_ERLC
else
	erl_path="${with_erlang}/bin"
	AC_ERLANG_PATH_ERL(, [$erl_path$PATH_SEPARATOR$PATH])
	AC_ERLANG_PATH_ERLC(, [$erl_path$PATH_SEPARATOR$PATH])
fi

if test "x${ERL}" = "x"; then
	AC_MSG_ERROR([
Erlang not found. Fill the ERL variable with erl(1) path or provide
Erlang prefix with --with-erlang.])
fi

dnl escript(1) is used by the testsuite.
AC_ARG_VAR([ESCRIPT], [Erlang/OTP interpreter command [autodetected]])

if test "x${ESCRIPT}" = "x"; then
	if test "x${with_erlang}" = "x"; then
		AC_PATH_PROG([ESCRIPT], [escript],,)
	else
		erl_path="${with_erlang}/bin"
		AC_PATH_PROG([ESCRIPT], [escript],,
		    [$erl_path$PATH_SEPARATOR$PATH])
	fi
else
	AC_MSG_CHECKING([for escript])
	AC_MSG_RESULT([$ESCRIPT])
fi

if test "x${ESCRIPT}" = "x"; then
	AC_MSG_WARN([
escript(1) not found. Fill the ESCRIPT variable with escript(1) path if
you want to use the testsuite.])
fi

dnl dialyzer(1) is used by the testsuite.
AC_ARG_VAR([DIALYZER], [Erlang/OTP discrepancy analyzer [autodetected]])

if test "x${DIALYZER}" = "x"; then
	if test "x${with_erlang}" = "x"; then
		AC_PATH_PROG([DIALYZER], [dialyzer],,)
	else
		erl_path="${with_erlang}/bin"
		AC_PATH_PROG([DIALYZER], [dialyzer],,
		    [$erl_path$PATH_SEPARATOR$PATH])
	fi
else
	AC_MSG_CHECKING([for dialyzer])
	AC_MSG_RESULT([$DIALYZER])
fi

if test "x${DIALYZER}" = "x"; then
	AC_MSG_WARN([
dialyzer(1) not found. Fill the DIALYZER variable with dialyzer(1) path if
you want it to be run during the testsuite.])
fi

dnl Declare ERL_LIBS as precious.
AC_ARG_VAR([ERL_LIBS], [Erlang/OTP applications search path [none]])

dnl Get Erlang $ROOT dir and lib dir.
AC_ERLANG_SUBST_ROOT_DIR
AC_ERLANG_SUBST_LIB_DIR

dnl Get ERTS version.
ERLANG_CHECK_ERTS
ERLANG_CHECK_RELEASE

dnl Erlang R14B02 (ERTS 5.8.3) is required.
AX_COMPARE_VERSION([${ERLANG_ERTS_VER}], [ge], [5.8.3],
    [is_erlang_r14b02="yes"],
    [is_erlang_r14b02="no"])
if test "x${is_erlang_r14b02}" = "xno"; then
	AC_MSG_ERROR([
Erlang R14B02 is required but only Erlang $ERLANG_RELEASE was found!])
fi

dnl Determine directories for installation.
if test "x${prefix}" != "xNONE" -a "x${ERLANG_INSTALL_LIB_DIR}" = "x"; then
    dnl Under $prefix
    ERLANG_INSTALL_LIB_DIR='${prefix}'
else
    dnl Under default erlang libdir
    ERLANG_INSTALL_LIB_DIR='${ERLANG_LIB_DIR}'
fi


AC_ERLANG_SUBST_INSTALL_LIB_DIR

. ${srcdir}/vsn.mk
AC_SUBST(YAWS_LOGGER_VSN)

AC_ERLANG_SUBST_INSTALL_LIB_SUBDIR(AC_PACKAGE_NAME, ${YAWS_LOGGER_VSN})

dnl ------------------------------------------------------------------
dnl Erlang applicatons.
dnl ------------------------------------------------------------------
AC_ERLANG_CHECK_LIB([kernel],,   [AC_MSG_ERROR(["kernel" Erlang application not found.])])
AC_ERLANG_CHECK_LIB([stdlib],,   [AC_MSG_ERROR(["stdlib" Erlang application not found.])])
AC_ERLANG_CHECK_LIB([erts],,     [AC_MSG_ERROR(["erts" Erlang application not found.])])
AC_ERLANG_CHECK_LIB([yaws],,     [AC_MSG_ERROR(["yaws" Erlang application not found.])])

dnl dnl "yaws" install directory.
dnl AC_ARG_WITH([yaws],
dnl         AC_HELP_STRING([--with-yaws=PREFIX],
dnl                        [prefix where the "yaws" Erlang application is installed (optional)]),
dnl         with_yaws=${withval%/},
dnl         with_yaws="")

dnl ERL_LIBS_save=$ERL_LIBS
dnl if test "x${with_yaws}" != "x"; then
dnl         ERL_LIBS="${with_yaws}:${ERL_LIBS}"
dnl fi
dnl export ERL_LIBS
dnl AC_ERLANG_CHECK_LIB([yaws],, [AC_MSG_ERROR(["yaws" Erlang application not found.
dnl Provide yaws install path with --with-yaws.])])
dnl ERL_LIBS=$ERL_LIBS_save
dnl export ERL_LIBS

dnl dnl Yaws 1.90 is required.
dnl AX_COMPARE_VERSION([${ERLANG_LIB_VER_yaws}], [ge], [1.90],
dnl     [is_yaws_190="yes"],
dnl     [is_yaws_190="no"])
dnl if test "x${is_yaws_190}" = "xno"; then
dnl 	AC_MSG_ERROR([
dnl Yaws 1.90 is required but only Yaws $ERLANG_LIB_VER_yaws was found!])
dnl fi


dnl ------------------------------------------------------------------
dnl Final substitutions.
dnl ------------------------------------------------------------------
exp_ERLANG_INSTALL_LIB_DIR_yaws_logger=`expand_var ERLANG_INSTALL_LIB_DIR_yaws_logger`
AC_SUBST(exp_ERLANG_INSTALL_LIB_DIR_yaws_logger)

dnl ------------------------------------------------------------------
dnl Autoconf output.
dnl ------------------------------------------------------------------
AC_SUBST([CONFIG_STATUS_DEPENDENCIES], ['$(top_srcdir)/vsn.mk'])

echo
AM_CONFIG_HEADER([config.h])
AC_CONFIG_FILES([
	src/Makefile
	ebin/Makefile
	Makefile
])
AC_OUTPUT

dnl --------------------------------------------------
dnl Configuration report
dnl --------------------------------------------------
echo
COLORED_ECHO([ %B== ${PACKAGE_NAME} ${YAWS_LOGGER_VSN} ==%b])
echo
COLORED_ECHO([Configuration:])
COLORED_ECHO([ %BApplication dir.%b:     ${exp_ERLANG_INSTALL_LIB_DIR_yaws_logger}])
echo
COLORED_ECHO([ %BErlang root dir%b:    ${ERLANG_ROOT_DIR}])
COLORED_ECHO([ %BErlang lib dir%b:     ${ERLANG_LIB_DIR}])
COLORED_ECHO([ %BErlang emulator%b:    ${ERL}])
COLORED_ECHO([ %BErlang compiler%b:    ${ERLC}])
COLORED_ECHO([ %BErlang interpreter%b: ${ESCRIPT}])
echo
