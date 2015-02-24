dnl
dnl More functions to query Erlang environment.
dnl

dnl ERLANG_CHECK_ERTS([ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]])
dnl Substitudes
dnl   ERLANG_ERTS_DIR
dnl   ERLANG_ERTS_VER
AC_DEFUN([ERLANG_CHECK_ERTS],
[
AC_REQUIRE([AC_ERLANG_PATH_ERLC])[]dnl
AC_REQUIRE([AC_ERLANG_PATH_ERL])[]dnl
AC_REQUIRE([AC_ERLANG_SUBST_ROOT_DIR])[]dnl
AC_CACHE_CHECK([for Erlang/OTP ERTS version],
  [erlang_cv_erts_ver],
  [
    AC_LANG_PUSH(Erlang)[]dnl
    AC_RUN_IFELSE(
      [AC_LANG_PROGRAM([], [dnl
        file:write_file("conftest.out", erlang:system_info(version)),
        halt(0)])],
      [erlang_cv_erts_ver=`cat conftest.out`],
      [if test ! -f conftest.out; then
         AC_MSG_FAILURE([test Erlang program execution failed])
       else
         erlang_cv_erts_ver="not found"
       fi])
    AC_LANG_POP(Erlang)[]dnl
  ])
AC_CACHE_CHECK([for Erlang/OTP ERTS directory],
  [erlang_cv_erts_dir],
  [
    erlang_cv_erts_dir="${ERLANG_ROOT_DIR}/erts-$erlang_cv_erts_ver"
    if test ! -d "$erlang_cv_erts_dir"; then
      erlang_cv_erts_dir="${ERLANG_ROOT_DIR}/usr"
    fi
  ])
AC_SUBST([ERLANG_ERTS_DIR], [$erlang_cv_erts_dir])
AC_SUBST([ERLANG_ERTS_VER], [$erlang_cv_erts_ver])
AS_IF([test "$erlang_cv_erts_ver" = "not found"], [$2], [$1])
])

dnl ERLANG_CHECK_RELEASE()
dnl Substitudes
dnl   ERLANG_RELEASE
AC_DEFUN([ERLANG_CHECK_RELEASE],
[
AC_REQUIRE([AC_ERLANG_PATH_ERLC])[]dnl
AC_REQUIRE([AC_ERLANG_PATH_ERL])[]dnl
AC_REQUIRE([AC_ERLANG_SUBST_ROOT_DIR])[]dnl
AC_CACHE_CHECK([for Erlang/OTP release],
  [erlang_cv_release],
  [
    AC_LANG_PUSH(Erlang)[]dnl
    AC_RUN_IFELSE(
      [AC_LANG_PROGRAM([], [dnl
        file:write_file("conftest.out", erlang:system_info(otp_release)),
        halt(0)])],
      [erlang_cv_release=`cat conftest.out`],
      [if test ! -f conftest.out; then
         AC_MSG_FAILURE([test Erlang program execution failed])
       else
         erlang_cv_release="not found"
       fi])
    AC_LANG_POP(Erlang)[]dnl
  ])
AC_SUBST([ERLANG_RELEASE], [$erlang_cv_release])
])


dnl AC_ERLANG_CHECK_LIB(LIBRARY, [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND])
dnl  Override the default macro to retrieve the library version in erlang
dnl
AC_DEFUN([AC_ERLANG_CHECK_LIB],
[AC_REQUIRE([AC_ERLANG_PATH_ERLC])[]dnl
AC_REQUIRE([AC_ERLANG_PATH_ERL])[]dnl
AC_CACHE_CHECK([for Erlang/OTP '$1' library subdirectory],
    [ac_cv_erlang_lib_dir_$1],
    [AC_LANG_PUSH(Erlang)[]dnl
     AC_RUN_IFELSE(
	[AC_LANG_PROGRAM([], [dnl
	    ReturnValue = case code:lib_dir("[$1]") of
	    {error, bad_name} ->
		file:write_file("conftest.out", "not found\n"),
		1;
	    LibDir ->
		file:write_file("conftest.out", LibDir),
		0
	    end,
	    halt(ReturnValue)])],
	[ac_cv_erlang_lib_dir_$1=`cat conftest.out`
	 rm -f conftest.out],
	[if test ! -f conftest.out; then
	     AC_MSG_FAILURE([test Erlang program execution failed])
	 else
	     ac_cv_erlang_lib_dir_$1="not found"
	     rm -f conftest.out
	 fi])
     AC_LANG_POP(Erlang)[]dnl
    ])
AC_CACHE_CHECK([for Erlang/OTP '$1' library version],
    [ac_cv_erlang_lib_ver_$1],
    [AS_IF([test "$ac_cv_erlang_lib_dir_$1" = "not found"],
	[ac_cv_erlang_lib_ver_$1="not found"],
    [AC_LANG_PUSH(Erlang)[]dnl
     AC_RUN_IFELSE(
	[AC_LANG_PROGRAM([], [dnl
	    AppFile = filename:join([["$ac_cv_erlang_lib_dir_$1", "ebin", "$1.app"]]),
	    ReturnValue = case file:consult(AppFile) of
	    {error, _} ->
		file:write_file("conftest.out", "not found\n"),
		1;
	    {ok, [[{application, $1, AppVars}]]} ->
		Vsn = proplists:get_value(vsn, AppVars, "not found"),
		file:write_file("conftest.out", Vsn),
		0
	    end,
	    halt(ReturnValue)])],
	[ac_cv_erlang_lib_ver_$1=`cat conftest.out`
	 rm -f conftest.out],
	[if test ! -f conftest.out; then
	     AC_MSG_FAILURE([test Erlang program execution failed])
	 else
	     ac_cv_erlang_lib_ver_$1="not found"
	     rm -f conftest.out
	 fi])
     AC_LANG_POP(Erlang)[]dnl
    ])[]dnl
    ])
AC_SUBST([ERLANG_LIB_DIR_$1], [$ac_cv_erlang_lib_dir_$1])
AC_SUBST([ERLANG_LIB_VER_$1], [$ac_cv_erlang_lib_ver_$1])
AS_IF([test "$ac_cv_erlang_lib_dir_$1" = "not found"], [$3], [$2])
])# AC_ERLANG_CHECK_LIB
