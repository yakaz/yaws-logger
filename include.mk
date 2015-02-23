AM_V_ERLC = $(am__v_ERLC_$(V))
am__v_ERLC_ = $(am__v_ERLC_$(AM_DEFAULT_VERBOSITY))
am__v_ERLC_0 = @echo "  ERLC    " $@;
am__v_ERLC_1 =

ERLC_GENERIC_FLAGS = -Werror +debug_info -I$(top_srcdir)/include			\
		     -pa $(top_srcdir) -pa $(top_builddir) -pa $(top_builddir)/ebin	\
		     -pa $(ERLANG_LIB_DIR_yaws)/ebin

# Local Variables:
#    tab-width: 8
# End:
