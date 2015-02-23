include @top_srcdir@/include.mk

MODULES = yaws_logger_app.erl			\
	  yaws_logger_sup.erl			\
	  yaws_extended_logger.erl		\
	  yaws_logger_console.erl		\
	  yaws_logger_file.erl			\
	  yaws_logger_sysloggerl.erl		\
	  yaws_logger_lager.erl			\
	  yaws_logger_formatter.erl		\
	  lager_yaws_logger_proxy_backend.erl	\
	  yaws_logger_netutils.erl

EBIN_DIR=@top_builddir@/ebin
EBIN_FILES=$(MODULES:%.erl=$(EBIN_DIR)/%.beam)

EXTRA_DIST = yaws_logger.hrl

ERLC_FLAGS = $(ERLC_GENERIC_FLAGS)

erlsrcdir = $(ERLANG_INSTALL_LIB_DIR_yaws_logger)/src
dist_erlsrc_DATA = $(MODULES) yaws_logger.app.src yaws_logger.appup.src

include @top_srcdir@/erlang_deps.mk

all-local: $(EBIN_DIR)/yaws_logger.app $(EBIN_DIR)/yaws_logger.appup $(EBIN_FILES)

clean-local:
	$(AM_V_at)rm -f $(EBIN_DIR)/yaws_logger.app $(EBIN_DIR)/yaws_logger.appup $(EBIN_FILES)


$(EBIN_DIR)/yaws_logger.app: @srcdir@/yaws_logger.app.src
	$(AM_V_GEN)$(AWK) -v src="$(MODULES)"				\
	"/{vsn, *{cmd,/ {						\
		line = \$$0;						\
		sub(/{vsn.*/, \"{vsn, \\\"@YAWS_LOGGER_VSN@\\\"},\", line);\
		print line;						\
		next;							\
        }								\
        /%% DO NOT EDIT: Modules list is generated/ {			\
		indent = index(\$$0, \"%\");				\
		indent = substr(\$$0, 1, indent - 1);			\
		split(src, mods);					\
		mods_count = 0;						\
		for (mod in mods) {					\
			mods_count++					\
		}							\
		for (i = 1; i <= mods_count; i++) {			\
			mod = mods[i];					\
			sub(/\.erl/, \"\", mod);			\
			if (i != mods_count)				\
				print indent mod \",\";			\
			else						\
				print indent mod			\
		}							\
                next;                                                   \
        }                                                               \
        { print; }" $< > $@

$(EBIN_DIR)/yaws_logger.appup: @srcdir@/yaws_logger.appup.src
	$(AM_V_GEN)$(SED) "s/%VSN%/@YAWS_LOGGER_VSN@/g" < $< > $@

$(EBIN_DIR)/yaws_logger_console.beam   : $(EBIN_DIR)/yaws_extended_logger.beam
$(EBIN_DIR)/yaws_logger_file.beam      : $(EBIN_DIR)/yaws_extended_logger.beam
$(EBIN_DIR)/yaws_logger_sysloggerl.beam: $(EBIN_DIR)/yaws_extended_logger.beam
$(EBIN_DIR)/yaws_logger_lager.beam     : $(EBIN_DIR)/yaws_extended_logger.beam

$(EBIN_DIR)/%.beam: %.erl
	$(AM_V_at)$(ERLC) $(ERLC_FLAGS) -M -MF $(@:$(EBIN_DIR)/%.beam=$(DEPDIR)/%.Pbeam) -MT $@ $<
	$(AM_V_ERLC)$(ERLC) $(ERLC_FLAGS) -o $(EBIN_DIR) $<

distclean-local:
	$(AM_V_at)rm -fr $(DEPDIR)

# Local Variables:
#    tab-width: 8
# End:
