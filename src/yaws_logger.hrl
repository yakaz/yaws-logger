%% $Id$

-ifdef(debug).

-define(PREFIX_FORMAT, " -- ~20s:~-4b -- ~p -- ").
-define(PREFIX_ARGS, [?MODULE, ?LINE, self()]).

-define(ERROR(Format, Args),   yaws_logger_log:error_msg(?PREFIX_FORMAT++Format,
                                                         ?PREFIX_ARGS++Args)).
-define(WARNING(Format, Args), yaws_logger_log:warning_msg(?PREFIX_FORMAT++Format,
                                                           ?PREFIX_ARGS++Args)).
-define(INFO(Format, Args),    yaws_logger_log:info_msg(?PREFIX_FORMAT++Format,
                                                        ?PREFIX_ARGS++Args)).
-define(DEBUG(Format, Args),   yaws_logger_log:debug_msg(?PREFIX_FORMAT++Format,
                                                         ?PREFIX_ARGS++Args)).
-else.
-define(ERROR(Format, Args),   yaws_logger_log:error_msg(Format, Args)).
-define(WARNING(Format, Args), yaws_logger_log:warning_msg(Format, Args)).
-define(INFO(Format, Args),    yaws_logger_log:info_msg(Format, Args)).
-define(DEBUG(Format, Args),   yaws_logger_log:debug_msg(Format, Args)).
-endif.
