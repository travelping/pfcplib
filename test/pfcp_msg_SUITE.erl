%% Copyright 2017, Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(pfcp_msg_SUITE).

-compile(export_all).

-include_lib("common_test/include/ct.hrl").

%%%===================================================================
%%% API
%%%===================================================================

init_per_suite(Config) ->
    ct_property_test:init_per_suite(Config).

end_per_suite(_Config) ->
    ok.


all() ->
    [msg_enc_dec].

%%%===================================================================
%%% Tests
%%%===================================================================

%%--------------------------------------------------------------------
msg_enc_dec() ->
    [{doc, "Check that Message encoding/decoding matches"}].
msg_enc_dec(Config) ->
    ct_property_test:quickcheck(pfcplib_prop:enc_dec_prop(Config), Config).
