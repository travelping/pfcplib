%% Copyright 2017,2019 Travelping GmbH <info@travelping.com>

%% This program is free software; you can redistribute it and/or
%% modify it under the terms of the GNU General Public License
%% as published by the Free Software Foundation; either version
%% 2 of the License, or (at your option) any later version.

-module(pfcp_msg_SUITE).

-compile([export_all, nowarn_export_all]).

-include_lib("common_test/include/ct.hrl").
-include_lib("pfcplib/include/pfcp_packet.hrl").

%%%===================================================================
%%% API
%%%===================================================================

init_per_suite(Config) ->
    ct_property_test:init_per_suite(Config).

end_per_suite(_Config) ->
    ok.


all() ->
    [msg_enc_dec, validation, normalize].

%%%===================================================================
%%% Tests
%%%===================================================================

-define(match(Guard, Expr),
	((fun () ->
		  case (Expr) of
		      Guard -> ok;
		      V -> ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n",
				  [?FILE, ?LINE, ??Expr, ??Guard, V]),
			   error(badmatch)
		  end
	  end)())).

%%--------------------------------------------------------------------
msg_enc_dec() ->
    [{doc, "Check that Message encoding/decoding matches"}].
msg_enc_dec(Config) ->
    ct_property_test:quickcheck(pfcplib_prop:enc_dec_prop(Config), Config).

%%--------------------------------------------------------------------
validation() ->
    [{doc, "Check that Message validation works"}].

validation(_Config) ->
    Msg1 = #pfcp{type = heartbeat_request, ie = []},
    ?match({'EXIT', {badarg, _}}, (catch pfcp_packet:validate('Sxb', Msg1))),

    Msg2 = #pfcp{type = heartbeat_request, ie = #{}},
    ?match({'EXIT', {badarg, _}}, (catch pfcp_packet:validate('Sxb', Msg2))),

    Msg3 = #pfcp{type = heartbeat_request, ie = [#recovery_time_stamp{}, #recovery_time_stamp{}]},
    ?match(ok, (catch pfcp_packet:validate('Sxb', Msg3))),

    Msg4 = #pfcp{type = heartbeat_request,
		 ie = #{recovery_time_stamp => #recovery_time_stamp{}}},
    ?match(ok, (catch pfcp_packet:validate('Sxb', Msg4))),

    Msg5 = #pfcp{type = heartbeat_request,
		 ie = #{recovery_time_stamp => [#recovery_time_stamp{}]}},
    ?match(ok, (catch pfcp_packet:validate('Sxb', Msg5))),

    Msg6 = #pfcp{type = session_deletion_response,
		 ie = #{pfcp_cause                   => #pfcp_cause{},
			load_control_information     => #load_control_information{},
			offending_ie                 => #offending_ie{},
			overload_control_information => #overload_control_information{},
			recovery_time_stamp          => []
		       }},
    ?match(ok, (catch pfcp_packet:validate('Sxb', Msg6))),

    Msg7 = #pfcp{type = session_deletion_response,
		 ie = #{pfcp_cause                   => #pfcp_cause{},
			load_control_information     => [#load_control_information{}],
			offending_ie                 => [#offending_ie{}, #offending_ie{}],
			overload_control_information => []
		       }},
    ?match(ok, (catch pfcp_packet:validate('Sxb', Msg7))),

    Msg8 = #pfcp{type = session_deletion_response, ie = #{pfcp_cause => []}},
    ?match({'EXIT', {badarg, _}}, (catch pfcp_packet:validate('Sxb', Msg8))),

    Msg9 = #pfcp{type = session_modification_request, ie = #{}},
    ?match(ok, (catch pfcp_packet:validate('Sxb', Msg9))),

    Msg10 = #pfcp{type = session_modification_request,
		  ie = #{update_pdr =>
			     #update_pdr{
				group =
				    #{pdr_id => #pdr_id{}}
			       }
			}},
    ?match(ok, (catch pfcp_packet:validate('Sxb', Msg10))),

    Msg11 = #pfcp{type = session_modification_request,
		  ie = #{update_pdr =>
			     #update_pdr{
				group =
				    #{pdr_id => #pdr_id{}}
			       },
			 update_far =>
			     #update_far{
				group =
				    #{far_id => #far_id{},
				      update_forwarding_parameters =>
					  #update_forwarding_parameters{
					    group =
						 #{destination_interface =>
						       #destination_interface{}
						  }
					    }
				     }
			       }
			}},
    ?match(ok, (catch pfcp_packet:validate('Sxb', Msg11))),

    Msg12 = #pfcp{type = session_modification_request,
		  ie = #{update_pdr =>
			     #update_pdr{
				group =
				    #{urr_id => #urr_id{}}
			       }
			}},
    ?match({'EXIT', {badarg, _}}, (catch pfcp_packet:validate('Sxb', Msg12))),

    %% Usage Report is missing Mandatory IEs
    Msg13 = #pfcp{type = session_deletion_response,
		 ie = #{pfcp_cause                   => #pfcp_cause{},
			load_control_information     => #load_control_information{},
			offending_ie                 => #offending_ie{},
			overload_control_information => #overload_control_information{},
			usage_report_sdr             => #usage_report_sdr{},
			recovery_time_stamp          => []
		       }},
    ?match({'EXIT', {badarg, _}}, (catch pfcp_packet:validate('Sxb', Msg13))),

    Msg14 = #pfcp{type = session_modification_request, ie = []},
    ?match(ok, (catch pfcp_packet:validate('Sxb', Msg14))),

    Msg15 = #pfcp{type = session_modification_request,
		  ie = [#update_pdr{group = [#pdr_id{}]}]},
    ?match(ok, (catch pfcp_packet:validate('Sxb', Msg15))),

    Msg16 = #pfcp{type = session_modification_request,
		  ie = [#update_pdr{group = [#pdr_id{}]},
			#update_far{
			   group =
			       [#far_id{},
				#update_forwarding_parameters{
				   group = [#destination_interface{}]}]}]},
    ?match(ok, (catch pfcp_packet:validate('Sxb', Msg16))),

    Msg17 = #pfcp{type = session_modification_request,
		  ie = [#update_pdr{group = [#urr_id{}]}]},
    ?match({'EXIT', {badarg, _}}, (catch pfcp_packet:validate('Sxb', Msg17))),

    %% Usage Report is missing Mandatory IEs
    Msg18 = #pfcp{type = session_deletion_response,
		  ie = [#pfcp_cause{},
			#load_control_information{},
			#offending_ie{},
			#overload_control_information{},
			#usage_report_sdr{}]},
    ?match({'EXIT', {badarg, _}}, (catch pfcp_packet:validate('Sxb', Msg18))),
    ok.

normalize() ->
    [{doc, "Test nomalization of FQDNs"}].
normalize(_) ->
    Bin1 = pfcp_packet:encode(
	     #pfcp{version = v1, type = heartbeat_request, seq_no = 0,
		   ie = [#remote_gtp_u_peer{network_instance = <<"TesT">>}]}),
    ?match(#pfcp{ie = #{remote_gtp_u_peer := #remote_gtp_u_peer{network_instance = <<"test">>}}},
	   pfcp_packet:decode(Bin1)),

    Bin2 = pfcp_packet:encode(
	     #pfcp{version = v1, type = heartbeat_request, seq_no = 0,
		   ie = [#user_plane_ip_resource_information{network_instance = <<"TesT">>}]}),
    ?match(#pfcp{ie = #{user_plane_ip_resource_information :=
			    #user_plane_ip_resource_information{network_instance = <<"test">>}}},
	   pfcp_packet:decode(Bin2)),

    Bin3 = pfcp_packet:encode(
	     #pfcp{version = v1, type = heartbeat_request, seq_no = 0,
		   ie = [#network_instance{instance = <<"TesT">>}]}),
    ?match(#pfcp{ie = #{network_instance := #network_instance{instance = <<"test">>}}},
	   pfcp_packet:decode(Bin3)),

    Bin4 = pfcp_packet:encode(
	     #pfcp{version = v1, type = heartbeat_request, seq_no = 0,
		   ie = [#network_instance{instance = <<4, "TesT">>}]}),
    ?match(#pfcp{ie = #{network_instance := #network_instance{instance = <<4, "test">>}}},
	   pfcp_packet:decode(Bin4)),

    Bin5 = pfcp_packet:encode(
	     #pfcp{version = v1, type = heartbeat_request, seq_no = 0,
		   ie = [#node_id{id = [<<"TesT">>, <<"NET">>]}]}),
    ?match(#pfcp{ie = #{node_id := #node_id{id = [<<"test">>, <<"net">>]}}},
	   pfcp_packet:decode(Bin5)),

    Bin6 = pfcp_packet:encode(
	     #pfcp{version = v1, type = heartbeat_request, seq_no = 0,
		   ie = [#apn_dnn{apn = [<<"TesT">>, <<"NET">>]}]}),
    ?match(#pfcp{ie = #{apn_dnn := #apn_dnn{apn = [<<"test">>, <<"net">>]}}},
	   pfcp_packet:decode(Bin6)),

    Bin7 = pfcp_packet:encode(
	     #pfcp{version = v1, type = heartbeat_request, seq_no = 0,
		   ie = [#smf_set_id{fqdn = [<<"TesT">>, <<"NET">>]}]}),
    ?match(#pfcp{ie = #{smf_set_id := #smf_set_id{fqdn = [<<"test">>, <<"net">>]}}},
	   pfcp_packet:decode(Bin7)),
    ok.
