%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

%% Copyright 2017, Travelping GmbH <info@travelping.com>

-module(pfcplib_prop).

-compile([export_all, nowarn_export_all]).

-include_lib("pfcplib/include/pfcp_packet.hrl").

-proptest(proper).
-proptest([triq,eqc]).

-ifndef(EQC).
-ifndef(PROPER).
-ifndef(TRIQ).
-define(PROPER,true).
%%-define(EQC,true).
%%-define(TRIQ,true).
-endif.
-endif.
-endif.

-ifdef(EQC).
-include_lib("eqc/include/eqc.hrl").
-define(MOD_eqc,eqc).

-else.
-ifdef(PROPER).
-include_lib("proper/include/proper.hrl").
-define(MOD_eqc,proper).

-else.
-ifdef(TRIQ).
-define(MOD_eqc,triq).
-include_lib("triq/include/triq.hrl").

-endif.
-endif.
-endif.

-define(equal(Expected, Actual),
    (fun (Expected@@@, Expected@@@) -> true;
	 (Expected@@@, Actual@@@) ->
	     ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~p~nActual:   ~p~n",
		    [?FILE, ?LINE, ??Actual, Expected@@@, Actual@@@]),
	     false
     end)(Expected, Actual) orelse error(badmatch)).

%%%===================================================================
%%% Tests
%%%===================================================================

%%--------------------------------------------------------------------
enc_dec_prop(Config) ->
    numtests(10000,
	     ?FORALL(Msg, msg_gen(),
		     begin
			 Enc = pfcp_packet:encode(Msg),
			 ?equal(Enc, pfcp_packet:encode(pfcp_packet:decode(Enc)))
		     end)).

%%%===================================================================
%%% Internal functions
%%%===================================================================

dns_label() ->
    ?LET(I, integer(1,63),
	 vector(I,
		oneof(
		  lists:seq($A, $Z) ++ lists:seq($a, $z) ++ lists:seq($0, $9) ++ [$-]))).

dns_name_list() ->
    ?SUCHTHAT(N,
	      ?LET(I, integer(1,7), vector(I, dns_label())),
	      length(lists:flatten(N)) < 100).

dns_name() ->
    ?LET(L, dns_name_list(),
	 [list_to_binary(X) || X <- L]).

uint16() ->
    integer(0,16#ffff).

uint32() ->
    integer(0,16#ffffffff).

uint64() ->
    integer(0,16#ffffffffffffffff).

ip4_address() ->
    binary(4).

ip6_address() ->
    binary(16).

msg_gen() ->
    #pfcp{
      version = v1,
      type = msg_type(),
      seid = integer(0,16#ffffffff),
      seq_no = integer(0,16#ffffff),
      ie = [ie()]
     }.

msg_type() ->
    oneof([
	   heartbeat_request,
	   heartbeat_response,
	   pfd_management_request,
	   pfd_management_response,
	   association_setup_request,
	   association_setup_response,
	   association_update_request,
	   association_update_response,
	   association_release_request,
	   association_release_response,
	   version_not_supported_response,
	   node_report_request,
	   node_report_response,
	   session_set_deletion_request,
	   session_set_deletion_response,
	   session_establishment_request,
	   session_establishment_response,
	   session_modification_request,
	   session_modification_response,
	   session_deletion_request,
	   session_deletion_response,
	   session_report_request,
	   session_report_response
	  ]).

ie() ->
    oneof([
	   gen_create_pdr(),
	   gen_pdi(),
	   gen_create_far(),
	   gen_forwarding_parameters(),
	   gen_duplicating_parameters(),
	   gen_create_urr(),
	   gen_create_qer(),
	   gen_created_pdr(),
	   gen_update_pdr(),
	   gen_update_far(),
	   gen_update_forwarding_parameters(),
	   gen_update_bar_response(),
	   gen_update_urr(),
	   gen_update_qer(),
	   gen_remove_pdr(),
	   gen_remove_far(),
	   gen_remove_urr(),
	   gen_remove_qer(),
	   gen_cause(),
	   gen_source_interface(),
	   gen_f_teid(),
	   gen_network_instance(),
	   gen_sdf_filter(),
	   gen_application_id(),
	   gen_gate_status(),
	   gen_mbr(),
	   gen_gbr(),
	   gen_qer_correlation_id(),
	   gen_precedence(),
	   gen_transport_level_marking(),
	   gen_volume_threshold(),
	   gen_time_threshold(),
	   gen_monitoring_time(),
	   gen_subsequent_volume_threshold(),
	   gen_subsequent_time_threshold(),
	   gen_inactivity_detection_time(),
	   gen_reporting_triggers(),
	   gen_redirect_information(),
	   gen_report_type(),
	   gen_offending_ie(),
	   gen_forwarding_policy(),
	   gen_destination_interface(),
	   gen_up_function_features(),
	   gen_apply_action(),
	   gen_downlink_data_service_information(),
	   gen_downlink_data_notification_delay(),
	   gen_dl_buffering_duration(),
	   gen_dl_buffering_suggested_packet_count(),
	   gen_sxsmreq_flags(),
	   gen_sxsrrsp_flags(),
	   gen_load_control_information(),
	   gen_sequence_number(),
	   gen_metric(),
	   gen_overload_control_information(),
	   gen_timer(),
	   gen_pdr_id(),
	   gen_f_seid(),
	   gen_application_id_pfds(),
	   gen_pfd_context(),
	   gen_node_id(),
	   gen_pfd_contents(),
	   gen_measurement_method(),
	   gen_usage_report_trigger(),
	   gen_measurement_period(),
	   gen_fq_csid(),
	   gen_volume_measurement(),
	   gen_duration_measurement(),
	   gen_application_detection_information(),
	   gen_time_of_first_packet(),
	   gen_time_of_last_packet(),
	   gen_quota_holding_time(),
	   gen_dropped_dl_traffic_threshold(),
	   gen_volume_quota(),
	   gen_time_quota(),
	   gen_start_time(),
	   gen_end_time(),
	   gen_query_urr(),
	   gen_usage_report_smr(),
	   gen_usage_report_sdr(),
	   gen_usage_report_srr(),
	   gen_urr_id(),
	   gen_linked_urr_id(),
	   gen_downlink_data_report(),
	   gen_outer_header_creation(),
	   gen_create_bar(),
	   gen_update_bar_request(),
	   gen_remove_bar(),
	   gen_bar_id(),
	   gen_cp_function_features(),
	   gen_usage_information(),
	   gen_application_instance_id(),
	   gen_flow_information(),
	   gen_ue_ip_address(),
	   gen_packet_rate(),
	   gen_outer_header_removal(),
	   gen_recovery_time_stamp(),
	   gen_dl_flow_level_marking(),
	   gen_header_enrichment(),
	   gen_error_indication_report(),
	   gen_measurement_information(),
	   gen_node_report_type(),
	   gen_user_plane_path_failure_report(),
	   gen_remote_gtp_u_peer(),
	   gen_ur_seqn(),
	   gen_update_duplicating_parameters(),
	   gen_activate_predefined_rules(),
	   gen_deactivate_predefined_rules(),
	   gen_far_id(),
	   gen_qer_id(),
	   gen_oci_flags(),
	   gen_sx_association_release_request(),
	   gen_graceful_release_period(),
	   gen_pdn_type(),
	   gen_failed_rule_id(),
	   gen_time_quota_mechanism(),
	   gen_user_plane_ip_resource_information()
	  ]).

gen_create_pdr() ->
    #create_pdr{group = []}.

gen_pdi() ->
    #pdi{group = []}.

gen_create_far() ->
    #create_far{group = []}.

gen_forwarding_parameters() ->
    #forwarding_parameters{group = []}.

gen_duplicating_parameters() ->
    #duplicating_parameters{group = []}.

gen_create_urr() ->
    #create_urr{group = []}.

gen_create_qer() ->
    #create_qer{group = []}.

gen_created_pdr() ->
    #created_pdr{group = []}.

gen_update_pdr() ->
    #update_pdr{group = []}.

gen_update_far() ->
    #update_far{group = []}.

gen_update_forwarding_parameters() ->
    #update_forwarding_parameters{group = []}.

gen_update_bar_response() ->
    #update_bar_response{group = []}.

gen_update_urr() ->
    #update_urr{group = []}.

gen_update_qer() ->
    #update_qer{group = []}.

gen_remove_pdr() ->
    #remove_pdr{group = []}.

gen_remove_far() ->
    #remove_far{group = []}.

gen_remove_urr() ->
    #remove_urr{group = []}.

gen_remove_qer() ->
    #remove_qer{group = []}.

gen_cause() ->
    #cause{}.

gen_source_interface() ->
    #source_interface{}.

gen_f_teid() ->
    #f_teid{}.

gen_network_instance() ->
    #network_instance{instance = dns_name()}.

gen_sdf_filter() ->
    #sdf_filter{}.

gen_application_id() ->
    #application_id{}.

gen_gate_status() ->
    #gate_status{}.

gen_mbr() ->
    #mbr{}.

gen_gbr() ->
    #gbr{}.

gen_qer_correlation_id() ->
    #qer_correlation_id{}.

gen_precedence() ->
    #precedence{}.

gen_transport_level_marking() ->
    #transport_level_marking{}.

gen_volume_threshold() ->
    #volume_threshold{}.

gen_time_threshold() ->
    #time_threshold{}.

gen_monitoring_time() ->
    #monitoring_time{}.

gen_subsequent_volume_threshold() ->
    #subsequent_volume_threshold{}.

gen_subsequent_time_threshold() ->
    #subsequent_time_threshold{}.

gen_inactivity_detection_time() ->
    #inactivity_detection_time{}.

gen_reporting_triggers() ->
    #reporting_triggers{}.

gen_redirect_information() ->
    #redirect_information{}.

gen_report_type() ->
    #report_type{}.

gen_offending_ie() ->
    #offending_ie{}.

gen_forwarding_policy() ->
    #forwarding_policy{}.

gen_destination_interface() ->
    #destination_interface{}.

gen_up_function_features() ->
    #up_function_features{}.

gen_apply_action() ->
    #apply_action{}.

gen_downlink_data_service_information() ->
    #downlink_data_service_information{}.

gen_downlink_data_notification_delay() ->
    #downlink_data_notification_delay{}.

gen_dl_buffering_duration() ->
    #dl_buffering_duration{}.

gen_dl_buffering_suggested_packet_count() ->
    #dl_buffering_suggested_packet_count{}.

gen_sxsmreq_flags() ->
    #sxsmreq_flags{}.

gen_sxsrrsp_flags() ->
    #sxsrrsp_flags{}.

gen_load_control_information() ->
    #load_control_information{group = []}.

gen_sequence_number() ->
    #sequence_number{}.

gen_metric() ->
    #metric{}.

gen_overload_control_information() ->
    #overload_control_information{group = []}.

gen_timer() ->
    #timer{}.

gen_pdr_id() ->
    #pdr_id{}.

gen_f_seid() ->
    #f_seid{
       seid = uint64(),
       ipv4 = oneof([undefined, ip4_address()]),
       ipv6 = oneof([undefined, ip6_address()])
      }.

gen_application_id_pfds() ->
    #application_id_pfds{group = []}.

gen_pfd_context() ->
    #pfd_context{group = []}.

gen_node_id() ->
    #node_id{id = oneof([ip4_address(), ip6_address(), dns_name()])}.

gen_pfd_contents() ->
    #pfd_contents{}.

gen_measurement_method() ->
    #measurement_method{}.

gen_usage_report_trigger() ->
    #usage_report_trigger{}.

gen_measurement_period() ->
    #measurement_period{}.

gen_fq_csid() ->
    #fq_csid{}.

gen_volume_measurement() ->
    #volume_measurement{}.

gen_duration_measurement() ->
    #duration_measurement{}.

gen_application_detection_information() ->
    #application_detection_information{group = []}.

gen_time_of_first_packet() ->
    #time_of_first_packet{}.

gen_time_of_last_packet() ->
    #time_of_last_packet{}.

gen_quota_holding_time() ->
    #quota_holding_time{}.

gen_dropped_dl_traffic_threshold() ->
    #dropped_dl_traffic_threshold{}.

gen_volume_quota() ->
    #volume_quota{}.

gen_time_quota() ->
    #time_quota{}.

gen_start_time() ->
    #start_time{}.

gen_end_time() ->
    #end_time{}.

gen_query_urr() ->
    #query_urr{group = []}.

gen_usage_report_smr() ->
    #usage_report_smr{group = []}.

gen_usage_report_sdr() ->
    #usage_report_sdr{group = []}.

gen_usage_report_srr() ->
    #usage_report_srr{group = []}.

gen_urr_id() ->
    #urr_id{}.

gen_linked_urr_id() ->
    #linked_urr_id{}.

gen_downlink_data_report() ->
    #downlink_data_report{group = []}.

gen_outer_header_creation() ->
    oneof(
      [#outer_header_creation{
	  type = 'GTP-U/UDP/IPv4', teid = uint32(), address = ip4_address()},
       #outer_header_creation{
	  type = 'GTP-U/UDP/IPv6', teid = uint32(), address = ip6_address()},
       #outer_header_creation{
	  type = 'UDP/IPv4', address = ip4_address(), port = uint16()},
       #outer_header_creation{
	  type = 'UDP/IPv6', address = ip6_address(), port = uint16()}
      ]).

gen_create_bar() ->
    #create_bar{group = []}.

gen_update_bar_request() ->
    #update_bar_request{group = []}.

gen_remove_bar() ->
    #remove_bar{group = []}.

gen_bar_id() ->
    #bar_id{}.

gen_cp_function_features() ->
    #cp_function_features{}.

gen_usage_information() ->
    #usage_information{}.

gen_application_instance_id() ->
    #application_instance_id{}.

gen_flow_information() ->
    #flow_information{}.

gen_ue_ip_address() ->
    #ue_ip_address{}.

gen_packet_rate() ->
    #packet_rate{}.

gen_outer_header_removal() ->
    #outer_header_removal{}.

gen_recovery_time_stamp() ->
    #recovery_time_stamp{}.

gen_dl_flow_level_marking() ->
    #dl_flow_level_marking{}.

gen_header_enrichment() ->
    #header_enrichment{}.

gen_error_indication_report() ->
    #error_indication_report{group = []}.

gen_measurement_information() ->
    #measurement_information{}.

gen_node_report_type() ->
    #node_report_type{}.

gen_user_plane_path_failure_report() ->
    #user_plane_path_failure_report{group = []}.

gen_remote_gtp_u_peer() ->
    #remote_gtp_u_peer{}.

gen_ur_seqn() ->
    #ur_seqn{}.

gen_update_duplicating_parameters() ->
    #update_duplicating_parameters{group = []}.

gen_activate_predefined_rules() ->
    #activate_predefined_rules{}.

gen_deactivate_predefined_rules() ->
    #deactivate_predefined_rules{}.

gen_far_id() ->
    #far_id{}.

gen_qer_id() ->
    #qer_id{}.

gen_oci_flags() ->
    #oci_flags{}.

gen_sx_association_release_request() ->
    #sx_association_release_request{}.

gen_graceful_release_period() ->
    #graceful_release_period{}.

gen_pdn_type() ->
    #pdn_type{}.

id_range(bar) -> integer(0, 16#ff);
id_range(_)   -> integer(0, 16#ffffffff).

gen_failed_rule_id() ->
    ?LET(Type, oneof([pdr, far, qer, urr, bar]),
	 #failed_rule_id{
	    type = Type,
	    id = id_range(Type)
	   }
	).

gen_time_quota_mechanism() ->
    #time_quota_mechanism{}.

gen_user_plane_ip_resource_information() ->
    #user_plane_ip_resource_information{}.
