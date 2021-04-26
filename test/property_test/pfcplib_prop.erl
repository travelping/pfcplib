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
	     ct:pal("MISMATCH(~s:~b, ~s)~nExpected: ~s~nActual:   ~s~n",
		    [?FILE, ?LINE, ??Actual,
		     pfcp_packet:pretty_print(Expected@@@),
		     pfcp_packet:pretty_print(Actual@@@)]),
	     false
     end)(Expected, Actual) orelse error(badmatch)).

%%%===================================================================
%%% Tests
%%%===================================================================

%%--------------------------------------------------------------------
enc_dec_prop(Config) ->
    numtests(1000,
	     ?FORALL(Msg, msg_gen(),
		     begin
			 ?equal(pfcp_packet:to_map(Msg),
				pfcp_packet:decode(pfcp_packet:encode(Msg)))
		     end)).

%%%===================================================================
%%% Generate PCAP with random (but valid PFCP packets)
%%%===================================================================

-define(PCAPNG_VERSION_MAJOR, 1).
-define(PCAPNG_VERSION_MINOR, 0).
-define(LINKTYPE_ETHERNET, 1).
-define(LINKTYPE_RAW, 101).

make_udp(NwSrc, NwDst, TpSrc, TpDst, PayLoad) ->
    Id = 0,
    Proto = gen_socket:protocol(udp),

    UDPLength = 8 + size(PayLoad),
    UDPCSum = flower_tools:ip_csum(<<NwSrc:4/bytes-unit:8, NwDst:4/bytes-unit:8,
				     0:8, Proto:8, UDPLength:16,
				     TpSrc:16, TpDst:16, UDPLength:16, 0:16,
				     PayLoad/binary>>),
    UDP = <<TpSrc:16, TpDst:16, UDPLength:16, UDPCSum:16, PayLoad/binary>>,

    TotLen = 20 + size(UDP),
    HdrCSum = flower_tools:ip_csum(<<4:4, 5:4, 0:8, TotLen:16,
				     Id:16, 0:16, 64:8, Proto:8,
				     0:16/integer, NwSrc:4/bytes-unit:8, NwDst:4/bytes-unit:8>>),
    IP = <<4:4, 5:4, 0:8, TotLen:16,
	   Id:16, 0:16, 64:8, Proto:8,
	   HdrCSum:16/integer, NwSrc:4/bytes-unit:8, NwDst:4/bytes-unit:8>>,
    list_to_binary([IP, UDP]).

format_pcapng(Data) ->
    TStamp = os:system_time(micro_seconds),
    Len = size(Data),
    pcapng:encode({epb, 0, TStamp, Len, [], Data}).

pcapng_shb() ->
    pcapng:encode({shb, {?PCAPNG_VERSION_MAJOR, ?PCAPNG_VERSION_MINOR},
		   [{os, <<"CAROS">>}, {userappl, <<"CAPWAP">>}]}).

pcapng_ifd(Name) ->
    pcapng:encode({ifd, ?LINKTYPE_RAW, 65535,
		   [{name,    Name},
		    {tsresol, <<6>>},
		    {os,      <<"CAROS">>}]}).

pcap_msg(Msg, Io) ->
    Data = pfcp_packet:encode(Msg),
    Packet = make_udp(<<127,0,0,1>>, <<127,0,0,2>>, 8805, 8805, Data),
    Dump = format_pcapng(Packet),
    ok = file:write(Io, Dump).

gen_pcap(0, _Io) ->
    ok;
gen_pcap(Cnt, Io) ->
    {ok, Msg} = proper_gen:pick(msg_gen()),
    pcap_msg(Msg, Io),
    gen_pcap(Cnt - 1, Io).

gen_pcap(Cnt) ->
    {ok, Io} = file:open("pfcp.pcap", [write, raw]),
    Header = << (pcapng_shb())/binary, (pcapng_ifd(<<"PFCP">>))/binary >>,
    file:write(Io, Header),
    gen_pcap(Cnt, Io),
    file:close(Io).

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% proper generates a random value for integers. That does not
%% guarantee that the full range of the integer value is tested.
%% Include Min and Max explicitly to ensure the full range is covered.
int_range(Min, Max) ->
    oneof([integer(Min, Max), Min, Max]).

encode_dns_label(Labels) ->
    ?LET(Name, Labels,
	 << <<(size(Label)):8, Label/binary>> || Label <- Name >>).

flag() ->
    oneof([0,1]).

string(I) ->
    vector(I,
	   oneof(
	     lists:seq($A, $Z) ++ lists:seq($a, $z) ++ lists:seq($0, $9) ++ [$-])).

dns_label() ->
    ?LET(I, int_range(1,63), string(I)).

dns_name_list() ->
    ?SUCHTHAT(N,
	      ?LET(I, int_range(1,7), vector(I, dns_label())),
	      length(lists:flatten(N)) < 100).

dns_name() ->
    ?LET(L, dns_name_list(),
	 [list_to_binary(X) || X <- L]).

mcc() ->
    ?LET(I, int_range(1,999), integer_to_binary(I)).

mcc_label() ->
    ?LET(M, mcc(), list_to_binary(io_lib:format("mcc~3..0s", [M]))).

mnc() ->
    ?LET(M, int_range(1,999), integer_to_binary(M)).

mnc_label() ->
    ?LET(M, mnc(), list_to_binary(io_lib:format("mnc~3..0s", [M]))).

apn() ->
    ?LET(L, [dns_name(), mnc_label(), mcc_label(), <<"gprs">>], lists:flatten(L)).

uint4() ->
    int_range(0,16#0f).

uint8() ->
    int_range(0,16#ff).

uint16() ->
    int_range(0,16#ffff).

uint24() ->
    int_range(0,16#ffffff).

int32() ->
    int_range(-16#7fffffff,16#7fffffff).

int64() ->
    int_range(-16#7fffffffffffffff,16#7fffffffffffffff).

uint32() ->
    int_range(0,16#ffffffff).

uint64() ->
    int_range(0,16#ffffffffffffffff).

float32() ->
    ?SUCHTHAT(Float,
	      ?LET(Int, uint32(),
		   ?LET(Frac, uint32(),  Int + Frac / (1 bsl 32))),
	      Float < (1 bsl 32)).

ip4_address() ->
    binary(4).

ip6_address() ->
    binary(16).

binstr_number(Min, Max) ->
    ?LET(X,
	 ?LET(I, int_range(Min,Max), vector(I, integer($0, $9))), list_to_binary(X)).

binary(Min, Max) ->
    ?LET(I, int_range(Min,Max), binary(I)).

imsi() ->
    binstr_number(7,15).

imei() ->
    binstr_number(15, 15).

imeisv() ->
    binstr_number(16, 16).

msg_gen() ->
    #pfcp{
      version = v1,
      type = msg_type(),
      seid = frequency([{1,undefined}, {10, uint32()}]),
      seq_no = uint24(),
      ie = ie()
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

grouped_ie() ->
    [gen_create_pdr(),
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
     gen_load_control_information(),
     gen_overload_control_information(),
     gen_application_id_pfds(),
     gen_pfd_context(),
     gen_application_detection_information(),
     gen_query_urr(),
     gen_usage_report_smr(),
     gen_usage_report_sdr(),
     gen_usage_report_srr(),
     gen_downlink_data_report(),
     gen_create_bar(),
     gen_update_bar_request(),
     gen_remove_bar(),
     gen_error_indication_report(),
     gen_user_plane_path_failure_report(),
     gen_update_duplicating_parameters(),
     gen_aggregated_urr_id(),
     gen_create_traffic_endpoint(),
     gen_created_traffic_endpoint(),
     gen_update_traffic_endpoint(),
     gen_remove_traffic_endpoint(),
     gen_ethernet_packet_filter(),
     gen_ethernet_traffic_information(),
     gen_additional_monitoring_time(),
     gen_create_mar(),
     gen_tgpp_access_forwarding_action_information(),
     gen_non_tgpp_access_forwarding_action_information(),
     gen_remove_mar(),
     gen_update_mar(),
     gen_update_tgpp_access_forwarding_action_information(),
     gen_update_non_tgpp_access_forwarding_action_information(),
     gen_pfcp_session_retention_information(),
     gen_user_plane_path_recovery_report(),
     gen_ip_multicast_addressing_info(),
     gen_join_ip_multicast_information(),
     gen_leave_ip_multicast_information(),
     gen_created_bridge_info_for_tsc(),
     gen_port_management_information_for_tsc(),
     gen_port_management_information_for_tsc_smr(),
     gen_port_management_information_for_tsc_sdr(),
     gen_clock_drift_control_information(),
     gen_clock_drift_report(),
     gen_remove_srr(),
     gen_create_srr(),
     gen_update_srr(),
     gen_session_report(),
     gen_access_availability_control_information(),
     gen_access_availability_report(),
     gen_provide_atsss_control_information(),
     gen_atsss_control_parameters(),
     gen_mptcp_parameters(),
     gen_atsss_ll_parameters(),
     gen_pmf_parameters(),
     gen_ue_ip_address_pool_information(),
     gen_gtp_u_path_qos_control_information(),
     gen_gtp_u_path_qos_report(),
     gen_path_report_qos_information(),
     gen_qos_monitoring_per_qos_flow_control_information(),
     gen_qos_monitoring_report(),
     gen_packet_rate_status_report(),
     gen_ethernet_context_information(),
     gen_redundant_transmission_parameters(),
     gen_updated_pdr(),
     gen_provide_rds_configuration_information(),
     gen_query_packet_rate_status_ie_smreq(),
     gen_packet_rate_status_report_ie_smresp(),
     gen_ue_ip_address_usage_information(),
     gen_redundant_transmission_forwarding(),
     gen_transport_delay_reporting(),
     gen_ppp_lcp_connectivity(),
     gen_l2tp_tunnel(),
     gen_bbf_nat_outside_address(),
     gen_bbf_apply_action(),
     gen_bbf_nat_external_port_range(),
     gen_bbf_nat_port_forward(),
     gen_bbf_nat_port_block(),
     gen_bbf_dynamic_port_block_starting_port()
    ].

simple_ie() ->
    [
     gen_pfcp_cause(),
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
     gen_sequence_number(),
     gen_metric(),
     gen_timer(),
     gen_pdr_id(),
     gen_f_seid(),
     gen_node_id(),
     gen_pfd_contents(),
     gen_measurement_method(),
     gen_usage_report_trigger(),
     gen_measurement_period(),
     gen_fq_csid(),
     gen_volume_measurement(),
     gen_duration_measurement(),
     gen_time_of_first_packet(),
     gen_time_of_last_packet(),
     gen_quota_holding_time(),
     gen_dropped_dl_traffic_threshold(),
     gen_volume_quota(),
     gen_time_quota(),
     gen_start_time(),
     gen_end_time(),
     gen_urr_id(),
     gen_linked_urr_id(),
     gen_outer_header_creation(),
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
     gen_measurement_information(),
     gen_node_report_type(),
     gen_remote_gtp_u_peer(),
     gen_ur_seqn(),
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
     gen_user_plane_ip_resource_information(),
     gen_user_plane_inactivity_timer(),
     gen_aggregated_urrs(),
     gen_multiplier(),
     gen_subsequent_volume_quota(),
     gen_subsequent_time_quota(),
     gen_rqi(),
     gen_qfi(),
     gen_query_urr_reference(),
     gen_additional_usage_reports_information(),
     gen_traffic_endpoint_id(),
     gen_mac_address(),
     gen_c_tag(),
     gen_s_tag(),
     gen_ethertype(),
     gen_proxying(),
     gen_ethernet_filter_id(),
     gen_ethernet_filter_properties(),
     gen_suggested_buffering_packets_count(),
     gen_user_id(),
     gen_ethernet_pdu_session_information(),
     gen_mac_addresses_detected(),
     gen_mac_addresses_removed(),
     gen_ethernet_inactivity_timer(),
     gen_event_quota(),
     gen_event_threshold(),
     gen_subsequent_event_quota(),
     gen_subsequent_event_threshold(),
     gen_trace_information(),
     gen_framed_route(),
     gen_framed_routing(),
     gen_framed_ipv6_route(),
     gen_event_time_stamp(),
     gen_averaging_window(),
     gen_paging_policy_indicator(),
     gen_apn_dnn(),
     gen_tgpp_interface_type(),
     gen_pfcpsrreq_flags(),
     gen_pfcpaureq_flags(),
     gen_activation_time(),
     gen_deactivation_time(),
     gen_mar_id(),
     gen_steering_functionality(),
     gen_steering_mode(),
     gen_weight(),
     gen_priority(),
     gen_ue_ip_address_pool_identity(),
     gen_alternative_smf_ip_address(),
     gen_packet_replication_and_detection_carry_on_information(),
     gen_smf_set_id(),
     gen_quota_validity_time(),
     gen_number_of_reports(),
     gen_pfcpasrsp_flags(),
     gen_cp_pfcp_entity_ip_address(),
     gen_pfcpsereq_flags(),
     gen_ip_multicast_address(),
     gen_source_ip_address(),
     gen_packet_rate_status(),
     gen_create_bridge_info_for_tsc(),
     gen_ds_tt_port_number(),
     gen_nw_tt_port_number(),
     gen_tsn_bridge_id(),
     gen_port_management_information_container(),
     gen_requested_clock_drift_information(),
     gen_tsn_time_domain_number(),
     gen_time_offset_threshold(),
     gen_cumulative_rateratio_threshold(),
     gen_time_offset_measurement(),
     gen_cumulative_rateratio_measurement(),
     gen_srr_id(),
     gen_requested_access_availability_information(),
     gen_access_availability_information(),
     gen_mptcp_control_information(),
     gen_atsss_ll_control_information(),
     gen_pmf_control_information(),
     gen_mptcp_address_information(),
     gen_ue_link_specific_ip_address(),
     gen_pmf_address_information(),
     gen_atsss_ll_information(),
     gen_data_network_access_identifier(),
     gen_average_packet_delay(),
     gen_minimum_packet_delay(),
     gen_maximum_packet_delay(),
     gen_qos_report_trigger(),
     gen_gtp_u_path_interface_type(),
     gen_requested_qos_monitoring(),
     gen_reporting_frequency(),
     gen_packet_delay_thresholds(),
     gen_minimum_wait_time(),
     gen_qos_monitoring_measurement(),
     gen_mt_edt_control_information(),
     gen_dl_data_packets_size(),
     gen_qer_control_indications(),
     gen_nf_instance_id(),
     gen_s_nssai(),
     gen_ip_version(),
     gen_pfcpasreq_flags(),
     gen_data_status(),
     gen_rds_configuration_information(),
     gen_mptcp_applicable_indication(),
     gen_bridge_management_information_container(),
     gen_number_of_ue_ip_addresses(),
     gen_validity_timer(),
     gen_bbf_up_function_features(),
     gen_logical_port(),
     gen_bbf_outer_header_creation(),
     gen_bbf_outer_header_removal(),
     gen_pppoe_session_id(),
     gen_ppp_protocol(),
     gen_verification_timers(),
     gen_ppp_lcp_magic_number(),
     gen_mtu(),
     gen_l2tp_tunnel_endpoint(),
     gen_l2tp_session_id(),
     gen_l2tp_type(),
     gen_tp_packet_measurement(),
     gen_tp_build_identifier(),
     gen_tp_now(),
     gen_tp_start_time(),
     gen_tp_stop_time(),
     gen_enterprise_priv()
    ].

ie() ->
    ie_map(
      ?LET(I, integer(1,10), vector(I, oneof(simple_ie() ++ grouped_ie())))).

put_ie(IE, IEs) ->
    Key = element(1, IE),
    UpdateFun = fun(V) when is_list(V) -> V ++ [IE];
		   (undefined)         -> IE;
		   (V)                 -> [V, IE]
		end,
    maps:update_with(Key, UpdateFun, IE, IEs).

list2map(List) ->
    lists:foldl(fun put_ie/2, #{}, List).

ie_map(IEs) ->
    ?LET(L, IEs, list2map(L)).

ie_group() ->
    ie_map(
      ?LET(I, integer(1,10), vector(I, oneof(simple_ie())))).

gen_volume(Type) ->
    {Type,
     oneof(['undefined', uint64()]),   %% total
     oneof(['undefined', uint64()]),   %% uplink
     oneof(['undefined', uint64()])   %% downlink
    }.

gen_create_pdr() ->
    #create_pdr{group = ie_group()}.

gen_pdi() ->
    #pdi{group = ie_group()}.

gen_create_far() ->
    #create_far{group = ie_group()}.

gen_forwarding_parameters() ->
    #forwarding_parameters{group = ie_group()}.

gen_duplicating_parameters() ->
    #duplicating_parameters{group = ie_group()}.

gen_create_urr() ->
    #create_urr{group = ie_group()}.

gen_create_qer() ->
    #create_qer{group = ie_group()}.

gen_created_pdr() ->
    #created_pdr{group = ie_group()}.

gen_update_pdr() ->
    #update_pdr{group = ie_group()}.

gen_update_far() ->
    #update_far{group = ie_group()}.

gen_update_forwarding_parameters() ->
    #update_forwarding_parameters{group = ie_group()}.

gen_update_bar_response() ->
    #update_bar_response{group = ie_group()}.

gen_update_urr() ->
    #update_urr{group = ie_group()}.

gen_update_qer() ->
    #update_qer{group = ie_group()}.

gen_remove_pdr() ->
    #remove_pdr{group = ie_group()}.

gen_remove_far() ->
    #remove_far{group = ie_group()}.

gen_remove_urr() ->
    #remove_urr{group = ie_group()}.

gen_remove_qer() ->
    #remove_qer{group = ie_group()}.

gen_pfcp_cause() ->
    #pfcp_cause{
       cause = oneof(
		 ['Reserved',
		  'Request accepted',
		  'More Usage Report to send',
		  'Request rejected',
		  'Session context not found',
		  'Mandatory IE missing',
		  'Conditional IE missing',
		  'Invalid length',
		  'Mandatory IE incorrect',
		  'Invalid Forwarding Policy',
		  'Invalid F-TEID allocation option',
		  'No established Sx Association',
		  'Rule creation/modification Failure',
		  'PFCP entity in congestion',
		  'No resources available',
		  'Service not supported',
		  'System failure',
		  'Redirection Requested',
		  'All dynamic addresses are occupied'])
      }.

gen_source_interface() ->
    #source_interface{
       interface = oneof(['Access',
			  'Core',
			  'SGi-LAN',
			  'CP-function',
			  '5G VN Internal'])
      }.

gen_f_teid(TEID, IP4, IP6, ChId) ->
    #f_teid{
       teid = TEID,
       ipv6 = IP6,
       ipv4 = IP4,
       choose_id = ChId}.

gen_f_teid() ->
    oneof(
      [gen_f_teid(uint32(), ip4_address(), ip6_address(), undefined),
       gen_f_teid(uint32(), ip4_address(), undefined,     undefined),
       gen_f_teid(uint32(), undefined,     ip6_address(), undefined),
       gen_f_teid(choose,   choose,        choose,        undefined),
       gen_f_teid(choose,   choose,        undefined,     undefined),
       gen_f_teid(choose,   undefined,     choose,        undefined),
       gen_f_teid(choose,   choose,        choose,        uint8()),
       gen_f_teid(choose,   choose,        undefined,     uint8()),
       gen_f_teid(choose,   undefined,     choose,        uint8())]).

gen_network_instance() ->
    #network_instance{
       instance =
	   oneof([encode_dns_label(dns_name()),
		  binary()])}.

gen_sdf_filter() ->
    #sdf_filter{
       flow_description = oneof([undefined, binary()]),
       tos_traffic_class = oneof([undefined, uint16()]),
       security_parameter_index = oneof([undefined, uint32()]),
       flow_label = oneof([undefined, uint24()]),
       filter_id = oneof([undefined, uint32()])
      }.

gen_application_id() ->
    #application_id{
       id = binary()
      }.

gen_gate_status() ->
    #gate_status{
       ul = oneof(['OPEN', 'CLOSED']),
       dl = oneof(['OPEN', 'CLOSED'])
      }.

gen_mbr() ->
    #mbr{
       ul = uint32(),
       dl = uint32()
      }.

gen_gbr() ->
    #gbr{
       ul = uint32(),
       dl = uint32()
      }.

gen_qer_correlation_id() ->
    #qer_correlation_id{
       id = uint32()
      }.

gen_precedence() ->
    #precedence{
       precedence = uint32()
      }.

gen_transport_level_marking() ->
    #transport_level_marking{
      tos = uint16()
      }.

gen_volume_threshold() ->
    gen_volume(volume_threshold).

gen_time_threshold() ->
    #time_threshold{
       threshold = uint32()
      }.

gen_monitoring_time() ->
    #monitoring_time{
       time = uint32()
      }.

gen_subsequent_volume_threshold() ->
    gen_volume(subsequent_volume_threshold).

gen_subsequent_time_threshold() ->
    #subsequent_time_threshold{
       threshold = uint32()
      }.

gen_inactivity_detection_time() ->
    #inactivity_detection_time{
       time = uint32()
      }.

gen_reporting_triggers() ->
    #reporting_triggers{
       linked_usage_reporting = flag(),
       dropped_dl_traffic_threshold = flag(),
       stop_of_traffic = flag(),
       start_of_traffic = flag(),
       quota_holding_time = flag(),
       time_threshold = flag(),
       volume_threshold = flag(),
       periodic_reporting = flag(),
       quota_validity_time = flag(),
       ip_multicast_join_leave = flag(),
       event_quota = flag(),
       event_threshold = flag(),
       mac_addresses_reporting = flag(),
       envelope_closure = flag(),
       time_quota = flag(),
       volume_quota = flag(),
       report_the_end_marker_reception = flag()
      }.

gen_redirect_information() ->
    oneof([#redirect_information{
	      type = oneof(['IPv4',
			    'IPv6',
			    'URL',
			    'SIP URI']),
	      address = binary()
	     },
	   #redirect_information{
	      type = 'IPv4 and IPv6 addresses',
	      address = binary(),
	      other_address = binary()
	     }]).

gen_report_type() ->
    #report_type{
       uisr = flag(),
       sesr = flag(),
       pmir = flag(),
       upir = flag(),
       erir = flag(),
       usar = flag(),
       dldr = flag()
      }.

gen_offending_ie() ->
    #offending_ie{
      type = uint16()
      }.

gen_forwarding_policy() ->
    #forwarding_policy{
       policy_identifier = ?LET(I, uint8(), binary(I))
      }.

gen_destination_interface() ->
    #destination_interface{
       interface = oneof(['Access',
			  'Core',
			  'SGi-LAN',
			  'CP-function',
			  'LI-function',
			  '5G VN Internal'])
      }.

gen_up_function_features() ->
    oneof([#up_function_features{
	      treu = flag(),    % 5/8
	      heeu = flag(),    % 5/7
	      pfdm = flag(),    % 5/6
	      ftup = flag(),    % 5/5
	      trst = flag(),    % 5/4
	      dlbd = flag(),    % 5/3
	      ddnd = flag(),    % 5/2
	      bucp = flag()     % 5/1
	     },
	   #up_function_features{
	      treu = flag(),    % 5/8
	      heeu = flag(),    % 5/7
	      pfdm = flag(),    % 5/6
	      ftup = flag(),    % 5/5
	      trst = flag(),    % 5/4
	      dlbd = flag(),    % 5/3
	      ddnd = flag(),    % 5/2
	      bucp = flag(),    % 5/1
	      epfar = flag(),   % 6/8
	      pfde = flag(),    % 6/7
	      frrt = flag(),    % 6/6
	      trace = flag(),   % 6/5
	      quoac = flag(),   % 6/4
	      udbc = flag(),    % 6/3
	      pdiu = flag(),    % 6/2
	      empu = flag()     % 6/1
	     },
	   #up_function_features{
	      treu = flag(),    % 5/8
	      heeu = flag(),    % 5/7
	      pfdm = flag(),    % 5/6
	      ftup = flag(),    % 5/5
	      trst = flag(),    % 5/4
	      dlbd = flag(),    % 5/3
	      ddnd = flag(),    % 5/2
	      bucp = flag(),    % 5/1
	      epfar = flag(),   % 6/8
	      pfde = flag(),    % 6/7
	      frrt = flag(),    % 6/6
	      trace = flag(),   % 6/5
	      quoac = flag(),   % 6/4
	      udbc = flag(),    % 6/3
	      pdiu = flag(),    % 6/2
	      empu = flag(),    % 6/1
	      gcom = flag(),    % 7/8
	      bundl = flag(),   % 7/7
	      mte = flag(),     % 7/6
	      mnop = flag(),    % 7/5
	      sset = flag(),    % 7/4
	      ueip = flag(),    % 7/3
	      adpdp = flag(),   % 7/2
	      dpdra = flag()    % 7/1
	     },
	   #up_function_features{
	      treu = flag(),    % 5/8
	      heeu = flag(),    % 5/7
	      pfdm = flag(),    % 5/6
	      ftup = flag(),    % 5/5
	      trst = flag(),    % 5/4
	      dlbd = flag(),    % 5/3
	      ddnd = flag(),    % 5/2
	      bucp = flag(),    % 5/1
	      epfar = flag(),   % 6/8
	      pfde = flag(),    % 6/7
	      frrt = flag(),    % 6/6
	      trace = flag(),   % 6/5
	      quoac = flag(),   % 6/4
	      udbc = flag(),    % 6/3
	      pdiu = flag(),    % 6/2
	      empu = flag(),    % 6/1
	      gcom = flag(),    % 7/8
	      bundl = flag(),   % 7/7
	      mte = flag(),     % 7/6
	      mnop = flag(),    % 7/5
	      sset = flag(),    % 7/4
	      ueip = flag(),    % 7/3
	      adpdp = flag(),   % 7/2
	      dpdra = flag(),   % 7/1
	      mptcp = flag(),   % 8/8
	      tscu = flag(),    % 8/7
	      ip6pl = flag(),   % 8/6
	      iptv = flag(),    % 8/5
	      norp = flag(),    % 8/4
	      vtime = flag(),   % 8/3
	      rttl = flag(),    % 8/2
	      mpas = flag()     % 8/1
	     },
	   #up_function_features{
	      treu = flag(),    % 5/8
	      heeu = flag(),    % 5/7
	      pfdm = flag(),    % 5/6
	      ftup = flag(),    % 5/5
	      trst = flag(),    % 5/4
	      dlbd = flag(),    % 5/3
	      ddnd = flag(),    % 5/2
	      bucp = flag(),    % 5/1
	      epfar = flag(),   % 6/8
	      pfde = flag(),    % 6/7
	      frrt = flag(),    % 6/6
	      trace = flag(),   % 6/5
	      quoac = flag(),   % 6/4
	      udbc = flag(),    % 6/3
	      pdiu = flag(),    % 6/2
	      empu = flag(),    % 6/1
	      gcom = flag(),    % 7/8
	      bundl = flag(),   % 7/7
	      mte = flag(),     % 7/6
	      mnop = flag(),    % 7/5
	      sset = flag(),    % 7/4
	      ueip = flag(),    % 7/3
	      adpdp = flag(),   % 7/2
	      dpdra = flag(),   % 7/1
	      mptcp = flag(),   % 8/8
	      tscu = flag(),    % 8/7
	      ip6pl = flag(),   % 8/6
	      iptv = flag(),    % 8/5
	      norp = flag(),    % 8/4
	      vtime = flag(),   % 8/3
	      rttl = flag(),    % 8/2
	      mpas = flag(),    % 8/1

	      rds = flag(),     % 9/8
	      ddds = flag(),    % 9/7
	      ethar = flag(),   % 9/6
	      ciot = flag(),    % 9/5
	      mt_edt = flag(),  % 9/4
	      gpqm = flag(),    % 9/3
	      qfqm = flag(),    % 9/2
	      atsss_ll = flag(),% 9/1

	      rttwp = flag()    % 10/1
	     }]).

gen_apply_action() ->
    oneof([#apply_action{
	      dfrt = flag(),
	      ipmd = flag(),
	      ipma = flag(),
	      dupl = flag(),
	      nocp = flag(),
	      buff = flag(),
	      forw = flag(),
	      drop = flag()
	     },
	   #apply_action{
	      dfrt = flag(),
	      ipmd = flag(),
	      ipma = flag(),
	      dupl = flag(),
	      nocp = flag(),
	      buff = flag(),
	      forw = flag(),
	      drop = flag(),
	      edrt = flag(),
	      bdpn = flag(),
	      ddpn = flag()
	     }]).

gen_downlink_data_service_information() ->
    #downlink_data_service_information{
       value = oneof(['undefined', int_range(0, 16#3f)]),
       qfi = oneof(['undefined', int_range(0, 16#3f)])
      }.

gen_downlink_data_notification_delay() ->
    #downlink_data_notification_delay{
       delay = byte()
      }.

gen_dl_buffering_duration() ->
    #dl_buffering_duration{
       dl_buffer_unit = oneof(['2 seconds',
			       '1 minute',
			       '10 minutes',
			       '1 hour',
			       '10 hours',
			       'infinite']),
       dl_buffer_value = int_range(0,16#1f)
      }.

gen_dl_buffering_suggested_packet_count() ->
    #dl_buffering_suggested_packet_count{
       count = oneof([uint8(), uint16()])
      }.

gen_sxsmreq_flags() ->
    #sxsmreq_flags{
       qaurr = flag(),
       sndem = flag(),
       drobu = flag()
      }.

gen_sxsrrsp_flags() ->
    #sxsrrsp_flags{
       drobu = flag()
      }.

gen_load_control_information() ->
    #load_control_information{group = ie_group()}.

gen_sequence_number() ->
    #sequence_number{
      number = uint32()
      }.

gen_metric() ->
    #metric{
      metric = byte()
      }.

gen_overload_control_information() ->
    #overload_control_information{group = ie_group()}.

gen_timer() ->
    #timer{
       timer_unit = oneof(['2 seconds',
			   '1 minute',
			   '10 minutes',
			   '1 hour',
			   '10 hours',
			   'infinite']),
       timer_value = int_range(0,16#1f)
      }.

gen_pdr_id() ->
    #pdr_id{id = id_range(pdr)}.

gen_f_seid() ->
    oneof([
	   #f_seid{
	      seid = uint64(),
	      ipv4 = ip4_address(),
	      ipv6 = undefined
	     },
	   #f_seid{
	      seid = uint64(),
	      ipv4 = undefined,
	      ipv6 = ip6_address()
	     },
	   #f_seid{
	      seid = uint64(),
	      ipv4 = ip4_address(),
	      ipv6 = ip6_address()
	     }]).


gen_application_id_pfds() ->
    #application_id_pfds{group = ie_group()}.

gen_pfd_context() ->
    #pfd_context{group = ie_group()}.

gen_node_id() ->
    #node_id{id = oneof([ip4_address(), ip6_address(), dns_name()])}.

gen_pfd_contents() ->
    #pfd_contents{
	  flow = oneof(['undefined', binary()]),
	  url = oneof(['undefined', binary()]),
	  domain = oneof(['undefined', binary()]),
	  custom = oneof(['undefined', binary()]),
	  dnp = oneof(['undefined', binary()]),
	  aflow = oneof(['undefined', binary()]),
	  aurl = oneof(['undefined', binary()]),
	  adnp = oneof(['undefined', binary()])
      }.

gen_measurement_method() ->
    #measurement_method{
	  event = flag(),
	  volum = flag(),
	  durat = flag()
}.

gen_usage_report_trigger() ->
    oneof([#usage_report_trigger{
	      immer = flag(),
	      droth = flag(),
	      stopt = flag(),
	      start = flag(),
	      quhti = flag(),
	      timth = flag(),
	      volth = flag(),
	      perio = flag(),
	      eveth = flag(),
	      macar = flag(),
	      envcl = flag(),
	      monit = flag(),
	      termr = flag(),
	      liusa = flag(),
	      timqu = flag(),
	      volqu = flag()
	     },
	   #usage_report_trigger{
	      immer = flag(),
	      droth = flag(),
	      stopt = flag(),
	      start = flag(),
	      quhti = flag(),
	      timth = flag(),
	      volth = flag(),
	      perio = flag(),
	      eveth = flag(),
	      macar = flag(),
	      envcl = flag(),
	      monit = flag(),
	      termr = flag(),
	      liusa = flag(),
	      timqu = flag(),
	      volqu = flag(),

	      emrre = flag(),
	      quvti = flag(),
	      ipmjl = flag(),
	      tebur = flag(),
	      evequ = flag()
	     }]).

gen_measurement_period() ->
    #measurement_period{
       period = uint32()
      }.

gen_fq_csid() ->
    #fq_csid{
       address =
	   oneof(
	     [ip4_address(),
	      ip6_address(),
	      {int_range(0,99), int_range(0,999), int_range(0,16#fff)}
	     ]),
       csid = ?LET(I, int_range(0,15), vector(I, uint16()))
      }.

gen_volume_measurement() ->
    #volume_measurement{
       total = oneof(['undefined', uint64()]),
       uplink = oneof(['undefined', uint64()]),
       downlink = oneof(['undefined', uint64()]),
       total_pkts = oneof(['undefined', uint64()]),
       uplink_pkts = oneof(['undefined', uint64()]),
       downlink_pkts = oneof(['undefined', uint64()])
       }.

gen_duration_measurement() ->
    #duration_measurement{
       duration = uint32()
      }.

gen_application_detection_information() ->
    #application_detection_information{group = ie_group()}.

gen_time_of_first_packet() ->
    #time_of_first_packet{
      time = uint32()
      }.

gen_time_of_last_packet() ->
    #time_of_last_packet{
      time = uint32()
      }.

gen_quota_holding_time() ->
    #quota_holding_time{
      time = uint32()
      }.

gen_dropped_dl_traffic_threshold() ->
    #dropped_dl_traffic_threshold{
       value = oneof(['undefined', uint64()]),
       bytes = oneof(['undefined', uint64()])
      }.

gen_volume_quota() ->
    gen_volume(volume_quota).

gen_time_quota() ->
    #time_quota{
       quota = uint32()
      }.

gen_start_time() ->
    #start_time{
      time = uint32()
      }.

gen_end_time() ->
    #end_time{
      time = uint32()
      }.

gen_query_urr() ->
    #query_urr{group = ie_group()}.

gen_usage_report_smr() ->
    #usage_report_smr{group = ie_group()}.

gen_usage_report_sdr() ->
    #usage_report_sdr{group = ie_group()}.

gen_usage_report_srr() ->
    #usage_report_srr{group = ie_group()}.

gen_urr_id() ->
    #urr_id{id = id_range(urr)}.

gen_linked_urr_id() ->
    #linked_urr_id{id = id_range(urr)}.

gen_downlink_data_report() ->
    #downlink_data_report{group = ie_group()}.

gen_outer_header_creation() ->
    oneof(
      [#outer_header_creation{n6 = boolean(), n19 = boolean()},
       #outer_header_creation{
	  n6 = boolean(), n19 = boolean(),
	  type = 'GTP-U', teid = uint32(), ipv4 = ip4_address()},
       #outer_header_creation{
	  n6 = boolean(), n19 = boolean(),
	  type = 'GTP-U', teid = uint32(), ipv6 = ip6_address()},
       #outer_header_creation{
	  n6 = boolean(), n19 = boolean(),
	  type = 'GTP-U', teid = uint32(), ipv4 = ip4_address(), ipv6 = ip6_address()},
       #outer_header_creation{
	  n6 = boolean(), n19 = boolean(),
	  type = 'UDP', ipv4 = ip4_address(), port = uint16()},
       #outer_header_creation{
	  n6 = boolean(), n19 = boolean(),
	  type = 'UDP', ipv6 = ip6_address(), port = uint16()},
       #outer_header_creation{
	  n6 = boolean(), n19 = boolean(),
	  type = 'IP', ipv4 = ip4_address()},
       #outer_header_creation{
	  n6 = boolean(), n19 = boolean(),
	  type = 'IP', ipv6 = ip6_address()},
       #outer_header_creation{
	  n6 = boolean(), n19 = boolean(),
	  type = 'RAW', c_tag = binary(3)},
       #outer_header_creation{
	  n6 = boolean(), n19 = boolean(),
	  type = 'RAW', s_tag = binary(3)},
       #outer_header_creation{
	  n6 = boolean(), n19 = boolean(),
	  type = 'RAW', c_tag = binary(3), s_tag = binary(3)}
      ]).

gen_create_bar() ->
    #create_bar{group = ie_group()}.

gen_update_bar_request() ->
    #update_bar_request{group = ie_group()}.

gen_remove_bar() ->
    #remove_bar{group = ie_group()}.

gen_bar_id() ->
    #bar_id{id = id_range(bar)}.

gen_cp_function_features() ->
    #cp_function_features{
       uiaur = flag(),
       ardr = flag(),
       mpas = flag(),
       bundl = flag(),
       sset = flag(),
       epfar = flag(),
       ovrl = flag(),
       load = flag()
      }.

gen_usage_information() ->
    #usage_information{
       ube = flag(),
       uae = flag(),
       aft = flag(),
       bef = flag()
      }.

gen_application_instance_id() ->
    #application_instance_id{
      id = binary()
      }.

gen_flow_information() ->
    #flow_information{
       direction =
	   oneof(
	     ['Unspecified',
	      'Downlink',
	      'Uplink',
	      'Bidirectional']),
       flow = binary()
      }.

gen_ue_ip_address() ->
    #ue_ip_address{
       type = oneof([src, dst]),
       ipv4 = oneof([undefined, choose, ip4_address()]),
       ipv6 = oneof([undefined, choose, ip6_address()]),
       prefix_delegation = oneof([undefined, uint8()]),
       prefix_length = oneof([undefined, uint8()])
      }.

gen_packet_rate() ->
    Unit = oneof(['minute','6 minutes', 'hour', 'day', 'week']),
    oneof([#packet_rate{},
	   #packet_rate{
	      ul_time_unit = Unit,
	      ul_max_packet_rate = uint16()
	     },
	   #packet_rate{
	      dl_time_unit = Unit,
	      dl_max_packet_rate = uint16()
	     },
	   #packet_rate{
	      ul_time_unit = Unit,
	      ul_max_packet_rate = uint16(),
	      dl_time_unit = Unit,
	      dl_max_packet_rate = uint16()
	     },
	   #packet_rate{
	      ul_time_unit = Unit,
	      ul_max_packet_rate = uint16(),
	      additional_ul_time_unit = Unit,
	      additional_ul_max_packet_rate = uint16()
	     },
	   #packet_rate{
	      dl_time_unit = Unit,
	      dl_max_packet_rate = uint16(),
	      additional_dl_time_unit = Unit,
	      additional_dl_max_packet_rate = uint16()
	     },
	   #packet_rate{
	      ul_time_unit = Unit,
	      ul_max_packet_rate = uint16(),
	      dl_time_unit = Unit,
	      dl_max_packet_rate = uint16(),
	      additional_ul_time_unit = Unit,
	      additional_ul_max_packet_rate = uint16(),
	      additional_dl_time_unit = Unit,
	      additional_dl_max_packet_rate = uint16()
	     }]).

gen_outer_header_removal() ->
    #outer_header_removal{
       header =
	   oneof(
	     ['GTP-U/UDP/IPv4',
	      'GTP-U/UDP/IPv6',
	      'UDP/IPv4',
	      'UDP/IPv6',
	      'IPv4',
	      'IPv6',
	      'GTP-U/UDP/IP',
	      'VLAN S-TAG',
	      'S-TAG and C-TAG'])
      }.

gen_recovery_time_stamp() ->
    #recovery_time_stamp{
       time = uint32()
      }.

gen_dl_flow_level_marking() ->
    #dl_flow_level_marking{
       traffic_class = oneof([undefined, binary(2)]),
       service_class_indicator = oneof([undefined, binary(2)])
      }.

gen_header_enrichment() ->
    #header_enrichment{
       header_type = 'HTTP',
       name = binary(),
       value = binary()
      }.

gen_error_indication_report() ->
    #error_indication_report{group = ie_group()}.

gen_measurement_information() ->
    #measurement_information{
       mnop = flag(),
       istm = flag(),
       radi = flag(),
       inam = flag(),
       mbqe = flag()
      }.

gen_node_report_type() ->
    #node_report_type{
       gpqr = flag(),
       ckdr = flag(),
       uprr = flag(),
       upfr = flag()
      }.

gen_user_plane_path_failure_report() ->
    #user_plane_path_failure_report{group = ie_group()}.

gen_remote_gtp_u_peer() ->
    #remote_gtp_u_peer{
       ipv4 = oneof([undefined, ip4_address()]),
       ipv6 = oneof([undefined, ip6_address()]),
       destination_interface = oneof([undefined, binary()]),
       network_instance = oneof([undefined, binary()])
      }.

gen_ur_seqn() ->
    #ur_seqn{
       number = uint32()
      }.

gen_update_duplicating_parameters() ->
    #update_duplicating_parameters{group = ie_group()}.

gen_activate_predefined_rules() ->
    #activate_predefined_rules{
      name = binary()
      }.

gen_deactivate_predefined_rules() ->
    #deactivate_predefined_rules{
      name = binary()
      }.

gen_far_id() ->
    #far_id{id = id_range(far)}.

gen_qer_id() ->
    #qer_id{id = id_range(qer)}.

gen_oci_flags() ->
    #oci_flags{
       aoci = flag()
      }.

gen_sx_association_release_request() ->
    #sx_association_release_request{
       urss = flag(),
       sarr = flag()
      }.

gen_graceful_release_period() ->
    #graceful_release_period{
       release_timer_unit = oneof(['2 seconds',
				   '1 minute',
				   '10 minutes',
				   '1 hour',
				   '10 hours',
				   'infinite']),
       release_timer_value = int_range(0,16#1f)
      }.

gen_pdn_type() ->
    #pdn_type{
       pdn_type = oneof(['IPv4', 'IPv6', 'IPv4v6', 'Non-IP', 'Ethernet'])
      }.

id_range(bar) -> uint8();
id_range(pdr) -> uint16();
id_range(_)   -> uint32().

gen_failed_rule_id() ->
    ?LET(Type, oneof([pdr, far, qer, urr, bar]),
	 #failed_rule_id{
	    type = Type,
	    id = id_range(Type)
	   }
	).

gen_time_quota_mechanism() ->
    #time_quota_mechanism{
       base_time_interval_type = oneof(['CTP', 'DTP']),
       interval = uint32()
      }.

gen_user_plane_ip_resource_information() ->
    #user_plane_ip_resource_information{
       teid_range = oneof([undefined, {byte(), int_range(1,7)}]),
       ipv4 = oneof([undefined, ip4_address()]),
       ipv6 = oneof([undefined, ip6_address()]),
       network_instance = oneof([undefined, encode_dns_label(dns_name()), binary()])
      }.

gen_user_plane_inactivity_timer() ->
    #user_plane_inactivity_timer{
       timer = uint32()
      }.

gen_aggregated_urrs() ->
    #aggregated_urrs{group = ie_group()}.

gen_multiplier() ->
    #multiplier{
       digits = int64(),
       exponent = int32()
      }.

gen_aggregated_urr_id() ->
    #aggregated_urr_id{
       id = id_range(urr)
      }.

gen_subsequent_volume_quota() ->
    gen_volume(subsequent_volume_quota).

gen_subsequent_time_quota() ->
    #subsequent_time_quota{
       quota = uint32()
      }.

gen_rqi() ->
    #rqi{
       rqi = flag()
      }.

gen_qfi() ->
    #qfi{
       qfi = int_range(0, 16#3f)
      }.

gen_query_urr_reference() ->
    #query_urr_reference{
       reference = uint32()
      }.

gen_additional_usage_reports_information() ->
    #additional_usage_reports_information{
       auri = flag(),
       reports = int_range(0, 16#7fff)
      }.

gen_create_traffic_endpoint() ->
    #create_traffic_endpoint{group = ie_group()}.

gen_created_traffic_endpoint() ->
    #created_traffic_endpoint{group = ie_group()}.

gen_update_traffic_endpoint() ->
    #update_traffic_endpoint{group = ie_group()}.

gen_remove_traffic_endpoint() ->
    #remove_traffic_endpoint{group = ie_group()}.

gen_traffic_endpoint_id() ->
    #traffic_endpoint_id{
       id = uint8()
      }.

gen_ethernet_packet_filter() ->
    #ethernet_packet_filter{group = ie_group()}.

gen_mac_address() ->
    #mac_address{
       source_mac = oneof(['undefined', binary(6)]),
       destination_mac = oneof(['undefined', binary(6)]),
       upper_source_mac = oneof(['undefined', binary(6)]),
       upper_destination_mac = oneof(['undefined', binary(6)])
      }.

gen_c_tag() ->
    #c_tag{
       pcp = oneof(['undefined', int_range(0, 7)]),
       dei = oneof(['undefined', flag()]),
       vid = oneof(['undefined', int_range(0, 16#fff)])
      }.

gen_s_tag() ->
    #s_tag{
       pcp = oneof(['undefined', int_range(0, 7)]),
       dei = oneof(['undefined', flag()]),
       vid = oneof(['undefined', int_range(0, 16#fff)])
      }.

gen_ethertype() ->
    #ethertype{
       type = uint16()
      }.

gen_proxying() ->
    #proxying{
       ins = flag(),
       arp = flag()
      }.

gen_ethernet_filter_id() ->
    #ethernet_filter_id{
       id = uint32()
      }.

gen_ethernet_filter_properties() ->
    #ethernet_filter_properties{
       bide = flag()
      }.

gen_suggested_buffering_packets_count() ->
    #suggested_buffering_packets_count{
       count = uint8()
      }.

gen_user_id() ->
    #user_id{
       imsi = oneof(['undefined', imsi()]),
       imei = oneof(['undefined', imei(), imeisv()]),
       msisdn = oneof(['undefined', binary()]),
       nai = oneof(['undefined', binary()])
      }.

gen_ethernet_pdu_session_information() ->
    #ethernet_pdu_session_information{
       ethi = flag()
      }.

gen_ethernet_traffic_information() ->
    #ethernet_traffic_information{group = ie_group()}.

gen_mac_addresses_detected() ->
    oneof([#mac_addresses_detected{
	      macs = ?LET(I, int_range(0,15), vector(I, binary(6)))
	     },
	   #mac_addresses_detected{
	      macs = ?LET(I, int_range(0,15), vector(I, binary(6))),
	      c_tag = binary()
	     },
	   #mac_addresses_detected{
	      macs = ?LET(I, int_range(0,15), vector(I, binary(6))),
	      c_tag = binary(),
	      s_tag = binary()
	     }]).
gen_mac_addresses_removed() ->
    oneof([#mac_addresses_removed{
	      macs = ?LET(I, int_range(0,15), vector(I, binary(6)))
	     },
	   #mac_addresses_removed{
	      macs = ?LET(I, int_range(0,15), vector(I, binary(6))),
	      c_tag = binary()
	     },
	   #mac_addresses_removed{
	      macs = ?LET(I, int_range(0,15), vector(I, binary(6))),
	      c_tag = binary(),
	      s_tag = binary()
	     }]).

gen_ethernet_inactivity_timer() ->
    #ethernet_inactivity_timer{
       timer = uint32()
      }.

gen_tp_packet_measurement() ->
    gen_volume(tp_packet_measurement).

gen_tp_build_identifier() ->
    #tp_build_identifier{
       id = binary()
      }.

gen_tp_now() ->
    #tp_now{
       now = float()
      }.

gen_tp_start_time() ->
    #tp_start_time{
       start = float()
      }.

gen_tp_stop_time() ->
    #tp_stop_time{
       stop = float()
      }.

gen_enterprise_priv() ->
    {{18681, 500}, binary()}.


%% =============================================================================

gen_additional_monitoring_time() ->
    #additional_monitoring_time{group = ie_group()}.

gen_event_quota() ->
    #event_quota{
       quota = uint32()
      }.

gen_event_threshold() ->
    #event_threshold{
       threshold = uint32()
      }.

gen_subsequent_event_quota() ->
    #subsequent_event_quota{
	  quota = uint32()
      }.

gen_subsequent_event_threshold() ->
    #subsequent_event_threshold{
       threshold = uint32()
      }.

gen_trace_information() ->
    #trace_information{
       mcc = mcc(),
       mnc = mnc(),
       trace_id = binary(3),
       events = binary(1,255),
       session_trace_depth = uint8(),
       interfaces = binary(1,255),
       ip_address = oneof([ip4_address(), ip6_address()])
      }.

gen_framed_route() ->
    #framed_route{
       value = binary()
      }.

gen_framed_routing() ->
    #framed_routing{
       value = uint32()
      }.

gen_framed_ipv6_route() ->
    #framed_ipv6_route{
       value = binary()
      }.

gen_event_time_stamp() ->
    #event_time_stamp{
       time = uint32()
      }.

gen_averaging_window() ->
    #averaging_window{
       window = uint32()
      }.

gen_paging_policy_indicator() ->
    #paging_policy_indicator{
       ppi = int_range(0,7)
      }.

gen_apn_dnn() ->
    #apn_dnn{
       apn = apn()
    }.

gen_tgpp_interface_type() ->
    #tgpp_interface_type{
       type = oneof(['S1-U',
		     'S5 /S8-U',
		     'S4-U',
		     'S11-U',
		     'S12-U',
		     'Gn/Gp-U',
		     'S2a-U',
		     'S2b-U',
		     'eNodeB GTP-U interface for DL data forwarding',
		     'eNodeB GTP-U interface for UL data forwarding',
		     'SGW/UPF GTP-U interface for DL data forwarding',
		     'N3 3GPP Access',
		     'N3 Trusted Non-3GPP Access',
		     'N3 Untrusted Non-3GPP Access',
		     'N3 for data forwarding',
		     'N9',
		     'SGi',
		     'N6',
		     'N19',
		     'S8-U',
		     'Gp-U'])
      }.

gen_pfcpsrreq_flags() ->
    #pfcpsrreq_flags{
       psdbu = flag()
      }.

gen_pfcpaureq_flags() ->
    #pfcpaureq_flags{
       parps = flag()
      }.

gen_activation_time() ->
    #activation_time{
       time = uint32()
      }.

gen_deactivation_time() ->
    #deactivation_time{
       time = uint32()
      }.

gen_create_mar() ->
    #create_mar{group = ie_group()}.

gen_tgpp_access_forwarding_action_information() ->
    #tgpp_access_forwarding_action_information{group = ie_group()}.

gen_non_tgpp_access_forwarding_action_information() ->
    #non_tgpp_access_forwarding_action_information{group = ie_group()}.

gen_remove_mar() ->
    #remove_mar{group = ie_group()}.

gen_update_mar() ->
    #update_mar{group = ie_group()}.

gen_mar_id() ->
    #mar_id{
       id = uint16()
      }.

gen_steering_functionality() ->
    #steering_functionality{
       functionality =
	   oneof(['ATSSS-LL', 'MPTCP'])
      }.

gen_steering_mode() ->
    #steering_mode{
       mode = oneof(['Active-Standby',
		     'Smallest Delay',
		     'Load Balancing',
		     'Priority-based'])
      }.

gen_weight() ->
    #weight{
       value = uint8()
      }.

gen_priority() ->
    #priority{
       priority = uint4()
      }.

gen_update_tgpp_access_forwarding_action_information() ->
    #update_tgpp_access_forwarding_action_information{group = ie_group()}.

gen_update_non_tgpp_access_forwarding_action_information() ->
    #update_non_tgpp_access_forwarding_action_information{group = ie_group()}.

gen_ue_ip_address_pool_identity() ->
    #ue_ip_address_pool_identity{
       identity = binary()
      }.

gen_alternative_smf_ip_address() ->
    #alternative_smf_ip_address{
       ipv4 = oneof([undefined, ip4_address()]),
       ipv6 = oneof([undefined, ip6_address()])
    }.

gen_packet_replication_and_detection_carry_on_information() ->
    #packet_replication_and_detection_carry_on_information{
       dcaroni = flag(),
       prin6i = flag(),
       prin19i = flag(),
       priueai = flag()
      }.

gen_smf_set_id() ->
    #smf_set_id{
       fqdn = dns_name()
      }.

gen_quota_validity_time() ->
    #quota_validity_time{
       time = uint32()
      }.

gen_number_of_reports() ->
    #number_of_reports{
       reports = uint16()
      }.

gen_pfcp_session_retention_information() ->
    #pfcp_session_retention_information{group = ie_group()}.

gen_pfcpasrsp_flags() ->
    #pfcpasrsp_flags{
       psrei = flag()
      }.

gen_cp_pfcp_entity_ip_address() ->
    #cp_pfcp_entity_ip_address{
       ipv4 = oneof([undefined, ip4_address()]),
       ipv6 = oneof([undefined, ip6_address()])
      }.

gen_pfcpsereq_flags() ->
    #pfcpsereq_flags{
       resti = flag()
      }.

gen_user_plane_path_recovery_report() ->
    #user_plane_path_recovery_report{group = ie_group()}.

gen_ip_multicast_addressing_info() ->
    #ip_multicast_addressing_info{group = ie_group()}.

gen_join_ip_multicast_information() ->
    #join_ip_multicast_information{group = ie_group()}.

gen_leave_ip_multicast_information() ->
    #leave_ip_multicast_information{group = ie_group()}.

gen_ip_multicast_address() ->
    #ip_multicast_address{
       ip = oneof([any,
		   ip4_address(),
		   {ip4_address(), ip4_address()},
		   ip6_address(),
		   {ip6_address(), ip6_address()}])
      }.

gen_source_ip_address() ->
    #source_ip_address{
       ip = oneof([ip4_address(),
		   {ip4_address(), int_range(0, 32)},
		   ip6_address(),
		   {ip6_address(), int_range(0, 128)}])
      }.

gen_packet_rate_status() ->
    oneof([#packet_rate_status{
	      remaining_uplink_packets_allowed = uint16(),
	      validity_time = float32()
	     },
	   #packet_rate_status{
	      remaining_uplink_packets_allowed = uint16(),
	      remaining_additional_uplink_packets_allowed = uint16(),
	      validity_time = float32()
	     },
	   #packet_rate_status{
	      remaining_uplink_packets_allowed = uint16(),
	      remaining_downlink_packets_allowed = uint16(),
	      validity_time = float32()
	     },
	   #packet_rate_status{
	      remaining_uplink_packets_allowed = uint16(),
	      remaining_downlink_packets_allowed = uint16(),
	      remaining_additional_uplink_packets_allowed = uint16(),
	      remaining_additional_downlink_packets_allowed = uint16(),
	      validity_time = float32()
	     },
	   #packet_rate_status{}]).

gen_create_bridge_info_for_tsc() ->
    #create_bridge_info_for_tsc{
       bii = flag()
      }.

gen_created_bridge_info_for_tsc() ->
    #created_bridge_info_for_tsc{group = ie_group()}.

gen_ds_tt_port_number() ->
    #ds_tt_port_number{
       value = uint32()
      }.

gen_nw_tt_port_number() ->
    #nw_tt_port_number{
       value = uint32()
      }.

gen_tsn_bridge_id() ->
    #tsn_bridge_id{
       mac = oneof(['undefined', binary(6)])
      }.

gen_port_management_information_for_tsc() ->
    #port_management_information_for_tsc{group = ie_group()}.

gen_port_management_information_for_tsc_smr() ->
    #port_management_information_for_tsc_smr{group = ie_group()}.

gen_port_management_information_for_tsc_sdr() ->
    #port_management_information_for_tsc_sdr{group = ie_group()}.

gen_port_management_information_container() ->
    #port_management_information_container{
       value = binary()
      }.

gen_clock_drift_control_information() ->
    #clock_drift_control_information{group = ie_group()}.

gen_requested_clock_drift_information() ->
    #requested_clock_drift_information{
       rrcr = flag(),
       rrto = flag()
      }.

gen_clock_drift_report() ->
    #clock_drift_report{group = ie_group()}.

gen_tsn_time_domain_number() ->
    #tsn_time_domain_number{
       number = uint8()
      }.

gen_time_offset_threshold() ->
    #time_offset_threshold{
       threshold = int64()
      }.

gen_cumulative_rateratio_threshold() ->
    #cumulative_rateratio_threshold{
       threshold = uint32()
      }.

gen_time_offset_measurement() ->
    #time_offset_measurement{
       measurement = int64()
      }.

gen_cumulative_rateratio_measurement() ->
    #cumulative_rateratio_measurement{
       measurement = uint32()
      }.

gen_remove_srr() ->
    #remove_srr{group = ie_group()}.

gen_create_srr() ->
    #create_srr{group = ie_group()}.

gen_update_srr() ->
    #update_srr{group = ie_group()}.

gen_session_report() ->
    #session_report{group = ie_group()}.

gen_srr_id() ->
    #srr_id{
       id = uint8()
      }.

gen_access_availability_control_information() ->
    #access_availability_control_information{group = ie_group()}.

gen_requested_access_availability_information() ->
    #requested_access_availability_information{
       rrca = flag()
      }.

gen_access_availability_report() ->
    #access_availability_report{group = ie_group()}.

gen_access_availability_information() ->
    #access_availability_information{
       status = oneof(['unavailable', 'available']),
       type = oneof(['TGPP', 'Non-TGPP'])
      }.

gen_provide_atsss_control_information() ->
    #provide_atsss_control_information{group = ie_group()}.

gen_atsss_control_parameters() ->
    #atsss_control_parameters{group = ie_group()}.

gen_mptcp_control_information() ->
    #mptcp_control_information{
       tci = flag()
      }.

gen_atsss_ll_control_information() ->
    #atsss_ll_control_information{
       lli = flag()
      }.

gen_pmf_control_information() ->
    #pmf_control_information{
       pmfi = flag()
      }.

gen_mptcp_parameters() ->
    #mptcp_parameters{group = ie_group()}.

gen_atsss_ll_parameters() ->
    #atsss_ll_parameters{group = ie_group()}.

gen_pmf_parameters() ->
    #pmf_parameters{group = ie_group()}.

gen_mptcp_address_information() ->
    #mptcp_address_information{
       proxy_type = uint8(),
       proxy_port = uint16(),
       ipv4 = oneof(['undefined', ip4_address()]),
       ipv6 = oneof(['undefined', ip6_address()])
      }.

gen_ue_link_specific_ip_address() ->
    #ue_link_specific_ip_address{
       tgpp_ipv4 = oneof(['undefined', ip4_address()]),
       tgpp_ipv6 = oneof(['undefined', ip6_address()]),
       non_tgpp_ipv4 = oneof(['undefined', ip4_address()]),
       non_tgpp_ipv6 = oneof(['undefined', ip6_address()])
      }.

gen_pmf_address_information() ->
    oneof([#pmf_address_information{
	      ipv4 = ip4_address(),
	      tgpp_port = uint16(),
	      non_tgpp_port = uint16()
	     },
	   #pmf_address_information{
	      ipv6 = ip6_address(),
	      tgpp_port = uint16(),
	      non_tgpp_port = uint16()
	     },
	   #pmf_address_information{
	      ipv4 = ip4_address(),
	      ipv6 = ip6_address(),
	      tgpp_port = uint16(),
	      non_tgpp_port = uint16()
	     },
	   #pmf_address_information{
	      ipv4 = ip4_address(),
	      ipv6 = ip6_address(),
	      tgpp_port = uint16(),
	      non_tgpp_port = uint16(),
	      tgpp_mac = binary(6),
	      non_tgpp_mac = binary(6)
	     },
	   #pmf_address_information{
	      tgpp_mac = binary(6),
	      non_tgpp_mac = binary(6)
	     },
	   #pmf_address_information{}]).

gen_atsss_ll_information() ->
    #atsss_ll_information{
       lli = flag()
      }.

gen_data_network_access_identifier() ->
    #data_network_access_identifier{
       value = binary()
      }.

gen_ue_ip_address_pool_information() ->
    #ue_ip_address_pool_information{group = ie_group()}.

gen_average_packet_delay() ->
    #average_packet_delay{
       delay = uint32()
      }.

gen_minimum_packet_delay() ->
    #minimum_packet_delay{
       delay = uint32()
      }.

gen_maximum_packet_delay() ->
    #maximum_packet_delay{
       delay = uint32()
      }.

gen_qos_report_trigger() ->
    #qos_report_trigger{
       ire = flag(),
       thr = flag(),
       per = flag()
    }.

gen_gtp_u_path_qos_control_information() ->
    #gtp_u_path_qos_control_information{group = ie_group()}.

gen_gtp_u_path_qos_report() ->
    #gtp_u_path_qos_report{group = ie_group()}.

gen_path_report_qos_information() ->
    #path_report_qos_information{group = ie_group()}.

gen_gtp_u_path_interface_type() ->
    #gtp_u_path_interface_type{
       n3 = flag(),
       n9 = flag()
      }.

gen_qos_monitoring_per_qos_flow_control_information() ->
    #qos_monitoring_per_qos_flow_control_information{group = ie_group()}.

gen_requested_qos_monitoring() ->
    #requested_qos_monitoring{
       rp = flag(),
       ul = flag(),
       dl = flag()
      }.

gen_reporting_frequency() ->
    #reporting_frequency{
       sesrl = flag(),
       perio = flag(),
       evett = flag()
      }.

gen_packet_delay_thresholds() ->
    #packet_delay_thresholds{
       downlink_packet_delay_threshold = oneof(['undefined', uint32()]),
       uplink_packet_delay_threshold = oneof(['undefined', uint32()]),
       round_trip_packet_delay_threshold = oneof(['undefined', uint32()])
      }.

gen_minimum_wait_time() ->
    #minimum_wait_time{
	  time = uint32()
    }.

gen_qos_monitoring_report() ->
    #qos_monitoring_report{group = ie_group()}.

gen_qos_monitoring_measurement() ->
    #qos_monitoring_measurement{
	  packet_delay_measurement_failure = boolean(),
	  downlink_packet_delay = oneof(['undefined', uint32()]),
	  uplink_packet_delay = oneof(['undefined', uint32()]),
	  round_trip_packet_delay = oneof(['undefined', uint32()])
    }.

gen_mt_edt_control_information() ->
    #mt_edt_control_information{
	  rdsi = flag()
    }.

gen_dl_data_packets_size() ->
    #dl_data_packets_size{
	  size = uint16()
    }.

gen_qer_control_indications() ->
    #qer_control_indications{
	  nord = flag(),
	  moed = flag(),
	  rcsrt = flag()
    }.

gen_packet_rate_status_report() ->
    #packet_rate_status_report{group = ie_group()}.

gen_nf_instance_id() ->
    #nf_instance_id{
       value = binary(16)
      }.

gen_ethernet_context_information() ->
    #ethernet_context_information{group = ie_group()}.

gen_redundant_transmission_parameters() ->
    #redundant_transmission_parameters{group = ie_group()}.

gen_updated_pdr() ->
    #updated_pdr{group = ie_group()}.

gen_s_nssai() ->
    #s_nssai{
       sst = uint8(),
       sd = uint24()
      }.

gen_ip_version() ->
    #ip_version{
       v6 = flag(),
       v4 = flag()
      }.

gen_pfcpasreq_flags() ->
    #pfcpasreq_flags{
       uupsi = flag()
      }.

gen_data_status() ->
    #data_status{
       buff = flag(),
       drop = flag()
      }.

gen_provide_rds_configuration_information() ->
    #provide_rds_configuration_information{group = ie_group()}.

gen_rds_configuration_information() ->
    #rds_configuration_information{
       rds = flag()
      }.

gen_query_packet_rate_status_ie_smreq() ->
    #query_packet_rate_status_ie_smreq{group = ie_group()}.

gen_packet_rate_status_report_ie_smresp() ->
    #packet_rate_status_report_ie_smresp{group = ie_group()}.

gen_mptcp_applicable_indication() ->
    #mptcp_applicable_indication{
       mai = flag()
      }.

gen_bridge_management_information_container() ->
    #bridge_management_information_container{
       value = binary()
      }.

gen_ue_ip_address_usage_information() ->
    #ue_ip_address_usage_information{group = ie_group()}.

gen_number_of_ue_ip_addresses() ->
    oneof([#number_of_ue_ip_addresses{
	      ipv6 = uint32(),
	      ipv4 = undefined},
	   #number_of_ue_ip_addresses{
	      ipv6 = undefined,
	      ipv4 = uint32()},
	   #number_of_ue_ip_addresses{
	      ipv6 = uint32(),
	      ipv4 = uint32()}
	  ]).

gen_validity_timer() ->
    #validity_timer{
       validity_timer = uint16()
      }.

gen_redundant_transmission_forwarding() ->
    #redundant_transmission_forwarding{group = ie_group()}.

gen_transport_delay_reporting() ->
    #transport_delay_reporting{group = ie_group()}.

gen_bbf_up_function_features() ->
    #bbf_up_function_features{
       nat_up = flag(),
       nat_cp = flag(),
       lcp_keepalive_offload = flag(),
       lns = flag(),
       lac = flag(),
       ipoe = flag(),
       pppoe = flag()
      }.

gen_logical_port() ->
    #logical_port{
       port = binary()
      }.

gen_bbf_outer_header_creation() ->
    #bbf_outer_header_creation{
       cpr_nsh = flag(),
       traffic_endpoint = flag(),
       l2tp = flag(),
       ppp = flag(),
       tunnel_id = uint16(),
       session_id = uint16()
      }.

gen_bbf_outer_header_removal() ->
    #bbf_outer_header_removal{
	 header = oneof(['Ethernet',
			 'PPPoE / Ethernet',
			 'PPP / PPPoE / Ethernet',
			 'L2TP',
			 'PPP / L2TP'])
      }.

gen_pppoe_session_id() ->
    #pppoe_session_id{
       id = uint16()
      }.

gen_ppp_protocol() ->
    #ppp_protocol{
       control = flag(),
       data = flag(),
       protocol = oneof([undefined, uint16()])
      }.

gen_verification_timers() ->
    #verification_timers{
	 interval = uint16(),
	 count = uint8()
      }.

gen_ppp_lcp_magic_number() ->
    #ppp_lcp_magic_number{
       tx = uint32(),
       rx = uint32()
      }.

gen_mtu() ->
    #mtu{
       mtu = uint16()
      }.

gen_l2tp_tunnel_endpoint() ->
    #l2tp_tunnel_endpoint{
       endpoint = oneof([choose, ip4_address(), ip6_address()])
      }.

gen_l2tp_session_id() ->
    #l2tp_session_id{
       id = uint16()
      }.

gen_l2tp_type() ->
    #l2tp_type{
       type = flag()
      }.

gen_ppp_lcp_connectivity() ->
    #ppp_lcp_connectivity{group = ie_group()}.

gen_l2tp_tunnel() ->
    #l2tp_tunnel{group = ie_group()}.


gen_bbf_nat_outside_address() ->
    #bbf_nat_outside_address{
       ipv4 = ip4_address()
      }.

gen_bbf_apply_action() ->
    #bbf_apply_action{
       nat = flag()
      }.

gen_bbf_nat_external_port_range() ->
    #bbf_nat_external_port_range{
       ranges = list({uint16(), uint16()})
      }.

gen_bbf_nat_port_forward() ->
    #bbf_nat_port_forward{
       forwards = list({ip4_address(), uint16(), uint16(), uint8()})
      }.

gen_bbf_nat_port_block() ->
    #bbf_nat_port_block{
       block = binary()
      }.

gen_bbf_dynamic_port_block_starting_port() ->
    #bbf_dynamic_port_block_starting_port{
       start = uint16()
      }.
