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
    numtests(1000,
	     ?FORALL(Msg, msg_gen(),
		     begin
			 ct:pal("Msg: ~p", [Msg]),
			 Enc = pfcp_packet:encode(Msg),
			 ?equal(Enc, pfcp_packet:encode(pfcp_packet:decode(Enc)))
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

encode_dns_label(Labels) ->
    ?LET(Name, Labels,
	 << <<(size(Label)):8, Label/binary>> || Label <- Name >>).

flag() ->
    oneof([0,1]).

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

uint8() ->
    integer(0,16#ff).

uint16() ->
    integer(0,16#ffff).

uint24() ->
    integer(0,16#ffffff).

int32() ->
    integer(-16#7fffffff,16#7fffffff).

uint32() ->
    integer(0,16#ffffffff).

uint64() ->
    integer(0,16#ffffffffffffffff).

ip4_address() ->
    binary(4).

ip6_address() ->
    binary(16).

binstr_number(Min, Max) ->
    ?LET(X,
	 ?LET(I, integer(Min,Max), vector(I, integer($0, $9))), list_to_binary(X)).

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
      seid = frequency([ {1,undefined}, {10, integer(0,16#ffffffff)}]),
      seq_no = integer(0,16#ffffff),
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
     gen_ethernet_traffic_information()
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
     gen_tp_packet_measurement(),
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
		  'System failure'])
      }.

gen_source_interface() ->
    #source_interface{
       interface = oneof(['Access',
			  'Core',
			  'SGi-LAN',
			  'CP-function'])
      }.

gen_f_teid() ->
    #f_teid{
       teid = uint32(),
       ipv6 = oneof([undefined, ip6_address()]),
       ipv4 = oneof([undefined, ip4_address()]),
       choose_id = byte()
}.

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
       flow_label = oneof([undefined, uint24()])
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
       mac_addresses_reporting = flag(),
       envelope_closure = flag(),
       time_quota = flag(),
       volume_quota = flag()
      }.

gen_redirect_information() ->
    #redirect_information{
       type = oneof(['IPv4',
		     'IPv6',
		     'URL',
		     'SIP URI']),
       address = binary()
      }.

gen_report_type() ->
    #report_type{
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
       policy_identifier = ?LET(I, integer(0,255), binary(I))
      }.

gen_destination_interface() ->
    #destination_interface{
       interface = oneof(['Access',
			  'Core',
			  'SGi-LAN',
			  'CP-function'])
      }.

gen_up_function_features() ->
    #up_function_features{
       treu = flag(),
       heeu = flag(),
       pfdm = flag(),
       ftup = flag(),
       trst = flag(),
       dlbd = flag(),
       ddnd = flag(),
       bucp = flag(),
       quoac = flag(),
       udbc = flag(),
       pdiu = flag(),
       empu = flag()
      }.

gen_apply_action() ->
    #apply_action{
       dupl = flag(),
       nocp = flag(),
       buff = flag(),
       forw = flag(),
       drop = flag()
      }.

gen_downlink_data_service_information() ->
    #downlink_data_service_information{
       value = oneof(['undefined', uint8()])
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
       dl_buffer_value = integer(0,16#1f)
      }.

gen_dl_buffering_suggested_packet_count() ->
    #dl_buffering_suggested_packet_count{
       count = uint32()
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
       timer_value = integer(0,16#1f)
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
	  custom = oneof(['undefined', binary()])
      }.

gen_measurement_method() ->
    #measurement_method{
	  event = flag(),
	  volum = flag(),
	  durat = flag()
}.

gen_usage_report_trigger() ->
    #usage_report_trigger{
	  immer = flag(),
	  droth = flag(),
	  stopt = flag(),
	  start = flag(),
	  quhti = flag(),
	  timth = flag(),
	  volth = flag(),
	  perio = flag(),
	  macar = flag(),
	  envcl = flag(),
	  monit = flag(),
	  termr = flag(),
	  liusa = flag(),
	  timqu = flag(),
	  volqu = flag()
}.

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
	      {integer(0,99), integer(0,999), integer(0,16#fff)}
	     ]),
       csid = ?LET(I, integer(0,15), vector(I, uint16()))
      }.

gen_volume_measurement() ->
    gen_volume(volume_measurement).

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
      value = oneof(['undefined', uint64()])
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
      [#outer_header_creation{
	  type = 'GTP-U', teid = uint32(), ipv4 = ip4_address()},
       #outer_header_creation{
	  type = 'GTP-U', teid = uint32(), ipv6 = ip6_address()},
       #outer_header_creation{
	  type = 'GTP-U', teid = uint32(), ipv4 = ip4_address(), ipv6 = ip6_address()},
       #outer_header_creation{
	  type = 'UDP', ipv4 = ip4_address(), port = uint16()},
       #outer_header_creation{
	  type = 'UDP', ipv6 = ip6_address(), port = uint16()}
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
       type = oneof([undefined, src, dst]),
       ipv4 = oneof([undefined, ip4_address()]),
       ipv6 = oneof([undefined, ip6_address()])
      }.

gen_packet_rate() ->
    Unit = oneof([undefined, 'minute','6 minutes', 'hour', 'day', 'week']),
    #packet_rate{
       ul_time_unit = Unit,
       ul_max_packet_rate = uint16(),
       dl_time_unit = Unit,
       dl_max_packet_rate = uint16()
      }.

gen_outer_header_removal() ->
    #outer_header_removal{
       header =
	   oneof(
	     ['GTP-U/UDP/IPv4',
	      'GTP-U/UDP/IPv6',
	      'UDP/IPv4',
	      'UDP/IPv6'])
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
       radi = flag(),
       inam = flag(),
       mbqe = flag()
      }.

gen_node_report_type() ->
    #node_report_type{
       upfr = flag()
}.

gen_user_plane_path_failure_report() ->
    #user_plane_path_failure_report{group = ie_group()}.

gen_remote_gtp_u_peer() ->
    #remote_gtp_u_peer{
       ipv4 = oneof([undefined, ip4_address()]),
       ipv6 = oneof([undefined, ip6_address()])
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
       release_timer_value = integer(0,16#1f)
      }.

gen_pdn_type() ->
    #pdn_type{
       pdn_type = oneof(['IPv4', 'IPv6', 'IPv4v6', 'Non-IP'])
      }.

id_range(bar) -> integer(0, 16#ff);
id_range(pdr) -> integer(0, 16#ffff);
id_range(_)   -> integer(0, 16#ffffffff).

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
       teid_range = oneof([undefined, {byte(), integer(1,7)}]),
       ipv4 = oneof([undefined, ip4_address()]),
       ipv6 = oneof([undefined, ip6_address()]),
       network_instance = oneof([undefined, dns_name()])
      }.

gen_user_plane_inactivity_timer() ->
    #user_plane_inactivity_timer{
       timer = uint32()
      }.

gen_aggregated_urrs() ->
    #aggregated_urrs{group = ie_group()}.

gen_multiplier() ->
    #multiplier{
       digits = uint64(),
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
       qfi = uint8()
      }.

gen_query_urr_reference() ->
    #query_urr_reference{
       reference = uint32()
      }.

gen_additional_usage_reports_information() ->
    #additional_usage_reports_information{
       auri = flag(),
       reports = integer(0, 16#7fff)
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
       pcp = oneof(['undefined', integer(0, 7)]),
       dei = oneof(['undefined', flag()]),
       vid = oneof(['undefined', integer(0, 16#fff)])
      }.

gen_s_tag() ->
    #s_tag{
       pcp = oneof(['undefined', integer(0, 7)]),
       dei = oneof(['undefined', flag()]),
       vid = oneof(['undefined', integer(0, 16#fff)])
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
       imei = oneof(['undefined', imei(), imeisv()])
      }.

gen_ethernet_pdu_session_information() ->
    #ethernet_pdu_session_information{
       ethi = flag()
      }.

gen_ethernet_traffic_information() ->
    #ethernet_traffic_information{group = ie_group()}.

gen_mac_addresses_detected() ->
    #mac_addresses_detected{
       macs = ?LET(I, integer(0,15), vector(I, binary(6)))
      }.

gen_mac_addresses_removed() ->
    #mac_addresses_removed{
       macs = ?LET(I, integer(0,15), vector(I, binary(6)))
      }.

gen_ethernet_inactivity_timer() ->
    #ethernet_inactivity_timer{
       timer = uint32()
      }.

gen_tp_packet_measurement() ->
    gen_volume(tp_packet_measurement).

gen_enterprise_priv() ->
    {{18681, 500}, binary()}.
