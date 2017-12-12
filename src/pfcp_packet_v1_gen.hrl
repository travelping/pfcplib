%% This file is auto-generated. DO NOT EDIT

msg_description_v1(heartbeat_request) -> <<"Heartbeat Request">>;
msg_description_v1(heartbeat_response) -> <<"Heartbeat Response">>;
msg_description_v1(pfd_management_request) -> <<"PFD Management Request">>;
msg_description_v1(pfd_management_response) -> <<"PFD Management Response">>;
msg_description_v1(association_setup_request) -> <<"Association Setup Request">>;
msg_description_v1(association_setup_response) -> <<"Association Setup Response">>;
msg_description_v1(association_update_request) -> <<"Association Update Request">>;
msg_description_v1(association_update_response) -> <<"Association Update Response">>;
msg_description_v1(association_release_request) -> <<"Association Release Request">>;
msg_description_v1(association_release_response) -> <<"Association Release Response">>;
msg_description_v1(version_not_supported_response) -> <<"Version Not Supported Response">>;
msg_description_v1(node_report_request) -> <<"Node Report Request">>;
msg_description_v1(node_report_response) -> <<"Node Report Response">>;
msg_description_v1(session_set_deletion_request) -> <<"Session Set Deletion Request">>;
msg_description_v1(session_set_deletion_response) -> <<"Session Set Deletion Response">>;
msg_description_v1(session_establishment_request) -> <<"Session Establishment Request">>;
msg_description_v1(session_establishment_response) -> <<"Session Establishment Response">>;
msg_description_v1(session_modification_request) -> <<"Session Modification Request">>;
msg_description_v1(session_modification_response) -> <<"Session Modification Response">>;
msg_description_v1(session_deletion_request) -> <<"Session Deletion Request">>;
msg_description_v1(session_deletion_response) -> <<"Session Deletion Response">>;
msg_description_v1(session_report_request) -> <<"Session Report Request">>;
msg_description_v1(session_report_response) -> <<"Session Report Response">>;
msg_description_v1(X) -> io_lib:format("~p", [X]).

message_type_v1(heartbeat_request) -> 1;
message_type_v1(heartbeat_response) -> 2;
message_type_v1(pfd_management_request) -> 3;
message_type_v1(pfd_management_response) -> 4;
message_type_v1(association_setup_request) -> 5;
message_type_v1(association_setup_response) -> 6;
message_type_v1(association_update_request) -> 7;
message_type_v1(association_update_response) -> 8;
message_type_v1(association_release_request) -> 9;
message_type_v1(association_release_response) -> 10;
message_type_v1(version_not_supported_response) -> 11;
message_type_v1(node_report_request) -> 12;
message_type_v1(node_report_response) -> 13;
message_type_v1(session_set_deletion_request) -> 14;
message_type_v1(session_set_deletion_response) -> 15;
message_type_v1(session_establishment_request) -> 50;
message_type_v1(session_establishment_response) -> 51;
message_type_v1(session_modification_request) -> 52;
message_type_v1(session_modification_response) -> 53;
message_type_v1(session_deletion_request) -> 54;
message_type_v1(session_deletion_response) -> 55;
message_type_v1(session_report_request) -> 56;
message_type_v1(session_report_response) -> 57;
message_type_v1(1) -> heartbeat_request;
message_type_v1(2) -> heartbeat_response;
message_type_v1(3) -> pfd_management_request;
message_type_v1(4) -> pfd_management_response;
message_type_v1(5) -> association_setup_request;
message_type_v1(6) -> association_setup_response;
message_type_v1(7) -> association_update_request;
message_type_v1(8) -> association_update_response;
message_type_v1(9) -> association_release_request;
message_type_v1(10) -> association_release_response;
message_type_v1(11) -> version_not_supported_response;
message_type_v1(12) -> node_report_request;
message_type_v1(13) -> node_report_response;
message_type_v1(14) -> session_set_deletion_request;
message_type_v1(15) -> session_set_deletion_response;
message_type_v1(50) -> session_establishment_request;
message_type_v1(51) -> session_establishment_response;
message_type_v1(52) -> session_modification_request;
message_type_v1(53) -> session_modification_response;
message_type_v1(54) -> session_deletion_request;
message_type_v1(55) -> session_deletion_response;
message_type_v1(56) -> session_report_request;
message_type_v1(57) -> session_report_response;
message_type_v1(Type) -> error(badarg, [Type]).

enum_v1_base_time_interval_type('CTP') -> 0;
enum_v1_base_time_interval_type('DTP') -> 1;
enum_v1_base_time_interval_type(0) -> 'CTP';
enum_v1_base_time_interval_type(1) -> 'DTP';
enum_v1_base_time_interval_type(X) when is_integer(X) -> X.

enum_v1_type('IPv4') -> 0;
enum_v1_type('IPv6') -> 1;
enum_v1_type('URL') -> 2;
enum_v1_type('SIP URI') -> 3;
enum_v1_type(0) -> 'IPv4';
enum_v1_type(1) -> 'IPv6';
enum_v1_type(2) -> 'URL';
enum_v1_type(3) -> 'SIP URI';
enum_v1_type(X) when is_integer(X) -> X.

enum_v1_release_timer_unit('2 seconds') -> 0;
enum_v1_release_timer_unit('1 minute') -> 1;
enum_v1_release_timer_unit('10 minutes') -> 2;
enum_v1_release_timer_unit('1 hour') -> 3;
enum_v1_release_timer_unit('10 hours') -> 4;
enum_v1_release_timer_unit('infinite') -> 7;
enum_v1_release_timer_unit(0) -> '2 seconds';
enum_v1_release_timer_unit(1) -> '1 minute';
enum_v1_release_timer_unit(2) -> '10 minutes';
enum_v1_release_timer_unit(3) -> '1 hour';
enum_v1_release_timer_unit(4) -> '10 hours';
enum_v1_release_timer_unit(7) -> 'infinite';
enum_v1_release_timer_unit(X) when is_integer(X) -> X.

enum_v1_header_type('HTTP') -> 0;
enum_v1_header_type(0) -> 'HTTP';
enum_v1_header_type(X) when is_integer(X) -> X.

enum_v1_header('GTP-U/UDP/IPv4') -> 0;
enum_v1_header('GTP-U/UDP/IPv6') -> 1;
enum_v1_header('UDP/IPv4') -> 2;
enum_v1_header('UDP/IPv6') -> 3;
enum_v1_header(0) -> 'GTP-U/UDP/IPv4';
enum_v1_header(1) -> 'GTP-U/UDP/IPv6';
enum_v1_header(2) -> 'UDP/IPv4';
enum_v1_header(3) -> 'UDP/IPv6';
enum_v1_header(X) when is_integer(X) -> X.

enum_v1_direction('Unspecified') -> 0;
enum_v1_direction('Downlink') -> 1;
enum_v1_direction('Uplink') -> 2;
enum_v1_direction('Bidirectional') -> 3;
enum_v1_direction(0) -> 'Unspecified';
enum_v1_direction(1) -> 'Downlink';
enum_v1_direction(2) -> 'Uplink';
enum_v1_direction(3) -> 'Bidirectional';
enum_v1_direction(X) when is_integer(X) -> X.

enum_v1_timer_unit('2 seconds') -> 0;
enum_v1_timer_unit('1 minute') -> 1;
enum_v1_timer_unit('10 minutes') -> 2;
enum_v1_timer_unit('1 hour') -> 3;
enum_v1_timer_unit('10 hours') -> 4;
enum_v1_timer_unit('infinite') -> 7;
enum_v1_timer_unit(0) -> '2 seconds';
enum_v1_timer_unit(1) -> '1 minute';
enum_v1_timer_unit(2) -> '10 minutes';
enum_v1_timer_unit(3) -> '1 hour';
enum_v1_timer_unit(4) -> '10 hours';
enum_v1_timer_unit(7) -> 'infinite';
enum_v1_timer_unit(X) when is_integer(X) -> X.

enum_v1_dl_buffer_unit('2 seconds') -> 0;
enum_v1_dl_buffer_unit('1 minute') -> 1;
enum_v1_dl_buffer_unit('10 minutes') -> 2;
enum_v1_dl_buffer_unit('1 hour') -> 3;
enum_v1_dl_buffer_unit('10 hours') -> 4;
enum_v1_dl_buffer_unit('infinite') -> 7;
enum_v1_dl_buffer_unit(0) -> '2 seconds';
enum_v1_dl_buffer_unit(1) -> '1 minute';
enum_v1_dl_buffer_unit(2) -> '10 minutes';
enum_v1_dl_buffer_unit(3) -> '1 hour';
enum_v1_dl_buffer_unit(4) -> '10 hours';
enum_v1_dl_buffer_unit(7) -> 'infinite';
enum_v1_dl_buffer_unit(X) when is_integer(X) -> X.

enum_v1_interface('Access') -> 0;
enum_v1_interface('Core') -> 1;
enum_v1_interface('SGi-LAN') -> 2;
enum_v1_interface('CP-function') -> 3;
enum_v1_interface(0) -> 'Access';
enum_v1_interface(1) -> 'Core';
enum_v1_interface(2) -> 'SGi-LAN';
enum_v1_interface(3) -> 'CP-function';
enum_v1_interface(X) when is_integer(X) -> X.

enum_v1_dl('OPEN') -> 0;
enum_v1_dl('CLOSED') -> 1;
enum_v1_dl(0) -> 'OPEN';
enum_v1_dl(1) -> 'CLOSED';
enum_v1_dl(X) when is_integer(X) -> X.

enum_v1_ul('OPEN') -> 0;
enum_v1_ul('CLOSED') -> 1;
enum_v1_ul(0) -> 'OPEN';
enum_v1_ul(1) -> 'CLOSED';
enum_v1_ul(X) when is_integer(X) -> X.

enum_v1_cause('Reserved') -> 0;
enum_v1_cause('Request accepted') -> 1;
enum_v1_cause('Request rejected') -> 64;
enum_v1_cause('Session context not found') -> 65;
enum_v1_cause('Mandatory IE missing') -> 66;
enum_v1_cause('Conditional IE missing') -> 67;
enum_v1_cause('Invalid length') -> 68;
enum_v1_cause('Mandatory IE incorrect') -> 69;
enum_v1_cause('Invalid Forwarding Policy') -> 70;
enum_v1_cause('Invalid F-TEID allocation option') -> 71;
enum_v1_cause('No established Sx Association') -> 72;
enum_v1_cause('Rule creation/modification Failure') -> 73;
enum_v1_cause('PFCP entity in congestion') -> 74;
enum_v1_cause('No resources available') -> 75;
enum_v1_cause('Service not supported') -> 76;
enum_v1_cause('System failure') -> 77;
enum_v1_cause(0) -> 'Reserved';
enum_v1_cause(1) -> 'Request accepted';
enum_v1_cause(64) -> 'Request rejected';
enum_v1_cause(65) -> 'Session context not found';
enum_v1_cause(66) -> 'Mandatory IE missing';
enum_v1_cause(67) -> 'Conditional IE missing';
enum_v1_cause(68) -> 'Invalid length';
enum_v1_cause(69) -> 'Mandatory IE incorrect';
enum_v1_cause(70) -> 'Invalid Forwarding Policy';
enum_v1_cause(71) -> 'Invalid F-TEID allocation option';
enum_v1_cause(72) -> 'No established Sx Association';
enum_v1_cause(73) -> 'Rule creation/modification Failure';
enum_v1_cause(74) -> 'PFCP entity in congestion';
enum_v1_cause(75) -> 'No resources available';
enum_v1_cause(76) -> 'Service not supported';
enum_v1_cause(77) -> 'System failure';
enum_v1_cause(X) when is_integer(X) -> X.

%% decode create_pdr
decode_v1_element(<<M_group/binary>>, 1) ->
    #create_pdr{group = decode_v1_grouped(M_group)};

%% decode pdi
decode_v1_element(<<M_group/binary>>, 2) ->
    #pdi{group = decode_v1_grouped(M_group)};

%% decode create_far
decode_v1_element(<<M_group/binary>>, 3) ->
    #create_far{group = decode_v1_grouped(M_group)};

%% decode forwarding_parameters
decode_v1_element(<<M_group/binary>>, 4) ->
    #forwarding_parameters{group = decode_v1_grouped(M_group)};

%% decode duplicating_parameters
decode_v1_element(<<M_group/binary>>, 5) ->
    #duplicating_parameters{group = decode_v1_grouped(M_group)};

%% decode create_urr
decode_v1_element(<<M_group/binary>>, 6) ->
    #create_urr{group = decode_v1_grouped(M_group)};

%% decode create_qer
decode_v1_element(<<M_group/binary>>, 7) ->
    #create_qer{group = decode_v1_grouped(M_group)};

%% decode created_pdr
decode_v1_element(<<M_group/binary>>, 8) ->
    #created_pdr{group = decode_v1_grouped(M_group)};

%% decode update_pdr
decode_v1_element(<<M_group/binary>>, 9) ->
    #update_pdr{group = decode_v1_grouped(M_group)};

%% decode update_far
decode_v1_element(<<M_group/binary>>, 10) ->
    #update_far{group = decode_v1_grouped(M_group)};

%% decode update_forwarding_parameters
decode_v1_element(<<M_group/binary>>, 11) ->
    #update_forwarding_parameters{group = decode_v1_grouped(M_group)};

%% decode update_bar_response
decode_v1_element(<<M_group/binary>>, 12) ->
    #update_bar_response{group = decode_v1_grouped(M_group)};

%% decode update_urr
decode_v1_element(<<M_group/binary>>, 13) ->
    #update_urr{group = decode_v1_grouped(M_group)};

%% decode update_qer
decode_v1_element(<<M_group/binary>>, 14) ->
    #update_qer{group = decode_v1_grouped(M_group)};

%% decode remove_pdr
decode_v1_element(<<M_group/binary>>, 15) ->
    #remove_pdr{group = decode_v1_grouped(M_group)};

%% decode remove_far
decode_v1_element(<<M_group/binary>>, 16) ->
    #remove_far{group = decode_v1_grouped(M_group)};

%% decode remove_urr
decode_v1_element(<<M_group/binary>>, 17) ->
    #remove_urr{group = decode_v1_grouped(M_group)};

%% decode remove_qer
decode_v1_element(<<M_group/binary>>, 18) ->
    #remove_qer{group = decode_v1_grouped(M_group)};

%% decode cause
decode_v1_element(<<M_cause:8/integer>>, 19) ->
    #cause{cause = enum_v1_cause(M_cause)};

%% decode source_interface
decode_v1_element(<<_:4,
		    M_interface:4/integer,
		    _/binary>>, 20) ->
    #source_interface{interface = enum_v1_interface(M_interface)};

%% decode f_teid
decode_v1_element(<<Data/binary>>, 21) ->
    decode_f_teid(Data, f_teid);

%% decode network_instance
decode_v1_element(<<M_instance/binary>>, 22) ->
    #network_instance{instance = decode_dns_label(M_instance)};

%% decode sdf_filter
decode_v1_element(<<Data/binary>>, 23) ->
    decode_sdf_filter(Data, sdf_filter);

%% decode application_id
decode_v1_element(<<M_indentifier/binary>>, 24) ->
    #application_id{indentifier = M_indentifier};

%% decode gate_status
decode_v1_element(<<_:4,
		    M_ul:2/integer,
		    M_dl:2/integer,
		    _/binary>>, 25) ->
    #gate_status{ul = enum_v1_ul(M_ul),
		 dl = enum_v1_dl(M_dl)};

%% decode mbr
decode_v1_element(<<M_ul:32/integer,
		    M_dl:32/integer,
		    _/binary>>, 26) ->
    #mbr{ul = M_ul,
	 dl = M_dl};

%% decode gbr
decode_v1_element(<<M_ul:32/integer,
		    M_dl:32/integer,
		    _/binary>>, 27) ->
    #gbr{ul = M_ul,
	 dl = M_dl};

%% decode qer_correlation_id
decode_v1_element(<<M_indentifier:32/integer,
		    _/binary>>, 28) ->
    #qer_correlation_id{indentifier = M_indentifier};

%% decode precedence
decode_v1_element(<<M_precedence:32/integer,
		    _/binary>>, 29) ->
    #precedence{precedence = M_precedence};

%% decode transport_level_marking
decode_v1_element(<<M_tos:16/integer,
		    _/binary>>, 30) ->
    #transport_level_marking{tos = M_tos};

%% decode volume_threshold
decode_v1_element(<<Data/binary>>, 31) ->
    decode_volume_threshold(Data, volume_threshold);

%% decode time_threshold
decode_v1_element(<<M_threshold:32/integer,
		    _/binary>>, 32) ->
    #time_threshold{threshold = M_threshold};

%% decode monitoring_time
decode_v1_element(<<M_time:32/integer,
		    _/binary>>, 33) ->
    #monitoring_time{time = M_time};

%% decode subsequent_volume_threshold
decode_v1_element(<<Data/binary>>, 34) ->
    decode_volume_threshold(Data, subsequent_volume_threshold);

%% decode subsequent_time_threshold
decode_v1_element(<<M_threshold:32/integer,
		    _/binary>>, 35) ->
    #subsequent_time_threshold{threshold = M_threshold};

%% decode inactivity_detection_time
decode_v1_element(<<M_time:32/integer,
		    _/binary>>, 36) ->
    #inactivity_detection_time{time = M_time};

%% decode reporting_triggers
decode_v1_element(<<M_linked_usage_reporting:1/integer,
		    M_dropped_dl_traffic_threshold:1/integer,
		    M_stop_of_traffic:1/integer,
		    M_start_of_traffic:1/integer,
		    M_quota_holding_time:1/integer,
		    M_time_threshold:1/integer,
		    M_volume_threshold:1/integer,
		    M_periodic_reporting:1/integer,
		    _:5,
		    M_envelope_closure:1/integer,
		    M_time_quota:1/integer,
		    M_volume_quota:1/integer,
		    _/binary>>, 37) ->
    #reporting_triggers{linked_usage_reporting = M_linked_usage_reporting,
			dropped_dl_traffic_threshold = M_dropped_dl_traffic_threshold,
			stop_of_traffic = M_stop_of_traffic,
			start_of_traffic = M_start_of_traffic,
			quota_holding_time = M_quota_holding_time,
			time_threshold = M_time_threshold,
			volume_threshold = M_volume_threshold,
			periodic_reporting = M_periodic_reporting,
			envelope_closure = M_envelope_closure,
			time_quota = M_time_quota,
			volume_quota = M_volume_quota};

%% decode redirect_information
decode_v1_element(<<_:4,
		    M_type:4/integer,
		    M_address_len:16/integer, M_address:M_address_len/bytes,
		    _/binary>>, 38) ->
    #redirect_information{type = enum_v1_type(M_type),
			  address = M_address};

%% decode report_type
decode_v1_element(<<_:5,
		    M_erir:1/integer,
		    M_usar:1/integer,
		    M_dldr:1/integer,
		    _/binary>>, 39) ->
    #report_type{erir = M_erir,
		 usar = M_usar,
		 dldr = M_dldr};

%% decode offending_ie
decode_v1_element(<<M_type:16/integer>>, 40) ->
    #offending_ie{type = M_type};

%% decode forwarding_policy
decode_v1_element(<<M_policy_identifier_len:8/integer, M_policy_identifier:M_policy_identifier_len/bytes,
		    _/binary>>, 41) ->
    #forwarding_policy{policy_identifier = M_policy_identifier};

%% decode destination_interface
decode_v1_element(<<_:4,
		    M_interface:4/integer,
		    _/binary>>, 42) ->
    #destination_interface{interface = enum_v1_interface(M_interface)};

%% decode up_function_features
decode_v1_element(<<M_treu:1/integer,
		    M_heeu:1/integer,
		    M_pfdm:1/integer,
		    M_ftup:1/integer,
		    M_trst:1/integer,
		    M_dlbd:1/integer,
		    M_ddnd:1/integer,
		    M_bucp:1/integer,
		    _:7,
		    M_empu:1/integer,
		    _/binary>>, 43) ->
    #up_function_features{treu = M_treu,
			  heeu = M_heeu,
			  pfdm = M_pfdm,
			  ftup = M_ftup,
			  trst = M_trst,
			  dlbd = M_dlbd,
			  ddnd = M_ddnd,
			  bucp = M_bucp,
			  empu = M_empu};

%% decode apply_action
decode_v1_element(<<_:3,
		    M_dupl:1/integer,
		    M_nocp:1/integer,
		    M_buff:1/integer,
		    M_forw:1/integer,
		    M_drop:1/integer,
		    _/binary>>, 44) ->
    #apply_action{dupl = M_dupl,
		  nocp = M_nocp,
		  buff = M_buff,
		  forw = M_forw,
		  drop = M_drop};

%% decode downlink_data_service_information
decode_v1_element(<<Data/binary>>, 45) ->
    decode_paging_policy_indication(Data, downlink_data_service_information);

%% decode downlink_data_notification_delay
decode_v1_element(<<M_delay:8/integer,
		    _/binary>>, 46) ->
    #downlink_data_notification_delay{delay = M_delay};

%% decode dl_buffering_duration
decode_v1_element(<<M_dl_buffer_unit:3/integer,
		    M_dl_buffer_value:5/integer,
		    _/binary>>, 47) ->
    #dl_buffering_duration{dl_buffer_unit = enum_v1_dl_buffer_unit(M_dl_buffer_unit),
			   dl_buffer_value = M_dl_buffer_value};

%% decode dl_buffering_suggested_packet_count
decode_v1_element(<<M_count:16/integer>>, 48) ->
    #dl_buffering_suggested_packet_count{count = M_count};

%% decode sxsmreq_flags
decode_v1_element(<<_:5,
		    M_qaurr:1/integer,
		    M_sndem:1/integer,
		    M_drobu:1/integer,
		    _/binary>>, 49) ->
    #sxsmreq_flags{qaurr = M_qaurr,
		   sndem = M_sndem,
		   drobu = M_drobu};

%% decode sxsrrsp_flags
decode_v1_element(<<_:7,
		    M_drobu:1/integer,
		    _/binary>>, 50) ->
    #sxsrrsp_flags{drobu = M_drobu};

%% decode load_control_information
decode_v1_element(<<M_group/binary>>, 51) ->
    #load_control_information{group = decode_v1_grouped(M_group)};

%% decode sequence_number
decode_v1_element(<<M_number:32/integer>>, 52) ->
    #sequence_number{number = M_number};

%% decode metric
decode_v1_element(<<M_metric:8/integer>>, 53) ->
    #metric{metric = M_metric};

%% decode overload_control_information
decode_v1_element(<<M_group/binary>>, 54) ->
    #overload_control_information{group = decode_v1_grouped(M_group)};

%% decode timer
decode_v1_element(<<M_timer_unit:3/integer,
		    M_timer_value:5/integer,
		    _/binary>>, 55) ->
    #timer{timer_unit = enum_v1_timer_unit(M_timer_unit),
	   timer_value = M_timer_value};

%% decode pdr_id
decode_v1_element(<<M_id:16/integer,
		    _/binary>>, 56) ->
    #pdr_id{id = M_id};

%% decode f_seid
decode_v1_element(<<Data/binary>>, 57) ->
    decode_f_seid(Data, f_seid);

%% decode application_id_pfds
decode_v1_element(<<M_group/binary>>, 58) ->
    #application_id_pfds{group = decode_v1_grouped(M_group)};

%% decode pfd_context
decode_v1_element(<<M_group/binary>>, 59) ->
    #pfd_context{group = decode_v1_grouped(M_group)};

%% decode node_id
decode_v1_element(<<Data/binary>>, 60) ->
    decode_node_id(Data, node_id);

%% decode pfd_contents
decode_v1_element(<<Data/binary>>, 61) ->
    decode_pfd_contents(Data, pfd_contents);

%% decode measurement_method
decode_v1_element(<<_:5,
		    M_event:1/integer,
		    M_volum:1/integer,
		    M_durat:1/integer,
		    _/binary>>, 62) ->
    #measurement_method{event = M_event,
			volum = M_volum,
			durat = M_durat};

%% decode usage_report_trigger
decode_v1_element(<<M_immer:1/integer,
		    M_droth:1/integer,
		    M_stopt:1/integer,
		    M_start:1/integer,
		    M_quhti:1/integer,
		    M_timth:1/integer,
		    M_volth:1/integer,
		    M_perio:1/integer,
		    _:2,
		    M_envcl:1/integer,
		    M_monit:1/integer,
		    M_termr:1/integer,
		    M_liusa:1/integer,
		    M_timqu:1/integer,
		    M_volqu:1/integer,
		    _/binary>>, 63) ->
    #usage_report_trigger{immer = M_immer,
			  droth = M_droth,
			  stopt = M_stopt,
			  start = M_start,
			  quhti = M_quhti,
			  timth = M_timth,
			  volth = M_volth,
			  perio = M_perio,
			  envcl = M_envcl,
			  monit = M_monit,
			  termr = M_termr,
			  liusa = M_liusa,
			  timqu = M_timqu,
			  volqu = M_volqu};

%% decode measurement_period
decode_v1_element(<<M_period:32/integer,
		    _/binary>>, 64) ->
    #measurement_period{period = M_period};

%% decode fq_csid
decode_v1_element(<<Data/binary>>, 65) ->
    decode_fq_csid(Data, fq_csid);

%% decode volume_measurement
decode_v1_element(<<Data/binary>>, 66) ->
    decode_volume_threshold(Data, volume_measurement);

%% decode duration_measurement
decode_v1_element(<<M_duration:32/integer,
		    _/binary>>, 67) ->
    #duration_measurement{duration = M_duration};

%% decode application_detection_information
decode_v1_element(<<M_group/binary>>, 68) ->
    #application_detection_information{group = decode_v1_grouped(M_group)};

%% decode time_of_first_packet
decode_v1_element(<<M_seconds:32/integer,
		    M_fraction:32/integer,
		    _/binary>>, 69) ->
    #time_of_first_packet{seconds = M_seconds,
			  fraction = M_fraction};

%% decode time_of_last_packet
decode_v1_element(<<M_seconds:32/integer,
		    M_fraction:32/integer,
		    _/binary>>, 70) ->
    #time_of_last_packet{seconds = M_seconds,
			 fraction = M_fraction};

%% decode quota_holding_time
decode_v1_element(<<M_seconds:32/integer,
		    M_fraction:32/integer,
		    _/binary>>, 71) ->
    #quota_holding_time{seconds = M_seconds,
			fraction = M_fraction};

%% decode dropped_dl_traffic_threshold
decode_v1_element(<<Data/binary>>, 72) ->
    decode_dropped_dl_traffic_threshold(Data, dropped_dl_traffic_threshold);

%% decode volume_quota
decode_v1_element(<<Data/binary>>, 73) ->
    decode_volume_threshold(Data, volume_quota);

%% decode time_quota
decode_v1_element(<<M_quota:32/integer,
		    _/binary>>, 74) ->
    #time_quota{quota = M_quota};

%% decode start_time
decode_v1_element(<<M_seconds:32/integer,
		    M_fraction:32/integer,
		    _/binary>>, 75) ->
    #start_time{seconds = M_seconds,
		fraction = M_fraction};

%% decode end_time
decode_v1_element(<<M_seconds:32/integer,
		    M_fraction:32/integer,
		    _/binary>>, 76) ->
    #end_time{seconds = M_seconds,
	      fraction = M_fraction};

%% decode query_urr
decode_v1_element(<<M_group/binary>>, 77) ->
    #query_urr{group = decode_v1_grouped(M_group)};

%% decode usage_report_smr
decode_v1_element(<<M_group/binary>>, 78) ->
    #usage_report_smr{group = decode_v1_grouped(M_group)};

%% decode usage_report_sdr
decode_v1_element(<<M_group/binary>>, 79) ->
    #usage_report_sdr{group = decode_v1_grouped(M_group)};

%% decode usage_report_srr
decode_v1_element(<<M_group/binary>>, 80) ->
    #usage_report_srr{group = decode_v1_grouped(M_group)};

%% decode urr_id
decode_v1_element(<<M_id:32/integer,
		    _/binary>>, 81) ->
    #urr_id{id = M_id};

%% decode linked_urr_id
decode_v1_element(<<M_id:32/integer,
		    _/binary>>, 82) ->
    #linked_urr_id{id = M_id};

%% decode downlink_data_report
decode_v1_element(<<M_group/binary>>, 83) ->
    #downlink_data_report{group = decode_v1_grouped(M_group)};

%% decode outer_header_creation
decode_v1_element(<<Data/binary>>, 84) ->
    decode_outer_header_creation(Data, outer_header_creation);

%% decode create_bar
decode_v1_element(<<M_group/binary>>, 85) ->
    #create_bar{group = decode_v1_grouped(M_group)};

%% decode update_bar_request
decode_v1_element(<<M_group/binary>>, 86) ->
    #update_bar_request{group = decode_v1_grouped(M_group)};

%% decode remove_bar
decode_v1_element(<<M_group/binary>>, 87) ->
    #remove_bar{group = decode_v1_grouped(M_group)};

%% decode bar_id
decode_v1_element(<<M_id:8/integer,
		    _/binary>>, 88) ->
    #bar_id{id = M_id};

%% decode cp_function_features
decode_v1_element(<<_:6,
		    M_ovrl:1/integer,
		    M_load:1/integer,
		    _/binary>>, 89) ->
    #cp_function_features{ovrl = M_ovrl,
			  load = M_load};

%% decode usage_information
decode_v1_element(<<_:4,
		    M_ube:1/integer,
		    M_uae:1/integer,
		    M_aft:1/integer,
		    M_bef:1/integer,
		    _/binary>>, 90) ->
    #usage_information{ube = M_ube,
		       uae = M_uae,
		       aft = M_aft,
		       bef = M_bef};

%% decode application_instance_id
decode_v1_element(<<M_id/binary>>, 91) ->
    #application_instance_id{id = M_id};

%% decode flow_information
decode_v1_element(<<_:4,
		    M_direction:4/integer,
		    M_flow_len:16/integer, M_flow:M_flow_len/bytes,
		    _/binary>>, 92) ->
    #flow_information{direction = enum_v1_direction(M_direction),
		      flow = M_flow};

%% decode ue_ip_address
decode_v1_element(<<Data/binary>>, 93) ->
    decode_ue_ip_address(Data, ue_ip_address);

%% decode packet_rate
decode_v1_element(<<Data/binary>>, 94) ->
    decode_packet_rate(Data, packet_rate);

%% decode outer_header_removal
decode_v1_element(<<M_header:8/integer,
		    _/binary>>, 95) ->
    #outer_header_removal{header = enum_v1_header(M_header)};

%% decode recovery_time_stamp
decode_v1_element(<<M_seconds:32/integer,
		    M_fraction:32/integer,
		    _/binary>>, 96) ->
    #recovery_time_stamp{seconds = M_seconds,
			 fraction = M_fraction};

%% decode dl_flow_level_marking
decode_v1_element(<<Data/binary>>, 97) ->
    decode_dl_flow_level_marking(Data, dl_flow_level_marking);

%% decode header_enrichment
decode_v1_element(<<_:4,
		    M_header_type:4/integer,
		    M_name_len:16/integer, M_name:M_name_len/bytes,
		    M_value_len:16/integer, M_value:M_value_len/bytes,
		    _/binary>>, 98) ->
    #header_enrichment{header_type = enum_v1_header_type(M_header_type),
		       name = M_name,
		       value = M_value};

%% decode error_indication_report
decode_v1_element(<<M_group/binary>>, 99) ->
    #error_indication_report{group = decode_v1_grouped(M_group)};

%% decode measurement_information
decode_v1_element(<<_:6,
		    M_inam:1/integer,
		    M_mbqe:1/integer,
		    _/binary>>, 100) ->
    #measurement_information{inam = M_inam,
			     mbqe = M_mbqe};

%% decode node_report_type
decode_v1_element(<<_:7,
		    M_upfr:1/integer,
		    _/binary>>, 101) ->
    #node_report_type{upfr = M_upfr};

%% decode user_plane_path_failure_report
decode_v1_element(<<M_group/binary>>, 102) ->
    #user_plane_path_failure_report{group = decode_v1_grouped(M_group)};

%% decode remote_gtp_u_peer
decode_v1_element(<<Data/binary>>, 103) ->
    decode_remote_peer(Data, remote_gtp_u_peer);

%% decode ur_seqn
decode_v1_element(<<M_number:32/integer>>, 104) ->
    #ur_seqn{number = M_number};

%% decode update_duplicating_parameters
decode_v1_element(<<M_group/binary>>, 105) ->
    #update_duplicating_parameters{group = decode_v1_grouped(M_group)};

%% decode activate_predefined_rules
decode_v1_element(<<M_name/binary>>, 106) ->
    #activate_predefined_rules{name = M_name};

%% decode deactivate_predefined_rules
decode_v1_element(<<M_name/binary>>, 107) ->
    #deactivate_predefined_rules{name = M_name};

%% decode far_id
decode_v1_element(<<M_id:32/integer,
		    _/binary>>, 108) ->
    #far_id{id = M_id};

%% decode qer_id
decode_v1_element(<<M_id:32/integer,
		    _/binary>>, 109) ->
    #qer_id{id = M_id};

%% decode oci_flags
decode_v1_element(<<_:7,
		    M_aoci:1/integer,
		    _/binary>>, 110) ->
    #oci_flags{aoci = M_aoci};

%% decode sx_association_release_request
decode_v1_element(<<_:7,
		    M_sarr:1/integer,
		    _/binary>>, 111) ->
    #sx_association_release_request{sarr = M_sarr};

%% decode graceful_release_period
decode_v1_element(<<M_release_timer_unit:3/integer,
		    M_release_timer_value:5/integer,
		    _/binary>>, 112) ->
    #graceful_release_period{release_timer_unit = enum_v1_release_timer_unit(M_release_timer_unit),
			     release_timer_value = M_release_timer_value};

%% decode pdn_type
decode_v1_element(<<_:5,
		    M_type:3/integer,
		    _/binary>>, 113) ->
    #pdn_type{type = enum_v1_type(M_type)};

%% decode failed_rule_id
decode_v1_element(<<Data/binary>>, 114) ->
    decode_failed_rule_id(Data, failed_rule_id);

%% decode time_quota_mechanism
decode_v1_element(<<_:6,
		    M_base_time_interval_type:2/integer,
		    M_interval:32/integer,
		    _/binary>>, 115) ->
    #time_quota_mechanism{base_time_interval_type = enum_v1_base_time_interval_type(M_base_time_interval_type),
			  interval = M_interval};

%% decode user_plane_ip_resource_information
decode_v1_element(<<Data/binary>>, 116) ->
    decode_user_plane_ip_resource_information(Data, user_plane_ip_resource_information);

decode_v1_element(Value, Tag) ->
    {Tag, Value}.

encode_v1_element(#create_pdr{
		       group = M_group}, Acc) ->
    encode_tlv(1, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#pdi{
		       group = M_group}, Acc) ->
    encode_tlv(2, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#create_far{
		       group = M_group}, Acc) ->
    encode_tlv(3, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#forwarding_parameters{
		       group = M_group}, Acc) ->
    encode_tlv(4, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#duplicating_parameters{
		       group = M_group}, Acc) ->
    encode_tlv(5, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#create_urr{
		       group = M_group}, Acc) ->
    encode_tlv(6, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#create_qer{
		       group = M_group}, Acc) ->
    encode_tlv(7, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#created_pdr{
		       group = M_group}, Acc) ->
    encode_tlv(8, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#update_pdr{
		       group = M_group}, Acc) ->
    encode_tlv(9, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#update_far{
		       group = M_group}, Acc) ->
    encode_tlv(10, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#update_forwarding_parameters{
		       group = M_group}, Acc) ->
    encode_tlv(11, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#update_bar_response{
		       group = M_group}, Acc) ->
    encode_tlv(12, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#update_urr{
		       group = M_group}, Acc) ->
    encode_tlv(13, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#update_qer{
		       group = M_group}, Acc) ->
    encode_tlv(14, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#remove_pdr{
		       group = M_group}, Acc) ->
    encode_tlv(15, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#remove_far{
		       group = M_group}, Acc) ->
    encode_tlv(16, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#remove_urr{
		       group = M_group}, Acc) ->
    encode_tlv(17, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#remove_qer{
		       group = M_group}, Acc) ->
    encode_tlv(18, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#cause{
		       cause = M_cause}, Acc) ->
    encode_tlv(19, <<(enum_v1_cause(M_cause)):8/integer>>, Acc);

encode_v1_element(#source_interface{
		       interface = M_interface}, Acc) ->
    encode_tlv(20, <<0:4,
		     (enum_v1_interface(M_interface)):4/integer>>, Acc);

encode_v1_element(#f_teid{} = IE, Acc) ->
    encode_tlv(21, encode_f_teid(IE), Acc);

encode_v1_element(#network_instance{
		       instance = M_instance}, Acc) ->
    encode_tlv(22, <<(encode_dns_label(M_instance))/binary>>, Acc);

encode_v1_element(#sdf_filter{} = IE, Acc) ->
    encode_tlv(23, encode_sdf_filter(IE), Acc);

encode_v1_element(#application_id{
		       indentifier = M_indentifier}, Acc) ->
    encode_tlv(24, <<M_indentifier/binary>>, Acc);

encode_v1_element(#gate_status{
		       ul = M_ul,
		       dl = M_dl}, Acc) ->
    encode_tlv(25, <<0:4,
		     (enum_v1_ul(M_ul)):2/integer,
		     (enum_v1_dl(M_dl)):2/integer>>, Acc);

encode_v1_element(#mbr{
		       ul = M_ul,
		       dl = M_dl}, Acc) ->
    encode_tlv(26, <<M_ul:32,
		     M_dl:32>>, Acc);

encode_v1_element(#gbr{
		       ul = M_ul,
		       dl = M_dl}, Acc) ->
    encode_tlv(27, <<M_ul:32,
		     M_dl:32>>, Acc);

encode_v1_element(#qer_correlation_id{
		       indentifier = M_indentifier}, Acc) ->
    encode_tlv(28, <<M_indentifier:32>>, Acc);

encode_v1_element(#precedence{
		       precedence = M_precedence}, Acc) ->
    encode_tlv(29, <<M_precedence:32>>, Acc);

encode_v1_element(#transport_level_marking{
		       tos = M_tos}, Acc) ->
    encode_tlv(30, <<M_tos:16>>, Acc);

encode_v1_element(#volume_threshold{} = IE, Acc) ->
    encode_tlv(31, encode_volume_threshold(IE), Acc);

encode_v1_element(#time_threshold{
		       threshold = M_threshold}, Acc) ->
    encode_tlv(32, <<M_threshold:32>>, Acc);

encode_v1_element(#monitoring_time{
		       time = M_time}, Acc) ->
    encode_tlv(33, <<M_time:32>>, Acc);

encode_v1_element(#subsequent_volume_threshold{} = IE, Acc) ->
    encode_tlv(34, encode_volume_threshold(IE), Acc);

encode_v1_element(#subsequent_time_threshold{
		       threshold = M_threshold}, Acc) ->
    encode_tlv(35, <<M_threshold:32>>, Acc);

encode_v1_element(#inactivity_detection_time{
		       time = M_time}, Acc) ->
    encode_tlv(36, <<M_time:32>>, Acc);

encode_v1_element(#reporting_triggers{
		       linked_usage_reporting = M_linked_usage_reporting,
		       dropped_dl_traffic_threshold = M_dropped_dl_traffic_threshold,
		       stop_of_traffic = M_stop_of_traffic,
		       start_of_traffic = M_start_of_traffic,
		       quota_holding_time = M_quota_holding_time,
		       time_threshold = M_time_threshold,
		       volume_threshold = M_volume_threshold,
		       periodic_reporting = M_periodic_reporting,
		       envelope_closure = M_envelope_closure,
		       time_quota = M_time_quota,
		       volume_quota = M_volume_quota}, Acc) ->
    encode_tlv(37, <<M_linked_usage_reporting:1,
		     M_dropped_dl_traffic_threshold:1,
		     M_stop_of_traffic:1,
		     M_start_of_traffic:1,
		     M_quota_holding_time:1,
		     M_time_threshold:1,
		     M_volume_threshold:1,
		     M_periodic_reporting:1,
		     0:5,
		     M_envelope_closure:1,
		     M_time_quota:1,
		     M_volume_quota:1>>, Acc);

encode_v1_element(#redirect_information{
		       type = M_type,
		       address = M_address}, Acc) ->
    encode_tlv(38, <<0:4,
		     (enum_v1_type(M_type)):4/integer,
		     (byte_size(M_address)):16/integer, M_address/binary>>, Acc);

encode_v1_element(#report_type{
		       erir = M_erir,
		       usar = M_usar,
		       dldr = M_dldr}, Acc) ->
    encode_tlv(39, <<0:5,
		     M_erir:1,
		     M_usar:1,
		     M_dldr:1>>, Acc);

encode_v1_element(#offending_ie{
		       type = M_type}, Acc) ->
    encode_tlv(40, <<M_type:16>>, Acc);

encode_v1_element(#forwarding_policy{
		       policy_identifier = M_policy_identifier}, Acc) ->
    encode_tlv(41, <<(byte_size(M_policy_identifier)):8/integer, M_policy_identifier/binary>>, Acc);

encode_v1_element(#destination_interface{
		       interface = M_interface}, Acc) ->
    encode_tlv(42, <<0:4,
		     (enum_v1_interface(M_interface)):4/integer>>, Acc);

encode_v1_element(#up_function_features{
		       treu = M_treu,
		       heeu = M_heeu,
		       pfdm = M_pfdm,
		       ftup = M_ftup,
		       trst = M_trst,
		       dlbd = M_dlbd,
		       ddnd = M_ddnd,
		       bucp = M_bucp,
		       empu = M_empu}, Acc) ->
    encode_tlv(43, <<M_treu:1,
		     M_heeu:1,
		     M_pfdm:1,
		     M_ftup:1,
		     M_trst:1,
		     M_dlbd:1,
		     M_ddnd:1,
		     M_bucp:1,
		     0:7,
		     M_empu:1>>, Acc);

encode_v1_element(#apply_action{
		       dupl = M_dupl,
		       nocp = M_nocp,
		       buff = M_buff,
		       forw = M_forw,
		       drop = M_drop}, Acc) ->
    encode_tlv(44, <<0:3,
		     M_dupl:1,
		     M_nocp:1,
		     M_buff:1,
		     M_forw:1,
		     M_drop:1>>, Acc);

encode_v1_element(#downlink_data_service_information{} = IE, Acc) ->
    encode_tlv(45, encode_paging_policy_indication(IE), Acc);

encode_v1_element(#downlink_data_notification_delay{
		       delay = M_delay}, Acc) ->
    encode_tlv(46, <<M_delay:8>>, Acc);

encode_v1_element(#dl_buffering_duration{
		       dl_buffer_unit = M_dl_buffer_unit,
		       dl_buffer_value = M_dl_buffer_value}, Acc) ->
    encode_tlv(47, <<(enum_v1_dl_buffer_unit(M_dl_buffer_unit)):3/integer,
		     M_dl_buffer_value:5>>, Acc);

encode_v1_element(#dl_buffering_suggested_packet_count{
		       count = M_count}, Acc) ->
    encode_tlv(48, <<M_count:16>>, Acc);

encode_v1_element(#sxsmreq_flags{
		       qaurr = M_qaurr,
		       sndem = M_sndem,
		       drobu = M_drobu}, Acc) ->
    encode_tlv(49, <<0:5,
		     M_qaurr:1,
		     M_sndem:1,
		     M_drobu:1>>, Acc);

encode_v1_element(#sxsrrsp_flags{
		       drobu = M_drobu}, Acc) ->
    encode_tlv(50, <<0:7,
		     M_drobu:1>>, Acc);

encode_v1_element(#load_control_information{
		       group = M_group}, Acc) ->
    encode_tlv(51, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#sequence_number{
		       number = M_number}, Acc) ->
    encode_tlv(52, <<M_number:32>>, Acc);

encode_v1_element(#metric{
		       metric = M_metric}, Acc) ->
    encode_tlv(53, <<M_metric:8>>, Acc);

encode_v1_element(#overload_control_information{
		       group = M_group}, Acc) ->
    encode_tlv(54, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#timer{
		       timer_unit = M_timer_unit,
		       timer_value = M_timer_value}, Acc) ->
    encode_tlv(55, <<(enum_v1_timer_unit(M_timer_unit)):3/integer,
		     M_timer_value:5>>, Acc);

encode_v1_element(#pdr_id{
		       id = M_id}, Acc) ->
    encode_tlv(56, <<M_id:16>>, Acc);

encode_v1_element(#f_seid{} = IE, Acc) ->
    encode_tlv(57, encode_f_seid(IE), Acc);

encode_v1_element(#application_id_pfds{
		       group = M_group}, Acc) ->
    encode_tlv(58, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#pfd_context{
		       group = M_group}, Acc) ->
    encode_tlv(59, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#node_id{} = IE, Acc) ->
    encode_tlv(60, encode_node_id(IE), Acc);

encode_v1_element(#pfd_contents{} = IE, Acc) ->
    encode_tlv(61, encode_pfd_contents(IE), Acc);

encode_v1_element(#measurement_method{
		       event = M_event,
		       volum = M_volum,
		       durat = M_durat}, Acc) ->
    encode_tlv(62, <<0:5,
		     M_event:1,
		     M_volum:1,
		     M_durat:1>>, Acc);

encode_v1_element(#usage_report_trigger{
		       immer = M_immer,
		       droth = M_droth,
		       stopt = M_stopt,
		       start = M_start,
		       quhti = M_quhti,
		       timth = M_timth,
		       volth = M_volth,
		       perio = M_perio,
		       envcl = M_envcl,
		       monit = M_monit,
		       termr = M_termr,
		       liusa = M_liusa,
		       timqu = M_timqu,
		       volqu = M_volqu}, Acc) ->
    encode_tlv(63, <<M_immer:1,
		     M_droth:1,
		     M_stopt:1,
		     M_start:1,
		     M_quhti:1,
		     M_timth:1,
		     M_volth:1,
		     M_perio:1,
		     0:2,
		     M_envcl:1,
		     M_monit:1,
		     M_termr:1,
		     M_liusa:1,
		     M_timqu:1,
		     M_volqu:1>>, Acc);

encode_v1_element(#measurement_period{
		       period = M_period}, Acc) ->
    encode_tlv(64, <<M_period:32>>, Acc);

encode_v1_element(#fq_csid{} = IE, Acc) ->
    encode_tlv(65, encode_fq_csid(IE), Acc);

encode_v1_element(#volume_measurement{} = IE, Acc) ->
    encode_tlv(66, encode_volume_threshold(IE), Acc);

encode_v1_element(#duration_measurement{
		       duration = M_duration}, Acc) ->
    encode_tlv(67, <<M_duration:32>>, Acc);

encode_v1_element(#application_detection_information{
		       group = M_group}, Acc) ->
    encode_tlv(68, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#time_of_first_packet{
		       seconds = M_seconds,
		       fraction = M_fraction}, Acc) ->
    encode_tlv(69, <<M_seconds:32,
		     M_fraction:32>>, Acc);

encode_v1_element(#time_of_last_packet{
		       seconds = M_seconds,
		       fraction = M_fraction}, Acc) ->
    encode_tlv(70, <<M_seconds:32,
		     M_fraction:32>>, Acc);

encode_v1_element(#quota_holding_time{
		       seconds = M_seconds,
		       fraction = M_fraction}, Acc) ->
    encode_tlv(71, <<M_seconds:32,
		     M_fraction:32>>, Acc);

encode_v1_element(#dropped_dl_traffic_threshold{} = IE, Acc) ->
    encode_tlv(72, encode_dropped_dl_traffic_threshold(IE), Acc);

encode_v1_element(#volume_quota{} = IE, Acc) ->
    encode_tlv(73, encode_volume_threshold(IE), Acc);

encode_v1_element(#time_quota{
		       quota = M_quota}, Acc) ->
    encode_tlv(74, <<M_quota:32>>, Acc);

encode_v1_element(#start_time{
		       seconds = M_seconds,
		       fraction = M_fraction}, Acc) ->
    encode_tlv(75, <<M_seconds:32,
		     M_fraction:32>>, Acc);

encode_v1_element(#end_time{
		       seconds = M_seconds,
		       fraction = M_fraction}, Acc) ->
    encode_tlv(76, <<M_seconds:32,
		     M_fraction:32>>, Acc);

encode_v1_element(#query_urr{
		       group = M_group}, Acc) ->
    encode_tlv(77, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#usage_report_smr{
		       group = M_group}, Acc) ->
    encode_tlv(78, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#usage_report_sdr{
		       group = M_group}, Acc) ->
    encode_tlv(79, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#usage_report_srr{
		       group = M_group}, Acc) ->
    encode_tlv(80, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#urr_id{
		       id = M_id}, Acc) ->
    encode_tlv(81, <<M_id:32>>, Acc);

encode_v1_element(#linked_urr_id{
		       id = M_id}, Acc) ->
    encode_tlv(82, <<M_id:32>>, Acc);

encode_v1_element(#downlink_data_report{
		       group = M_group}, Acc) ->
    encode_tlv(83, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#outer_header_creation{} = IE, Acc) ->
    encode_tlv(84, encode_outer_header_creation(IE), Acc);

encode_v1_element(#create_bar{
		       group = M_group}, Acc) ->
    encode_tlv(85, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#update_bar_request{
		       group = M_group}, Acc) ->
    encode_tlv(86, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#remove_bar{
		       group = M_group}, Acc) ->
    encode_tlv(87, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#bar_id{
		       id = M_id}, Acc) ->
    encode_tlv(88, <<M_id:8>>, Acc);

encode_v1_element(#cp_function_features{
		       ovrl = M_ovrl,
		       load = M_load}, Acc) ->
    encode_tlv(89, <<0:6,
		     M_ovrl:1,
		     M_load:1>>, Acc);

encode_v1_element(#usage_information{
		       ube = M_ube,
		       uae = M_uae,
		       aft = M_aft,
		       bef = M_bef}, Acc) ->
    encode_tlv(90, <<0:4,
		     M_ube:1,
		     M_uae:1,
		     M_aft:1,
		     M_bef:1>>, Acc);

encode_v1_element(#application_instance_id{
		       id = M_id}, Acc) ->
    encode_tlv(91, <<M_id/binary>>, Acc);

encode_v1_element(#flow_information{
		       direction = M_direction,
		       flow = M_flow}, Acc) ->
    encode_tlv(92, <<0:4,
		     (enum_v1_direction(M_direction)):4/integer,
		     (byte_size(M_flow)):16/integer, M_flow/binary>>, Acc);

encode_v1_element(#ue_ip_address{} = IE, Acc) ->
    encode_tlv(93, encode_ue_ip_address(IE), Acc);

encode_v1_element(#packet_rate{} = IE, Acc) ->
    encode_tlv(94, encode_packet_rate(IE), Acc);

encode_v1_element(#outer_header_removal{
		       header = M_header}, Acc) ->
    encode_tlv(95, <<(enum_v1_header(M_header)):8/integer>>, Acc);

encode_v1_element(#recovery_time_stamp{
		       seconds = M_seconds,
		       fraction = M_fraction}, Acc) ->
    encode_tlv(96, <<M_seconds:32,
		     M_fraction:32>>, Acc);

encode_v1_element(#dl_flow_level_marking{} = IE, Acc) ->
    encode_tlv(97, encode_dl_flow_level_marking(IE), Acc);

encode_v1_element(#header_enrichment{
		       header_type = M_header_type,
		       name = M_name,
		       value = M_value}, Acc) ->
    encode_tlv(98, <<0:4,
		     (enum_v1_header_type(M_header_type)):4/integer,
		     (byte_size(M_name)):16/integer, M_name/binary,
		     (byte_size(M_value)):16/integer, M_value/binary>>, Acc);

encode_v1_element(#error_indication_report{
		       group = M_group}, Acc) ->
    encode_tlv(99, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#measurement_information{
		       inam = M_inam,
		       mbqe = M_mbqe}, Acc) ->
    encode_tlv(100, <<0:6,
		      M_inam:1,
		      M_mbqe:1>>, Acc);

encode_v1_element(#node_report_type{
		       upfr = M_upfr}, Acc) ->
    encode_tlv(101, <<0:7,
		      M_upfr:1>>, Acc);

encode_v1_element(#user_plane_path_failure_report{
		       group = M_group}, Acc) ->
    encode_tlv(102, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#remote_gtp_u_peer{} = IE, Acc) ->
    encode_tlv(103, encode_remote_peer(IE), Acc);

encode_v1_element(#ur_seqn{
		       number = M_number}, Acc) ->
    encode_tlv(104, <<M_number:32>>, Acc);

encode_v1_element(#update_duplicating_parameters{
		       group = M_group}, Acc) ->
    encode_tlv(105, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#activate_predefined_rules{
		       name = M_name}, Acc) ->
    encode_tlv(106, <<M_name/binary>>, Acc);

encode_v1_element(#deactivate_predefined_rules{
		       name = M_name}, Acc) ->
    encode_tlv(107, <<M_name/binary>>, Acc);

encode_v1_element(#far_id{
		       id = M_id}, Acc) ->
    encode_tlv(108, <<M_id:32>>, Acc);

encode_v1_element(#qer_id{
		       id = M_id}, Acc) ->
    encode_tlv(109, <<M_id:32>>, Acc);

encode_v1_element(#oci_flags{
		       aoci = M_aoci}, Acc) ->
    encode_tlv(110, <<0:7,
		      M_aoci:1>>, Acc);

encode_v1_element(#sx_association_release_request{
		       sarr = M_sarr}, Acc) ->
    encode_tlv(111, <<0:7,
		      M_sarr:1>>, Acc);

encode_v1_element(#graceful_release_period{
		       release_timer_unit = M_release_timer_unit,
		       release_timer_value = M_release_timer_value}, Acc) ->
    encode_tlv(112, <<(enum_v1_release_timer_unit(M_release_timer_unit)):3/integer,
		      M_release_timer_value:5>>, Acc);

encode_v1_element(#pdn_type{
		       type = M_type}, Acc) ->
    encode_tlv(113, <<0:5,
		      (enum_v1_type(M_type)):3/integer>>, Acc);

encode_v1_element(#failed_rule_id{} = IE, Acc) ->
    encode_tlv(114, encode_failed_rule_id(IE), Acc);

encode_v1_element(#time_quota_mechanism{
		       base_time_interval_type = M_base_time_interval_type,
		       interval = M_interval}, Acc) ->
    encode_tlv(115, <<0:6,
		      (enum_v1_base_time_interval_type(M_base_time_interval_type)):2/integer,
		      M_interval:32>>, Acc);

encode_v1_element(#user_plane_ip_resource_information{} = IE, Acc) ->
    encode_tlv(116, encode_user_plane_ip_resource_information(IE), Acc);

encode_v1_element({Tag, Value}, Acc) when is_binary(Value) ->
    encode_tlv(Tag, Value, Acc).
