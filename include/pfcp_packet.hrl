%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

%% Copyright 2017, Travelping GmbH <info@travelping.com>

-record(pfcp, {
	  version	:: 'undefined' | 'v1',
	  type		:: atom(),
	  seid		:: 'undefined' | 0..16#ffffffffffffffff,
	  seq_no	:: 0..16#ffffff,
	  ie		:: [term()] | map()
	 }).

-record(f_teid, {
	  teid       :: 'choose' | 0..16#ffffffff,
	  ipv6       :: 'undefined' | 'choose' | inet:ip6_address(),
	  ipv4       :: 'undefined' | 'choose' | inet:ip4_address(),
	  choose_id  :: 'undefined' | 0..16#ff
	 }).

-record(sdf_filter, {
	  flow_description         :: binary(),
	  tos_traffic_class        :: 0..16#ffff,
	  security_parameter_index :: 0..16#ffffffff,
	  flow_label               :: 0..16#ffffff,
	  filter_id                :: 0..16#ffffffff
	 }).

-record(volume_threshold, {
	  total		:: 0..16#ffffffffffffffff,
	  uplink	:: 0..16#ffffffffffffffff,
	  downlink	:: 0..16#ffffffffffffffff
	 }).

-record(subsequent_volume_threshold, {
	  total		:: 0..16#ffffffffffffffff,
	  uplink	:: 0..16#ffffffffffffffff,
	  downlink	:: 0..16#ffffffffffffffff
	 }).

-record(downlink_data_service_information, {
	  value :: 0..16#3f,
	  qfi   :: 0..16#3f
	 }).

-record(dl_buffering_suggested_packet_count, {
	  count = 0	:: 0..16#ffff
}).

-record(f_seid, {
	  seid	:: 0..16#ffffffffffffffff,
	  ipv4	:: inet:ip4_address(),
	  ipv6	:: inet:ip6_address()
	 }).

-record(node_id, {
	  id	:: {ipv4 | ipv6 | fqdn, binary()}
	 }).

-record(pfd_contents, {
	  flow		:: binary(),
	  url		:: binary(),
	  domain	:: binary(),
	  custom	:: binary(),
	  dnp		:: binary(),
	  aflow		:: binary(),
	  aurl		:: binary(),
	  adnp		:: binary()
	 }).

-record(fq_csid, {
	  address = {1,1,0}	:: binary() | {MCC :: integer, MNC :: integer, Id :: integer},
	  csid = []		:: [0..16#ffff]
	 }).

-record(volume_measurement, {
	  total		:: 0..16#ffffffffffffffff,
	  uplink	:: 0..16#ffffffffffffffff,
	  downlink	:: 0..16#ffffffffffffffff,
	  total_pkts	:: 0..16#ffffffffffffffff,
	  uplink_pkts	:: 0..16#ffffffffffffffff,
	  downlink_pkts	:: 0..16#ffffffffffffffff
	 }).

-record(dropped_dl_traffic_threshold, {
	  value         :: 0..16#ffffffffffffffff,
	  bytes         :: 0..16#ffffffffffffffff
	 }).

-record(volume_quota, {
	  total		:: 0..16#ffffffffffffffff,
	  uplink	:: 0..16#ffffffffffffffff,
	  downlink	:: 0..16#ffffffffffffffff
	 }).

-record(outer_header_creation, {
	  n6 = false	:: boolean(),
	  n19 = false	:: boolean(),
	  type		:: 'GTP-U' | 'UDP' | 'IP' | 'RAW',
	  teid		:: 'undefined' | 0..16#fffffffffffffff,
	  ipv4		:: 'undefined' | inet:ip4_address(),
	  ipv6		:: 'undefined' | inet:ip6_address(),
	  port		:: 'undefined' | 0..16#ffff,
	  c_tag		:: 'undefined' | binary(),
	  s_tag		:: 'undefined' | binary()
	 }).

-record(ue_ip_address, {
	  type			:: 'undefined' | 'src' | 'dst',
	  ipv4			:: 'undefined' | 'choose' | inet:ip4_address(),
	  ipv6			:: 'undefined' | 'choose' | inet:ip6_address(),
	  prefix_delegation	:: 0..16#ff,
	  prefix_length		:: 0..16#ff
	 }).

-record(packet_rate, {
	  ul_time_unit,
	  ul_max_packet_rate,
	  dl_time_unit,
	  dl_max_packet_rate,
	  additional_ul_time_unit,
	  additional_ul_max_packet_rate,
	  additional_dl_time_unit,
	  additional_dl_max_packet_rate
	 }).

-record(dl_flow_level_marking, {
	  traffic_class,
	  service_class_indicator
	 }).

-record(remote_gtp_u_peer, {
	  ipv4	:: 'undefined' | inet:ip4_address(),
	  ipv6	:: 'undefined' | inet:ip6_address(),
	  destination_interface  :: 'undefined' | binary(),
	  network_instance       :: 'undefined' | binary()
	 }).

-record(failed_rule_id, {
	  type	:: 'pdr' | 'far' | 'qer' | 'urr' | 'bar',
	  id	:: integer()
	 }).

-record(user_plane_ip_resource_information, {
	  teid_range,
	  ipv4,
	  ipv6,
	  network_instance
	 }).

-record(subsequent_volume_quota, {
	  total		:: 0..16#ffffffffffffffff,
	  uplink	:: 0..16#ffffffffffffffff,
	  downlink	:: 0..16#ffffffffffffffff
	 }).

-record(mac_address, {
	  source_mac,
	  destination_mac,
	  upper_source_mac,
	  upper_destination_mac
	 }).

-record(c_tag, {
	  pcp		:: 'undefined' | 0..7,
	  dei		:: 'undefined' | 0..1,
	  vid		:: 'undefined' | 0..16#fff
	 }).

-record(s_tag, {
	  pcp		:: 0..16#fff,
	  dei		:: 0..1,
	  vid		:: 0..16#fff
	 }).

-record(user_id, {
	  imsi		:: 'undefined' | binary(),
	  imei		:: 'undefined' | binary(),
	  msisdn	:: 'undefined' | binary(),
	  nai		:: 'undefined' | binary()
	 }).

-record(mac_addresses_detected, {
	  macs = [],
	  c_tag,
	  s_tag
}).

-record(mac_addresses_removed, {
	  macs = [],
	  c_tag,
	  s_tag
}).

-record(alternative_smf_ip_address, {
	  ipv4,
	  ipv6
}).

-record(cp_pfcp_entity_ip_address, {
	  ipv4,
	  ipv6
}).

-record(ip_multicast_address, {
	  ip
}).

-record(source_ip_address, {
	  ip
}).

-record(packet_rate_status, {
	  remaining_uplink_packets_allowed,
	  remaining_downlink_packets_allowed,
	  remaining_additional_uplink_packets_allowed,
	  remaining_additional_downlink_packets_allowed,
	  validity_time
}).

-record(tsn_bridge_id, {
	  mac
}).

-record(mptcp_address_information, {
	  proxy_type,
	  proxy_port,
	  ipv4,
	  ipv6
}).

-record(ue_link_specific_ip_address, {
	  tgpp_ipv4,
	  tgpp_ipv6,
	  non_tgpp_ipv4,
	  non_tgpp_ipv6
}).

-record(pmf_address_information, {
	  ipv4,
	  ipv6,
	  tgpp_port,
	  non_tgpp_port,
	  tgpp_mac,
	  non_tgpp_mac
}).

-record(packet_delay_thresholds, {
	  downlink_packet_delay_threshold,
	  uplink_packet_delay_threshold,
	  round_trip_packet_delay_threshold
}).

-record(qos_monitoring_measurement, {
	  packet_delay_measurement_failure = false,
	  downlink_packet_delay,
	  uplink_packet_delay,
	  round_trip_packet_delay
}).

-record(number_of_ue_ip_addresses, {
	  ipv4	:: 'undefined' | 0..16#ffffffff,
	  ipv6	:: 'undefined' | 0..16#ffffffff
	 }).

-record(ppp_protocol, {
	  control = 0,
	  data = 0,
	  protocol = undefined
	 }).

-record(bbf_nat_external_port_range, {
	  ranges = []
	 }).

-record(bbf_nat_port_forward, {
	  forwards = []
	 }).

-record(l2tp_tunnel_endpoint, {
	  tunnel_id = 0,
	  endpoint
	 }).

-record(tp_packet_measurement, {
	  total		:: 0..16#ffffffffffffffff,
	  uplink	:: 0..16#ffffffffffffffff,
	  downlink	:: 0..16#ffffffffffffffff
	 }).

%% The following code is auto-generated. DO NOT EDIT

%% -include("pfcp_packet_v1_gen.hrl").

-record(create_pdr, {
	  group
}).

-record(pdi, {
	  group
}).

-record(create_far, {
	  group
}).

-record(forwarding_parameters, {
	  group
}).

-record(duplicating_parameters, {
	  group
}).

-record(create_urr, {
	  group
}).

-record(create_qer, {
	  group
}).

-record(created_pdr, {
	  group
}).

-record(update_pdr, {
	  group
}).

-record(update_far, {
	  group
}).

-record(update_forwarding_parameters, {
	  group
}).

-record(update_bar_response, {
	  group
}).

-record(update_urr, {
	  group
}).

-record(update_qer, {
	  group
}).

-record(remove_pdr, {
	  group
}).

-record(remove_far, {
	  group
}).

-record(remove_urr, {
	  group
}).

-record(remove_qer, {
	  group
}).

-record(pfcp_cause, {
	  cause = 'Reserved'
}).

-record(source_interface, {
	  interface = 'Access'
}).

-record(network_instance, {
	  instance = <<>>
}).

-record(application_id, {
	  id = <<>>
}).

-record(gate_status, {
	  ul = 'OPEN',
	  dl = 'OPEN'
}).

-record(mbr, {
	  ul = 0,
	  dl = 0
}).

-record(gbr, {
	  ul = 0,
	  dl = 0
}).

-record(qer_correlation_id, {
	  id = 0
}).

-record(precedence, {
	  precedence = 0
}).

-record(transport_level_marking, {
	  tos = 0
}).

-record(time_threshold, {
	  threshold = 0
}).

-record(monitoring_time, {
	  time = 0
}).

-record(subsequent_time_threshold, {
	  threshold = 0
}).

-record(inactivity_detection_time, {
	  time = 0
}).

-record(reporting_triggers, {
	  linked_usage_reporting = 0,
	  dropped_dl_traffic_threshold = 0,
	  stop_of_traffic = 0,
	  start_of_traffic = 0,
	  quota_holding_time = 0,
	  time_threshold = 0,
	  volume_threshold = 0,
	  periodic_reporting = 0,
	  quota_validity_time = 0,
	  ip_multicast_join_leave = 0,
	  event_quota = 0,
	  event_threshold = 0,
	  mac_addresses_reporting = 0,
	  envelope_closure = 0,
	  time_quota = 0,
	  volume_quota = 0,
	  report_the_end_marker_reception
}).

-record(redirect_information, {
	  type = 'IPv4',
	  address = <<>>,
	  other_address = <<>>
}).

-record(report_type, {
	  uisr = 0,
	  sesr = 0,
	  pmir = 0,
	  upir = 0,
	  erir = 0,
	  usar = 0,
	  dldr = 0
}).

-record(offending_ie, {
	  type = 0
}).

-record(forwarding_policy, {
	  policy_identifier = <<>>
}).

-record(destination_interface, {
	  interface = 'Access'
}).

-record(up_function_features, {
	  treu = 0,
	  heeu = 0,
	  pfdm = 0,
	  ftup = 0,
	  trst = 0,
	  dlbd = 0,
	  ddnd = 0,
	  bucp = 0,
	  epfar,
	  pfde,
	  frrt,
	  trace,
	  quoac,
	  udbc,
	  pdiu,
	  empu,
	  gcom,
	  bundl,
	  mte,
	  mnop,
	  sset,
	  ueip,
	  adpdp,
	  dpdra,
	  mptcp,
	  tscu,
	  ip6pl,
	  iptv,
	  norp,
	  vtime,
	  rttl,
	  mpas,
	  rds,
	  ddds,
	  ethar,
	  ciot,
	  mt_edt,
	  gpqm,
	  qfqm,
	  atsss_ll,
	  rttwp
}).

-record(apply_action, {
	  dfrt = 0,
	  ipmd = 0,
	  ipma = 0,
	  dupl = 0,
	  nocp = 0,
	  buff = 0,
	  forw = 0,
	  drop = 0,
	  ddpn,
	  bdpn,
	  edrt
}).

-record(downlink_data_notification_delay, {
	  delay = 0
}).

-record(dl_buffering_duration, {
	  dl_buffer_unit = '2 seconds',
	  dl_buffer_value = 0
}).

-record(sxsmreq_flags, {
	  qaurr = 0,
	  sndem = 0,
	  drobu = 0
}).

-record(sxsrrsp_flags, {
	  drobu = 0
}).

-record(load_control_information, {
	  group
}).

-record(sequence_number, {
	  number = 0
}).

-record(metric, {
	  metric = 0
}).

-record(overload_control_information, {
	  group
}).

-record(timer, {
	  timer_unit = '2 seconds',
	  timer_value = 0
}).

-record(pdr_id, {
	  id = 0
}).

-record(application_id_pfds, {
	  group
}).

-record(pfd_context, {
	  group
}).

-record(measurement_method, {
	  event = 0,
	  volum = 0,
	  durat = 0
}).

-record(usage_report_trigger, {
	  immer = 0,
	  droth = 0,
	  stopt = 0,
	  start = 0,
	  quhti = 0,
	  timth = 0,
	  volth = 0,
	  perio = 0,
	  eveth = 0,
	  macar = 0,
	  envcl = 0,
	  monit = 0,
	  termr = 0,
	  liusa = 0,
	  timqu = 0,
	  volqu = 0,
	  emrre,
	  quvti,
	  ipmjl,
	  tebur,
	  evequ
}).

-record(measurement_period, {
	  period = 0
}).

-record(duration_measurement, {
	  duration = 0
}).

-record(application_detection_information, {
	  group
}).

-record(time_of_first_packet, {
	  time = 0
}).

-record(time_of_last_packet, {
	  time = 0
}).

-record(quota_holding_time, {
	  time = 0
}).

-record(time_quota, {
	  quota = 0
}).

-record(start_time, {
	  time = 0
}).

-record(end_time, {
	  time = 0
}).

-record(query_urr, {
	  group
}).

-record(usage_report_smr, {
	  group
}).

-record(usage_report_sdr, {
	  group
}).

-record(usage_report_srr, {
	  group
}).

-record(urr_id, {
	  id = 0
}).

-record(linked_urr_id, {
	  id = 0
}).

-record(downlink_data_report, {
	  group
}).

-record(create_bar, {
	  group
}).

-record(update_bar_request, {
	  group
}).

-record(remove_bar, {
	  group
}).

-record(bar_id, {
	  id = 0
}).

-record(cp_function_features, {
	  uiaur = 0,
	  ardr = 0,
	  mpas = 0,
	  bundl = 0,
	  sset = 0,
	  epfar = 0,
	  ovrl = 0,
	  load = 0
}).

-record(usage_information, {
	  ube = 0,
	  uae = 0,
	  aft = 0,
	  bef = 0
}).

-record(application_instance_id, {
	  id = <<>>
}).

-record(flow_information, {
	  direction = 'Unspecified',
	  flow = <<>>
}).

-record(outer_header_removal, {
	  header = 'GTP-U/UDP/IPv4'
}).

-record(recovery_time_stamp, {
	  time = 0
}).

-record(header_enrichment, {
	  header_type = 'HTTP',
	  name = <<>>,
	  value = <<>>
}).

-record(error_indication_report, {
	  group
}).

-record(measurement_information, {
	  mnop = 0,
	  istm = 0,
	  radi = 0,
	  inam = 0,
	  mbqe = 0
}).

-record(node_report_type, {
	  gpqr = 0,
	  ckdr = 0,
	  uprr = 0,
	  upfr = 0
}).

-record(user_plane_path_failure_report, {
	  group
}).

-record(ur_seqn, {
	  number = 0
}).

-record(update_duplicating_parameters, {
	  group
}).

-record(activate_predefined_rules, {
	  name = <<>>
}).

-record(deactivate_predefined_rules, {
	  name = <<>>
}).

-record(far_id, {
	  id = 0
}).

-record(qer_id, {
	  id = 0
}).

-record(oci_flags, {
	  aoci = 0
}).

-record(sx_association_release_request, {
	  urss = 0,
	  sarr = 0
}).

-record(graceful_release_period, {
	  release_timer_unit = '2 seconds',
	  release_timer_value = 0
}).

-record(pdn_type, {
	  pdn_type = 'IPv4'
}).

-record(time_quota_mechanism, {
	  base_time_interval_type = 'CTP',
	  interval = 0
}).

-record(user_plane_inactivity_timer, {
	  timer = 0
}).

-record(aggregated_urrs, {
	  group
}).

-record(multiplier, {
	  digits = 0,
	  exponent = 0
}).

-record(aggregated_urr_id, {
	  id = 0
}).

-record(subsequent_time_quota, {
	  quota = 0
}).

-record(rqi, {
	  rqi = 0
}).

-record(qfi, {
	  qfi = 0
}).

-record(query_urr_reference, {
	  reference = 0
}).

-record(additional_usage_reports_information, {
	  auri = 0,
	  reports = 0
}).

-record(create_traffic_endpoint, {
	  group
}).

-record(created_traffic_endpoint, {
	  group
}).

-record(update_traffic_endpoint, {
	  group
}).

-record(remove_traffic_endpoint, {
	  group
}).

-record(traffic_endpoint_id, {
	  id = 0
}).

-record(ethernet_packet_filter, {
	  group
}).

-record(ethertype, {
	  type = 0
}).

-record(proxying, {
	  ins = 0,
	  arp = 0
}).

-record(ethernet_filter_id, {
	  id = 0
}).

-record(ethernet_filter_properties, {
	  bide = 0
}).

-record(suggested_buffering_packets_count, {
	  count = 0
}).

-record(ethernet_pdu_session_information, {
	  ethi = 0
}).

-record(ethernet_traffic_information, {
	  group
}).

-record(ethernet_inactivity_timer, {
	  timer = 0
}).

-record(additional_monitoring_time, {
	  group
}).

-record(event_quota, {
	  quota = 0
}).

-record(event_threshold, {
	  threshold = 0
}).

-record(subsequent_event_quota, {
	  quota = 0
}).

-record(subsequent_event_threshold, {
	  threshold = 0
}).

-record(trace_information, {
	  mcc = <<"001">>,
	  mnc = <<"001">>,
	  trace_id = <<>>,
	  events = <<>>,
	  session_trace_depth = 0,
	  interfaces = <<>>,
	  ip_address = <<>>
}).

-record(framed_route, {
	  value = <<>>
}).

-record(framed_routing, {
	  value = 0
}).

-record(framed_ipv6_route, {
	  value = <<>>
}).

-record(event_time_stamp, {
	  time = 0
}).

-record(averaging_window, {
	  window = 0
}).

-record(paging_policy_indicator, {
	  ppi = 0
}).

-record(apn_dnn, {
	  apn
}).

-record(tgpp_interface_type, {
	  type = 'S1-U'
}).

-record(pfcpsrreq_flags, {
	  psdbu = 0
}).

-record(pfcpaureq_flags, {
	  parps = 0
}).

-record(activation_time, {
	  time = 0
}).

-record(deactivation_time, {
	  time = 0
}).

-record(create_mar, {
	  group
}).

-record(tgpp_access_forwarding_action_information, {
	  group
}).

-record(non_tgpp_access_forwarding_action_information, {
	  group
}).

-record(remove_mar, {
	  group
}).

-record(update_mar, {
	  group
}).

-record(mar_id, {
	  id = 0
}).

-record(steering_functionality, {
	  functionality = 'ATSSS-LL'
}).

-record(steering_mode, {
	  mode = 'Active-Standby'
}).

-record(weight, {
	  value = 0
}).

-record(priority, {
	  priority = 0
}).

-record(update_tgpp_access_forwarding_action_information, {
	  group
}).

-record(update_non_tgpp_access_forwarding_action_information, {
	  group
}).

-record(ue_ip_address_pool_identity, {
	  identity = <<>>
}).

-record(packet_replication_and_detection_carry_on_information, {
	  dcaroni = 0,
	  prin6i = 0,
	  prin19i = 0,
	  priueai = 0
}).

-record(smf_set_id, {
	  fqdn
}).

-record(quota_validity_time, {
	  time = 0
}).

-record(number_of_reports, {
	  reports = 0
}).

-record(pfcp_session_retention_information, {
	  group
}).

-record(pfcpasrsp_flags, {
	  psrei = 0
}).

-record(pfcpsereq_flags, {
	  resti = 0
}).

-record(user_plane_path_recovery_report, {
	  group
}).

-record(ip_multicast_addressing_info, {
	  group
}).

-record(join_ip_multicast_information, {
	  group
}).

-record(leave_ip_multicast_information, {
	  group
}).

-record(create_bridge_info_for_tsc, {
	  bii = 0
}).

-record(created_bridge_info_for_tsc, {
	  group
}).

-record(ds_tt_port_number, {
	  value = 0
}).

-record(nw_tt_port_number, {
	  value = 0
}).

-record(port_management_information_for_tsc, {
	  group
}).

-record(port_management_information_for_tsc_smr, {
	  group
}).

-record(port_management_information_for_tsc_sdr, {
	  group
}).

-record(port_management_information_container, {
	  value = <<>>
}).

-record(clock_drift_control_information, {
	  group
}).

-record(requested_clock_drift_information, {
	  rrcr = 0,
	  rrto = 0
}).

-record(clock_drift_report, {
	  group
}).

-record(tsn_time_domain_number, {
	  number = 0
}).

-record(time_offset_threshold, {
	  threshold = 0
}).

-record(cumulative_rateratio_threshold, {
	  threshold = 0
}).

-record(time_offset_measurement, {
	  measurement = 0
}).

-record(cumulative_rateratio_measurement, {
	  measurement = 0
}).

-record(remove_srr, {
	  group
}).

-record(create_srr, {
	  group
}).

-record(update_srr, {
	  group
}).

-record(session_report, {
	  group
}).

-record(srr_id, {
	  id = 0
}).

-record(access_availability_control_information, {
	  group
}).

-record(requested_access_availability_information, {
	  rrca = 0
}).

-record(access_availability_report, {
	  group
}).

-record(access_availability_information, {
	  status = unavailable,
	  type = 'TGPP'
}).

-record(provide_atsss_control_information, {
	  group
}).

-record(atsss_control_parameters, {
	  group
}).

-record(mptcp_control_information, {
	  tci = 0
}).

-record(atsss_ll_control_information, {
	  lli = 0
}).

-record(pmf_control_information, {
	  pmfi = 0
}).

-record(mptcp_parameters, {
	  group
}).

-record(atsss_ll_parameters, {
	  group
}).

-record(pmf_parameters, {
	  group
}).

-record(atsss_ll_information, {
	  lli = 0
}).

-record(data_network_access_identifier, {
	  value = <<>>
}).

-record(ue_ip_address_pool_information, {
	  group
}).

-record(average_packet_delay, {
	  delay = 0
}).

-record(minimum_packet_delay, {
	  delay = 0
}).

-record(maximum_packet_delay, {
	  delay = 0
}).

-record(qos_report_trigger, {
	  ire = 0,
	  thr = 0,
	  per = 0
}).

-record(gtp_u_path_qos_control_information, {
	  group
}).

-record(gtp_u_path_qos_report, {
	  group
}).

-record(path_report_qos_information, {
	  group
}).

-record(gtp_u_path_interface_type, {
	  n3 = 0,
	  n9 = 0
}).

-record(qos_monitoring_per_qos_flow_control_information, {
	  group
}).

-record(requested_qos_monitoring, {
	  rp = 0,
	  ul = 0,
	  dl = 0
}).

-record(reporting_frequency, {
	  sesrl = 0,
	  perio = 0,
	  evett = 0
}).

-record(minimum_wait_time, {
	  time = 0
}).

-record(qos_monitoring_report, {
	  group
}).

-record(mt_edt_control_information, {
	  rdsi = 0
}).

-record(dl_data_packets_size, {
	  size = 0
}).

-record(qer_control_indications, {
	  nord = 0,
	  moed = 0,
	  rcsrt = 0
}).

-record(packet_rate_status_report, {
	  group
}).

-record(nf_instance_id, {
	  value = <<>>
}).

-record(ethernet_context_information, {
	  group
}).

-record(redundant_transmission_parameters, {
	  group
}).

-record(updated_pdr, {
	  group
}).

-record(s_nssai, {
	  sst = 0,
	  sd = 0
}).

-record(ip_version, {
	  v6 = 0,
	  v4 = 0
}).

-record(pfcpasreq_flags, {
	  uupsi = 0
}).

-record(data_status, {
	  buff = 0,
	  drop = 0
}).

-record(provide_rds_configuration_information, {
	  group
}).

-record(rds_configuration_information, {
	  rds = 0
}).

-record(query_packet_rate_status_ie_smreq, {
	  group
}).

-record(packet_rate_status_report_ie_smresp, {
	  group
}).

-record(mptcp_applicable_indication, {
	  mai = 0
}).

-record(bridge_management_information_container, {
	  value = <<>>
}).

-record(ue_ip_address_usage_information, {
	  group
}).

-record(validity_timer, {
	  validity_timer = 0
}).

-record(redundant_transmission_forwarding, {
	  group
}).

-record(transport_delay_reporting, {
	  group
}).

-record(bbf_up_function_features, {
	  nat_up = 0,
	  nat_cp = 0,
	  lcp_keepalive_offload = 0,
	  lns = 0,
	  lac = 0,
	  ipoe = 0,
	  pppoe = 0
}).

-record(logical_port, {
	  port = <<>>
}).

-record(bbf_outer_header_creation, {
	  cpr_nsh = 0,
	  traffic_endpoint = 0,
	  l2tp = 0,
	  ppp = 0,
	  tunnel_id = 0,
	  session_id = 0
}).

-record(bbf_outer_header_removal, {
	  header = 'Ethernet'
}).

-record(pppoe_session_id, {
	  id = 0
}).

-record(verification_timers, {
	  interval = 0,
	  count = 0
}).

-record(ppp_lcp_magic_number, {
	  tx = 0,
	  rx = 0
}).

-record(mtu, {
	  mtu = 0
}).

-record(l2tp_session_id, {
	  id = 0
}).

-record(l2tp_type, {
	  type = 0
}).

-record(ppp_lcp_connectivity, {
	  group
}).

-record(l2tp_tunnel, {
	  group
}).

-record(bbf_nat_outside_address, {
	  ipv4 = <<0,0,0,0>>
}).

-record(bbf_apply_action, {
	  nat = 0
}).

-record(bbf_nat_port_block, {
	  block = <<>>
}).

-record(bbf_dynamic_port_block_starting_port, {
	  start = 0
}).

-record(tp_build_identifier, {
	  id = <<>>
}).

-record(tp_now, {
	  now = 0.0
}).

-record(tp_start_time, {
	  start = 0.0
}).

-record(tp_stop_time, {
	  stop = 0.0
}).
