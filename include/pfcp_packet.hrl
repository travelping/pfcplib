%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

%% Copyright 2017, Travelping GmbH <info@travelping.com>

-record(pfcp, {
	  version	:: undefined | 'v1',
	  type		:: atom(),
	  seid		:: undefined | 0..16#ffffffffffffffff,
	  seq_no	:: 0..16#ffffff,
	  ie		:: [term()] | map() | binary()
	 }).

-record(f_teid, {
	  teid       :: 'choose' | 0..16#ffffffff,
	  ipv6       :: undefined | 'choose' | inet:ip6_address(),
	  ipv4       :: undefined | 'choose' | inet:ip4_address(),
	  choose_id  :: undefined | 0..16#ff
	 }).

-record(sdf_filter, {
	  flow_description         :: undefined | binary(),
	  tos_traffic_class        :: undefined | 0..16#ffff,
	  security_parameter_index :: undefined | 0..16#ffffffff,
	  flow_label               :: undefined | 0..16#ffffff,
	  filter_id                :: undefined | 0..16#ffffffff
	 }).

-record(volume_threshold, {
	  total		:: undefined | 0..16#ffffffffffffffff,
	  uplink	:: undefined | 0..16#ffffffffffffffff,
	  downlink	:: undefined | 0..16#ffffffffffffffff
	 }).

-record(subsequent_volume_threshold, {
	  total		:: undefined | 0..16#ffffffffffffffff,
	  uplink	:: undefined | 0..16#ffffffffffffffff,
	  downlink	:: undefined | 0..16#ffffffffffffffff
	 }).

-record(downlink_data_service_information, {
	  value :: undefined | 0..16#3f,
	  qfi   :: undefined | 0..16#3f
	 }).

-record(dl_buffering_suggested_packet_count, {
	  count = 0	:: 0..16#ffff
}).

-record(f_seid, {
	  seid	:: 0..16#ffffffffffffffff,
	  ipv4	:: undefined | inet:ip4_address(),
	  ipv6	:: undefined | inet:ip6_address()
	 }).

-record(node_id, {
	  id	:: {ipv4 | ipv6 | fqdn, binary()} | binary() |[ bitstring()]
	 }).

-record(pfd_contents, {
	  flow		:: undefined | binary(),
	  url		:: undefined | binary(),
	  domain	:: undefined | binary(),
	  custom	:: undefined | binary(),
	  dnp		:: undefined | binary(),
	  aflow		:: undefined | binary(),
	  aurl		:: undefined | binary(),
	  adnp		:: undefined | binary()
	 }).

-record(fq_csid, {
	  address = {1,1,0}	:: binary() | {MCC :: integer, MNC :: integer, Id :: integer} |  {MCC :: char(), MNC :: char(), Id :: char()},
	  csid = []		:: [0..16#ffff]
	 }).

-record(volume_measurement, {
	  total		:: undefined | 0..16#ffffffffffffffff,
	  uplink	:: undefined | 0..16#ffffffffffffffff,
	  downlink	:: undefined | 0..16#ffffffffffffffff,
	  total_pkts	:: undefined | 0..16#ffffffffffffffff,
	  uplink_pkts	:: undefined | 0..16#ffffffffffffffff,
	  downlink_pkts	:: undefined | 0..16#ffffffffffffffff
	 }).

-record(dropped_dl_traffic_threshold, {
	  value         :: undefined | 0..16#ffffffffffffffff,
	  bytes         :: undefined | 0..16#ffffffffffffffff
	 }).

-record(volume_quota, {
	  total		:: undefined | 0..16#ffffffffffffffff,
	  uplink	:: undefined | 0..16#ffffffffffffffff,
	  downlink	:: undefined | 0..16#ffffffffffffffff
	 }).

-record(outer_header_creation, {
	  n6 = false	:: boolean(),
	  n19 = false	:: boolean(),
	  type		:: 'GTP-U' | 'UDP' | 'IP' | 'RAW' | undefined,
	  teid		:: undefined | 0..16#fffffffffffffff,
	  ipv4		:: undefined | inet:ip4_address() | binary(),
	  ipv6		:: undefined | inet:ip6_address() | binary(),
	  port		:: undefined | 0..16#ffff,
	  c_tag		:: undefined | binary(),
	  s_tag		:: undefined | binary()
	 }).

-record(ue_ip_address, {
	  type			:: undefined | 'src' | 'dst',
	  ipv4			:: undefined | 'choose' | inet:ip4_address(),
	  ipv6			:: undefined | 'choose' | inet:ip6_address(),
	  prefix_delegation	:: undefined | 0..16#ff,
	  prefix_length		:: undefined | 0..16#ff
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
	  ipv4	:: undefined | inet:ip4_address(),
	  ipv6	:: undefined | inet:ip6_address(),
	  destination_interface  :: undefined | binary(),
	  network_instance       :: undefined | binary()
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
	  total		:: undefined | 0..16#ffffffffffffffff,
	  uplink	:: undefined | 0..16#ffffffffffffffff,
	  downlink	:: undefined | 0..16#ffffffffffffffff
	 }).

-record(mac_address, {
	  source_mac,
	  destination_mac,
	  upper_source_mac,
	  upper_destination_mac
	 }).

-record(c_tag, {
	  pcp		:: undefined | 0..7,
	  dei		:: undefined | 0..1,
	  vid		:: undefined | 0..16#fff
	 }).

-record(s_tag, {
	  pcp		:: undefined | 0..7,
	  dei		:: undefined | 0..1,
	  vid		:: undefined | 0..16#fff
	 }).

-record(user_id, {
	  imsi		:: undefined | binary(),
	  imei		:: undefined | binary(),
	  msisdn	:: undefined | binary(),
	  nai		:: undefined | binary()
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
	  ipv4	:: undefined | 0..16#ffffffff,
	  ipv6	:: undefined | 0..16#ffffffff
	 }).

-record(ppp_protocol, {
	  flags = #{},
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

-record(source_interface, {
	  interface = 'Access'
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

-record(redirect_information, {
	  type = 'IPv4',
	  address = <<>>,
	  other_address = <<>>
}).

-record(forwarding_policy, {
	  policy_identifier = <<>>
}).

-record(destination_interface, {
	  interface = 'Access'
}).

-record(downlink_data_notification_delay, {
	  delay = 0
}).

-record(dl_buffering_duration, {
	  dl_buffer_unit = '2 seconds',
	  dl_buffer_value = 0
}).

-record(timer, {
	  timer_unit = '2 seconds',
	  timer_value = 0
}).

-record(pdr_id, {
	  id = 0
}).

-record(measurement_period, {
	  period = 0
}).

-record(duration_measurement, {
	  duration = 0
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

-record(urr_id, {
	  id = 0
}).

-record(linked_urr_id, {
	  id = 0
}).

-record(bar_id, {
	  id = 0
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

-record(far_id, {
	  id = 0
}).

-record(qer_id, {
	  id = 0
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

-record(multiplier, {
	  digits = 0,
	  exponent = 0
}).

-record(subsequent_time_quota, {
	  quota = 0
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

-record(traffic_endpoint_id, {
	  id = 0
}).

-record(ethertype, {
	  type = 0
}).

-record(ethernet_filter_id, {
	  id = 0
}).

-record(suggested_buffering_packets_count, {
	  count = 0
}).

-record(ethernet_inactivity_timer, {
	  timer = 0
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

-record(event_time_stamp, {
	  time = 0
}).

-record(averaging_window, {
	  window = 0
}).

-record(paging_policy_indicator, {
	  ppi = 0
}).

-record(tgpp_interface_type, {
	  type = 'S1-U'
}).

-record(activation_time, {
	  time = 0
}).

-record(deactivation_time, {
	  time = 0
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

-record(priority, {
	  priority = 0
}).

-record(ue_ip_address_pool_identity, {
	  identity = <<>>
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

-record(srr_id, {
	  id = 0
}).

-record(access_availability_information, {
	  status = unavailable,
	  type = 'TGPP'
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

-record(minimum_wait_time, {
	  time = 0
}).

-record(dl_data_packets_size, {
	  size = 0
}).

-record(s_nssai, {
	  sst = 0,
	  sd = 0
}).

-record(validity_timer, {
	  validity_timer = 0
}).

-record(bbf_outer_header_creation, {
	  flags = #{},
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

-record(bbf_dynamic_port_block_starting_port, {
	  start = 0
}).

-record(tp_now, {
	  seconds = 0,
	  fraction = 0
}).

-record(tp_start_time, {
	  seconds = 0,
	  fraction = 0
}).

-record(tp_stop_time, {
	  seconds = 0,
	  fraction = 0
}).

-record(tp_line_number, {
	  line = 0
}).
