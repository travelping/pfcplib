%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

%% Copyright 2017, Travelping GmbH <info@travelping.com>

-record(pfcp, {
	  version	:: 'undefined' | 'v1',
	  type,
	  seid		:: 0..16#ffffffffffffffff,
	  seq_no	:: 0..16#ffffff,
	  ie		:: [term()] | map()
	 }).

-record(f_teid, {
	  teid       :: 0..16#ffffffff,
	  ipv6       :: inet:ip6_address(),
	  ipv4       :: inet:ip4_address(),
	  choose_id  :: 0..16#ff
	 }).

-record(sdf_filter, {
	  flow_description         :: binary(),
	  tos_traffic_class        :: 0..16#ffff,
	  security_parameter_index :: 0..16#ffffffff,
	  flow_label               :: 0..16#ffffff
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
	  value :: 0..16#3f
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
	  custom	:: binary()
	 }).

-record(fq_csid, {
	  address = {1,1,0}	:: binary() | {MCC :: integer, MNC :: integer, Id :: integer},
	  csid = []		:: [0..16#ffff]
	 }).

-record(volume_measurement, {
	  total		:: 0..16#ffffffffffffffff,
	  uplink	:: 0..16#ffffffffffffffff,
	  downlink	:: 0..16#ffffffffffffffff
	 }).

-record(dropped_dl_traffic_threshold, {
	  value         :: 0..16#ffffffffffffffff
	 }).

-record(volume_quota, {
	  total		:: 0..16#ffffffffffffffff,
	  uplink	:: 0..16#ffffffffffffffff,
	  downlink	:: 0..16#ffffffffffffffff
	 }).

-record(outer_header_creation, {
	  type,
	  teid,
	  address,
	  port
	 }).

-record(ue_ip_address, {
	  type		:: 'undefined' | 'src' | 'dst',
	  ipv4		:: 'undefined' | inet:ip4_address(),
	  ipv6		:: 'undefined' | inet:ip6_address()
	 }).

-record(packet_rate, {
	  ul_time_unit,
	  ul_max_packet_rate,
	  dl_time_unit,
	  dl_max_packet_rate
	 }).

-record(dl_flow_level_marking, {
	  traffic_class,
	  service_class_indicator
	 }).

-record(remote_gtp_u_peer, {
	  ipv4	:: inet:ip4_address(),
	  ipv6	:: inet:ip6_address()
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

-include("pfcp_packet_v1_gen.hrl").
