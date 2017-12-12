%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

%% Copyright 2017, Travelping GmbH <info@travelping.com>

-module(pfcp_packet).

-export([encode/1, encode_ies/1,
	 decode/1, decode/2, decode_ies/1, decode_ies/2,
	 msg_description_v1/1]).

-compile([{parse_transform, cut}, bin_opt_info]).
-compile({inline,[decode_v1_grouped/1]}).

-ifdef (TEST).
-compile([export_all, nowarn_export_all]).
-endif.

-include("pfcp_packet.hrl").

%%====================================================================
%% API
%%====================================================================

decode(Data) ->
    decode(Data, #{ies => map}).

decode(Data, Opts) ->
    Msg = decode_header(Data),
    decode_ies(Msg, Opts).

decode_ies(Msg) ->
    decode_ies(Msg, #{ies => map}).

decode_ies(#pfcp{ie = IEs} = Msg, #{ies := map})
  when is_map(IEs) ->
    Msg;
decode_ies(#pfcp{ie = IEs} = Msg, #{ies := Format} = Opts)
  when not is_binary(IEs) orelse (Format /= map andalso Format /= binary) ->
    error(badargs, [Msg, Opts]);
decode_ies(#pfcp{version = v1, type = Type, ie = IEs} = Msg, #{ies := map}) ->
    Msg#pfcp{ie = decode_v1(IEs, #{})};
decode_ies(Msg, _) ->
    Msg.

encode(#pfcp{version = v1, type = Type, seid = SEID, seq_no = SeqNo, ie = IEs}) ->
    encode_v1_msg(message_type_v1(Type), SEID, SeqNo, encode_v1(IEs, <<>>)).

encode_ies(#pfcp{version = v1, ie = IEs} = Msg) ->
    Msg#pfcp{ie = encode_v1(IEs, <<>>)}.

%%====================================================================
%% Helpers
%%====================================================================

decode_header(<<1:3, _Spare:3, MP:1, S:1, Type:8, Length:16,
		Data:Length/bytes, _Next/binary>>) ->
    decode_v1_msg(Data, MP, S, Type).

decode_v1_msg(<<SEID:64/integer, SeqNo:24/integer, _Spare1:8, IEs/binary>>, _MP, 1, Type) ->
    #pfcp{version = v1, type = message_type_v1(Type), seid = SEID, seq_no = SeqNo, ie = IEs};
decode_v1_msg(<<SeqNo:24/integer, _Spare1:8, IEs/binary>>, _MP, 0, Type) ->
    #pfcp{version = v1, type = message_type_v1(Type), seid = undefined, seq_no = SeqNo, ie = IEs}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

%% pad_length(Width, Length) ->
%%     (Width - Length rem Width) rem Width.

%% %%
%% %% pad binary to specific length
%% %%   -> http://www.erlang.org/pipermail/erlang-questions/2008-December/040709.html
%% %%
%% pad_to(Width, Binary) ->
%%     case pad_length(Width, size(Binary)) of
%% 	0 -> Binary;
%% 	N -> <<Binary/binary, 0:(N*8)>>
%%     end.

put_ie(IE, IEs) ->
    Key = element(1, IE),
    UpdateFun = fun(V) when is_list(V) -> [IE | V];
		   (undefined)         -> IE;
		   (V)                 -> [IE, V]
		end,
    maps:update_with(Key, UpdateFun, IE, IEs).

bool2int(false) -> 0;
bool2int(true)  -> 1.

%% ip2bin({A,B,C,D}) ->
%%     <<A,B,C,D>>;
%% ip2bin({A,B,C,D,E,F,G,H}) ->
%%     <<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>;
%% ip2bin(undefined) ->
%%     undefined.

%% bin2ip(<<A,B,C,D>>) ->
%%     {A,B,C,D};
%% bin2ip(<<A:16,B:16,C:16,D:16,E:16,F:16,G:16,H:16>>) ->
%%     {A,B,C,D,E,F,G,H}.

%% encode_flag(Flag, Flags) ->
%%     bool2int(proplists:get_bool(Flag, Flags)).

is_set(Value) -> bool2int(Value =/= undefined).

maybe_bin(<<Bin/binary>>, 0, _, _, IE) ->
    {IE, Bin};
maybe_bin(<<Bin/binary>>, 1, Len, Pos, IE) ->
    <<V:Len/bytes, Rest/binary>> = Bin,
    {setelement(Pos, IE, V), Rest}.

maybe_bin(Bin, Len, IE) when is_binary(Bin) ->
    <<IE/binary, Bin:Len/bytes>>;
maybe_bin(_, _, IE) ->
    IE.

maybe_len_bin(<<Bin/binary>>, 0, _, _, IE) ->
    {IE, Bin};
maybe_len_bin(<<Bin/binary>>, 1, Size, Pos, IE) ->
    <<Len:Size/integer, V:Len/bytes, Rest/binary>> = Bin,
    {setelement(Pos, IE, V), Rest}.

maybe_len_bin(Bin, Size, IE) when is_binary(Bin) ->
    <<IE/binary, (byte_size(Bin)):Size/integer, Bin/bytes>>;
maybe_len_bin(_, _, IE) ->
    IE.

maybe_unsigned_integer(<<Value/binary>>, 0, _, _, IE) ->
    {IE, Value};
maybe_unsigned_integer(<<Value/binary>>, 1, Len, Pos, IE) ->
    <<V:Len/integer, Rest/binary>> = Value,
    {setelement(Pos, IE, V), Rest}.

maybe_unsigned_integer(Value, Len, IE) when is_integer(Value) ->
    <<IE/binary, Value:Len/integer>>;
maybe_unsigned_integer(_, _, IE) ->
    IE.

decode_v1(<<>>, IEs) ->
    IEs;
decode_v1(<<0:1, Type:15/integer, Length:16/integer, Data:Length/bytes, Next/binary>>, IEs)
  when Type < 32768 ->
    IE = decode_v1_element(Data, Type),
    decode_v1(Next, put_ie(IE, IEs));
decode_v1(<<1:1, Type:15/integer, Length:16/integer, EnterpriseId:16/integer,
	    Data:Length/bytes, Next/binary>>, IEs) ->
    IE = decode_v1_element(Data, {EnterpriseId, Type}),
    decode_v1(Next, put_ie(IE, IEs));
decode_v1(Data, IEs) ->
    ct:pal("undecoded: ~p", [Data]),
    decode_v1(<<>>, put_ie({undecoded, Data}, IEs)).

decode_v1_grouped(Bin) ->
    decode_v1(Bin, #{}).

encode_v1_element(_K, V, Acc) when is_list(V) ->
    encode_v1(V, Acc);
encode_v1_element(_K, V, Acc) ->
    encode_v1_element(V, Acc).

encode_tlv(Type, Bin, Acc)
  when is_integer(Type) ->
    ct:pal("encode_tlv(~p, ~p, ~p)", [Type, Bin, Acc]),
    Size = byte_size(Bin),
    <<Acc/binary, 0:1, Type:15, Size:16, Bin/binary>>;
encode_tlv({Type, EnterpriseId}, Bin, Acc)
  when is_integer(Type), is_integer(EnterpriseId) ->
    Size = byte_size(Bin) + 2,
    <<Acc/binary, 1:1, Type:15, Size:16, EnterpriseId:16, Bin/binary>>.

encode_v1(IEs, Acc) when is_binary(IEs) ->
    <<Acc/binary, IEs/binary>>;
encode_v1(IEs, Acc) when is_list(IEs) ->
    lists:foldl(fun encode_v1_element/2, Acc, IEs);
encode_v1(IEs, Acc) when is_map(IEs) ->
    maps:fold(fun encode_v1_element/3, Acc, IEs).

encode_v1_grouped(IEs) ->
    encode_v1(IEs, <<>>).

encode_v1_msg(Type, SEID, SeqNo, IEs)
  when is_integer(SEID) ->
    <<1:3, 0:3, 0:1, 1:1, Type:8, (size(IEs) + 12):16, SEID:64, SeqNo:24, 0:8, IEs/binary>>;
encode_v1_msg(Type, _SEID, SeqNo, IEs) ->
    <<1:3, 0:3, 0:1, 0:1, Type:8, (size(IEs) + 4):16, SeqNo:24, 0:8, IEs/binary>>.

decode_dns_label(Name) ->
    [ Label || <<Len:8, Label:Len/bytes>> <= Name ].

encode_dns_label(Name) ->
    << <<(size(Label)):8, Label/binary>> || Label <- Name >>.

decode_f_teid(<<_:4, ChId:1, TEID:1, IPv6:1, IPv4:1, Rest0/binary>>, _Type) ->
    IE0 = #f_teid{},
    {IE1, Rest1} = maybe_unsigned_integer(Rest0, TEID, 32, #f_teid.teid, IE0),
    {IE2, Rest2} = maybe_bin(Rest1, IPv4, 4, #f_teid.ipv4, IE1),
    {IE3, Rest3} = maybe_bin(Rest2, IPv6, 16, #f_teid.ipv6, IE2),
    {IE4, _Rest4} = maybe_unsigned_integer(Rest3, ChId, 8, #f_teid.choose_id, IE3),
    IE4.

encode_f_teid(#f_teid{teid = TEID, ipv6 = IPv6, ipv4 = IPv4, choose_id = ChId}) ->
    IE0 = <<0:4,
	    (is_set(ChId)):1, (is_set(TEID)):1, (is_set(IPv6)):1, (is_set(IPv4)):1>>,
    IE1 = maybe_unsigned_integer(TEID, 32, IE0),
    IE2 = maybe_bin(IPv4, 4, IE1),
    IE3 = maybe_bin(IPv6, 16, IE2),
    maybe_unsigned_integer(ChId, 8, IE3).

decode_sdf_filter(<<_Spare0:4, FL:1, SPI:1, TTC:1, FD:1, _Spare1:8, Rest0/binary>>, _Type) ->
    IE0 = #sdf_filter{},
    {IE1, Rest1} =
	case {Rest0, FD} of
	    {<<FlowLen:2/integer, Flow:FlowLen/bytes, R1/binary>>, 1} ->
		{IE0#sdf_filter{flow_description = Flow}, R1};
	    _ ->
		{IE0, Rest0}
	end,
    {IE2, Rest2} = maybe_unsigned_integer(Rest1, TTC, 16, #sdf_filter.tos_traffic_class, IE1),
    {IE3, Rest3} = maybe_unsigned_integer(Rest2, SPI, 32,
					  #sdf_filter.security_parameter_index, IE2),
    {IE4, _Rest4} = maybe_unsigned_integer(Rest3, FL, 24, #sdf_filter.flow_label, IE3),
    IE4.

encode_sdf_filter(#sdf_filter{
		     flow_description = FD, tos_traffic_class = TTC,
		     security_parameter_index = SPI,
		     flow_label = FL}) ->
    IE0 = <<0:4,
	    (is_set(FL)):1, (is_set(SPI)):1, (is_set(TTC)):1, (is_set(FD)):1, 0:8>>,
    IE1 = if is_binary(FD) ->
		  <<IE0/binary, (byte_size(FD)):2/integer, FD/binary>>;
	     true ->
		  IE0
	  end,
    IE2 = maybe_unsigned_integer(TTC, 16, IE1),
    IE3 = maybe_unsigned_integer(SPI, 32, IE2),
    maybe_unsigned_integer(FL, 24, IE3).

decode_volume_threshold(<<_:5, DLVOL:1, ULVOL:1, TOVOL:1, Rest0/binary>>, Type) ->
    IE0 = {Type, undefined, undefined, undefined},
    {IE1, Rest1} = maybe_unsigned_integer(Rest0, TOVOL, 64, 2, IE0),
    {IE2, Rest2} = maybe_unsigned_integer(Rest1, ULVOL, 64, 3, IE1),
    {IE3, _Rest3} = maybe_unsigned_integer(Rest2, DLVOL, 64, 4, IE2),
    IE3.

encode_volume_threshold({_Type, Total, UL, DL}) ->
    IE0 = <<0:5,
	    (is_set(DL)):1, (is_set(UL)):1, (is_set(Total)):1>>,
    IE1 = maybe_unsigned_integer(Total, 64, IE0),
    IE2 = maybe_unsigned_integer(UL, 64, IE1),
    maybe_unsigned_integer(DL, 64, IE2).

decode_paging_policy_indication(<<_:7, PPI:1, Rest0/binary>>, _Type) ->
    IE0 = #downlink_data_service_information{},
    {IE1, _Rest1} = maybe_unsigned_integer(Rest0, PPI, 8,
					   #downlink_data_service_information.value, IE0),
    IE1.

encode_paging_policy_indication(#downlink_data_service_information{value = Value}) ->
    IE0 = <<0:7, (is_set(Value)):1>>,
    maybe_unsigned_integer(Value, 8, IE0).

decode_f_seid(<<_:6, IPv4:1, IPv6:1, SEID:64/integer, Rest0/binary>>, _Type) ->
    IE0 = #f_seid{seid = SEID},
    {IE1, Rest1} = maybe_bin(Rest0, IPv4, 4, #f_seid.ipv4, IE0),
    {IE2, _Rest2} = maybe_bin(Rest1, IPv6, 16, #f_seid.ipv6, IE1),
    IE2.

encode_f_seid(#f_seid{seid = SEID, ipv4 = IPv4, ipv6 = IPv6}) ->
    IE0 = <<0:6, (is_set(IPv4)):1, (is_set(IPv6)):1, SEID:64/integer>>,
    IE1 = maybe_bin(IPv4, 4, IE0),
    maybe_bin(IPv6, 16, IE1).

decode_node_id(<<_:4, 0:4, IPv4:4/bytes, _/binary>>, _Type) ->
    #node_id{id = IPv4};
decode_node_id(<<_:4, 1:4, IPv6:16/bytes, _/binary>>, _Type) ->
    #node_id{id = IPv6};
decode_node_id(<<_:4, 2:4, FQDN/binary>>, _Type) ->
    #node_id{id = [ Part || <<Len:8, Part:Len/bytes>> <= FQDN ]}.

encode_node_id(#node_id{id = IPv4})
  when is_binary(IPv4), byte_size(IPv4) == 4 ->
    <<0:4, 0:4, IPv4/binary>>;
encode_node_id(#node_id{id = IPv6})
  when is_binary(IPv6), byte_size(IPv6) == 16 ->
    <<0:4, 1:4, IPv6/binary>>;
encode_node_id(#node_id{id = FQDN})
  when is_list(FQDN) ->
    <<0:4, 2:4, << <<(size(Part)):8, Part/binary>> || Part <- FQDN >>/binary >>.

decode_pfd_contents(<<_:4, CP:1, DN:1, URL:1, FD:1, Rest0/binary>>, _Type) ->
    IE0 = #pfd_contents{},
    {IE1, Rest1} = maybe_len_bin(Rest0, CP, 16, #pfd_contents.flow, IE0),
    {IE2, Rest2} = maybe_len_bin(Rest1, DN, 16, #pfd_contents.url, IE1),
    {IE3, Rest3} = maybe_len_bin(Rest2, URL, 16, #pfd_contents.domain, IE2),
    {IE4, _Rest4} = maybe_len_bin(Rest3, FD, 16, #pfd_contents.custom, IE3),
    IE4.

encode_pfd_contents(#pfd_contents{flow = Flow, url = URL,
				  domain = Domain, custom = Custom}) ->
    IE0 = <<0:4, (is_set(Flow)):1, (is_set(URL)):1, (is_set(Domain)):1, (is_set(Custom)):1>>,
    IE1 = maybe_len_bin(Flow, 16, IE0),
    IE2 = maybe_len_bin(URL, 16, IE1),
    IE3 = maybe_len_bin(Domain, 16, IE2),
    maybe_len_bin(Custom, 16, IE3).

decode_fq_csid(<<Type:4, Count:4, Rest0/binary>>, _Type) ->
    {IE1, Rest1} =
	case {Rest0, Type} of
	    {<< IPv4:4/bytes, R1/binary>>, 0} ->
		{#fq_csid{address = IPv4}, R1};
	    {<< IPv6:16/bytes, R1/binary>>, 1} ->
		{#fq_csid{address = IPv6}, R1};
	    {<< MCCMNC:20/integer, Id:12/integer, R1/binary>>, 2} ->
		{#fq_csid{address = {MCCMNC div 1000, MCCMNC rem 1000, Id}}, R1}
	end,
    Len = Count * 2,
    <<CSIDs:Len/bytes, _/binary>> = Rest1,
    IE1#fq_csid{csid = [X || <<X:16/integer>> <= CSIDs]}.

encode_fq_csid(#fq_csid{address = Address, csid = CSID}) ->
    Count = length(CSID),
    IE0 = case Address of
	      IPv4 when is_binary(IPv4) andalso byte_size(IPv4) == 4 ->
		  <<0:4, Count:4, IPv4/binary>>;
	      IPv6 when is_binary(IPv6) andalso byte_size(IPv6) == 16 ->
		  <<1:4, Count:4, IPv6/binary>>;
	      {MCC, MNC, Id} ->
		  <<2:4, Count:4, (MCC * 1000 + MNC):20, Id:12>>
	  end,
    <<IE0/binary, << <<X:16>> || X <- CSID >>/binary>>.

decode_dropped_dl_traffic_threshold(<<_:7, DLPA:1, Rest0/binary>>, _Type) ->
    IE0 = #dropped_dl_traffic_threshold{},
    {IE1, _Rest1} = maybe_unsigned_integer(Rest0, DLPA, 8,
					   #dropped_dl_traffic_threshold.value, IE0),
    IE1.

encode_dropped_dl_traffic_threshold(#dropped_dl_traffic_threshold{value = Value}) ->
    IE0 = <<0:7, (is_set(Value)):1>>,
    maybe_unsigned_integer(Value, 8, IE0).

decode_outer_header_creation(
  <<0:8/integer, TEID:32/integer, IPv4:4/bytes, _/binary>>, _Type) ->
    #outer_header_creation{
       type = 'GTP-U/UDP/IPv4', teid = TEID, address = IPv4};
decode_outer_header_creation(
  <<1:8/integer, TEID:32/integer, IPv6:16/bytes, _/binary>>, _Type) ->
    #outer_header_creation{
       type = 'GTP-U/UDP/IPv6', teid = TEID, address = IPv6};
decode_outer_header_creation(
  <<2:8/integer, IPv4:4/bytes, Port:16/integer, _/binary>>, _Type) ->
    #outer_header_creation{
       type = 'UDP/IPv4', address = IPv4, port = Port};
decode_outer_header_creation(
  <<3:8/integer, IPv6:16/bytes, Port:16/integer, _/binary>>, _Type) ->
    #outer_header_creation{
       type = 'UDP/IPv6', address = IPv6, port = Port}.

encode_outer_header_creation(
  #outer_header_creation{
     type = 'GTP-U/UDP/IPv4', teid = TEID, address = IPv4}) ->
    <<0:8/integer, TEID:32/integer, IPv4:4/bytes>>;
encode_outer_header_creation(
    #outer_header_creation{
       type = 'GTP-U/UDP/IPv6', teid = TEID, address = IPv6}) ->
    <<1:8/integer, TEID:32/integer, IPv6:16/bytes>>;
encode_outer_header_creation(
  #outer_header_creation{
     type = 'UDP/IPv4', address = IPv4, port = Port}) ->
    <<2:8/integer, IPv4:4/bytes, Port:16/integer>>;
encode_outer_header_creation(
  #outer_header_creation{
     type = 'UDP/IPv6', address = IPv6, port = Port}) ->
    <<3:8/integer, IPv6:16/bytes, Port:16/integer>>.

decode_ue_ip_address(<<_:5, Type:1, IPv4:1, IPv6:1, Rest0/binary>>, _Type) ->
    IE0 = if Type =:= 0 -> #ue_ip_address{type = src};
	     true ->       #ue_ip_address{type = dst}
	  end,
    {IE1, Rest1} = maybe_bin(Rest0, IPv4, 4, #f_teid.ipv4, IE0),
    {IE2, _Rest2} = maybe_bin(Rest1, IPv6, 16, #f_teid.ipv6, IE1),
    IE2.

encode_ue_ip_address(#ue_ip_address{type = Type, ipv4 = IPv4, ipv6 = IPv6}) ->
    SD = case Type of
	     src -> 0;
	     dst -> 1;
	     undefined -> 0
	 end,
    IE0 = <<0:5, SD:1, (is_set(IPv4)):1, (is_set(IPv6)):1>>,
    IE1 = maybe_bin(IPv4, 4, IE0),
    maybe_bin(IPv6, 16, IE1).

enum_v1_packet_rate_unit('minute') -> 0;
enum_v1_packet_rate_unit('6 minutes') -> 1;
enum_v1_packet_rate_unit('hour') -> 2;
enum_v1_packet_rate_unit('day') -> 3;
enum_v1_packet_rate_unit('week') -> 4;
enum_v1_packet_rate_unit(0) -> 'minute';
enum_v1_packet_rate_unit(1) -> '6 minutes';
enum_v1_packet_rate_unit(2) -> 'hour';
enum_v1_packet_rate_unit(3) -> 'day';
enum_v1_packet_rate_unit(4) -> 'week';
enum_v1_packet_rate_unit(X) when is_integer(X) -> X.

decode_packet_rate(<<_:6, DL:1, UL:1, Rest0/binary>>, _Type) ->
    IE0 = #packet_rate{},
    {IE1, Rest1} =
	case {Rest0, UL} of
	    {<<_:5, UlUnit:3/integer, UlRate:16/integer, R1>>, 1} ->
		{IE0#packet_rate{
		  ul_time_unit = enum_v1_packet_rate_unit(UlUnit),
		  ul_max_packet_rate = UlRate}, R1};
	    _ ->
		{IE0, Rest0}
	end,
    case {Rest1, DL} of
	{<<_:5, DlUnit:3/integer, DlRate:16/integer>>, 1} ->
	    IE1#packet_rate{
	      dl_time_unit = enum_v1_packet_rate_unit(DlUnit),
	      dl_max_packet_rate = DlRate};
	_ ->
	    IE1
    end.

encode_packet_rate(#packet_rate{
		      ul_time_unit = UlUnit, ul_max_packet_rate = UlRate,
		      dl_time_unit = DlUnit, dl_max_packet_rate = DlRate}) ->
    IE0 = <<0:6, (is_set(UlUnit)):1, (is_set(DlUnit)):1>>,
    IE1 = if UlUnit =/= undefined ->
		  <<IE0/binary, 0:5, (enum_v1_packet_rate_unit(UlUnit)):3, UlRate:16>>;
	     true ->
		  IE0
	  end,
    if DlUnit =/= undefined ->
	    <<IE1/binary, 0:5, (enum_v1_packet_rate_unit(DlUnit)):3, DlRate:16>>;
       true ->
	    IE1
    end.

decode_dl_flow_level_marking(<<_:6, SCI:1, TTC:1, Rest0/binary>>, _Type) ->
    IE0 = #dl_flow_level_marking{},
    {IE1, Rest1} = maybe_bin(Rest0, TTC, 2, #dl_flow_level_marking.traffic_class, IE0),
    {IE2, _Rest2} = maybe_bin(Rest1, SCI, 2,
			      #dl_flow_level_marking.service_class_indicator, IE1),
    IE2.
encode_dl_flow_level_marking(#dl_flow_level_marking{
				traffic_class = TTC,
				service_class_indicator = SCI}) ->
    IE0 = <<0:6, (is_set(SCI)):1, (is_set(TTC)):1>>,
    IE1 = maybe_bin(TTC, 2, IE0),
    maybe_bin(SCI, 2, IE1).

decode_remote_peer(<<_:6, IPv4:1, IPv6:1, Rest0/binary>>, _Type) ->
    IE0 = #remote_gtp_u_peer{},
    {IE1, Rest1} = maybe_bin(Rest0, IPv4, 4, #remote_gtp_u_peer.ipv4, IE0),
    {IE2, _Rest2} = maybe_bin(Rest1, IPv6, 16, #remote_gtp_u_peer.ipv6, IE1),
    IE2.

encode_remote_peer(#remote_gtp_u_peer{ipv4 = IPv4, ipv6 = IPv6}) ->
    IE0 = <<0:6, (is_set(IPv4)):1, (is_set(IPv6)):1>>,
    IE1 = maybe_bin(IPv4, 4, IE0),
    maybe_bin(IPv6, 16, IE1).

decode_failed_rule_id(<<_:4, 0:4, Id:32/integer, _/binary>>, _Type) ->
    #failed_rule_id{type = pdr, id = Id};
decode_failed_rule_id(<<_:4, 1:4, Id:32/integer, _/binary>>, _Type) ->
    #failed_rule_id{type = far, id = Id};
decode_failed_rule_id(<<_:4, 2:4, Id:32/integer, _/binary>>, _Type) ->
    #failed_rule_id{type = qer, id = Id};
decode_failed_rule_id(<<_:4, 3:4, Id:32/integer, _/binary>>, _Type) ->
    #failed_rule_id{type = urr, id = Id};
decode_failed_rule_id(<<_:4, 4:4, Id:8/integer, _/binary>>, _Type) ->
    #failed_rule_id{type = bar, id = Id}.

encode_failed_rule_id(#failed_rule_id{type = pdr, id = Id}) ->
    <<0:4, 0:4, Id:32>>;
encode_failed_rule_id(#failed_rule_id{type = far, id = Id}) ->
    <<0:4, 1:4, Id:32>>;
encode_failed_rule_id(#failed_rule_id{type = qer, id = Id}) ->
    <<0:4, 2:4, Id:32>>;
encode_failed_rule_id(#failed_rule_id{type = urr, id = Id}) ->
    <<0:4, 3:4, Id:32>>;
encode_failed_rule_id(#failed_rule_id{type = bar, id = Id}) ->
    <<0:4, 4:4, Id:8>>.

decode_user_plane_ip_resource_information(<<_:2, ASSONI:1, TEIDRI:3, IPv6:1, IPv4:1,
					    Rest0/binary>>, _Type) ->
    IE0 = #user_plane_ip_resource_information{},
    {IE1, Rest1} =
	case {Rest0, TEIDRI} of
	    {<<Base:8, R1/binary>>, 1} ->
		{IE0#user_plane_ip_resource_information{teid_range = {Base, TEIDRI}}, R1};
	    _ ->
		{IE0, Rest0}
	end,
    {IE2, Rest2} = maybe_bin(Rest1, IPv4, 4,
			     #user_plane_ip_resource_information.ipv4, IE1),
    {IE3, Rest3} = maybe_bin(Rest2, IPv6, 16,
			     #user_plane_ip_resource_information.ipv6, IE2),
    if ASSONI == 1 ->
	    IE3#user_plane_ip_resource_information{
	      network_instance = decode_dns_label(Rest3)};
       true ->
	    IE3
    end.

encode_user_plane_ip_resource_information(
  #user_plane_ip_resource_information{
     teid_range = Range, ipv4 = IPv4, ipv6 = IPv6, network_instance = Instance}) ->
    {Base, TEIDRI} =
	case Range of
	    undefined ->
		{undefined, 0};
	    {_,_} ->
		Range
	end,
    IE0 = <<0:2, (is_set(Instance)):1, TEIDRI:3, (is_set(IPv6)):1, (is_set(IPv4)):1>>,
    IE1 = maybe_unsigned_integer(Base, 8, IE0),
    IE2 = maybe_bin(IPv4, 4, IE1),
    IE3 = maybe_bin(IPv6, 16, IE2),
    if Instance =/= undefined ->
	    <<IE3/binary, (encode_dns_label(Instance))/binary>>;
       true ->
	    IE3
    end.

-include("pfcp_packet_v1_gen.hrl").
