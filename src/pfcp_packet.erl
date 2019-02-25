%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

%% Copyright 2017, Travelping GmbH <info@travelping.com>

-module(pfcp_packet).

-export([encode/1, encode_ies/1,
	 decode/1, decode/2, decode_ies/1, decode_ies/2,
	 msg_description_v1/1, to_map/1, ies_to_map/1]).
-export([lager_pr/1, pretty_print/1]).

-compile([{parse_transform, cut}, bin_opt_info]).
-compile({inline,[decode_v1_grouped/1]}).

-ifdef (TEST).
-compile([export_all, nowarn_export_all]).
-endif.

-include("pfcp_packet.hrl").

-define(IS_IPv4(X), (is_binary(X) andalso size(X) == 4)).
-define(IS_IPv6(X), (is_binary(X) andalso size(X) == 16)).

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
decode_ies(#pfcp{version = v1, ie = IEs} = Msg, #{ies := map}) ->
    Msg#pfcp{ie = decode_v1(IEs, #{})};
decode_ies(Msg, _) ->
    Msg.

encode(#pfcp{version = v1, type = Type, seid = SEID, seq_no = SeqNo, ie = IEs}) ->
    encode_v1_msg(message_type_v1(Type), SEID, SeqNo, encode_v1(IEs, <<>>)).

encode_ies(#pfcp{version = v1, ie = IEs} = Msg) ->
    Msg#pfcp{ie = encode_v1(IEs, <<>>)}.

to_map(#pfcp{ie = IEs} = Req) when is_list(IEs); is_map(IEs) ->
    Req#pfcp{ie = ies_to_map(IEs)}.

%%%===================================================================
%%% Record formating
%%%===================================================================

-define(PRETTY_PRINT(F, R),
	F(R, N) ->
	       case record_info(size, R) - 1 of
		   N -> record_info(fields, R);
		   _ -> no
	       end).

pretty_print(Record) ->
    io_lib_pretty:print(Record, fun pretty_print/2).

pretty_print(pfcp, N) ->
    N = record_info(size, pfcp) - 1,
    record_info(fields, pfcp);
pretty_print(Record, N) ->
    pretty_print_v1(Record, N).

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

put_ie(IE, IEs) ->
    Key = element(1, IE),
    UpdateFun = fun(V) when is_list(V) -> V ++ [IE];
		   (V)                 -> [V, IE]
		end,
    maps:update_with(Key, UpdateFun, IE, IEs).

to_map({Type, Group}, M)
  when Type =:= create_pdr orelse
       Type =:= pdi orelse
       Type =:= create_far orelse
       Type =:= forwarding_parameters orelse
       Type =:= duplicating_parameters orelse
       Type =:= create_urr orelse
       Type =:= create_qer orelse
       Type =:= created_pdr orelse
       Type =:= update_pdr orelse
       Type =:= update_far orelse
       Type =:= update_forwarding_parameters orelse
       Type =:= update_bar_response orelse
       Type =:= update_urr orelse
       Type =:= update_qer orelse
       Type =:= remove_pdr orelse
       Type =:= remove_far orelse
       Type =:= remove_urr orelse
       Type =:= remove_qer orelse
       Type =:= load_control_information orelse
       Type =:= overload_control_information orelse
       Type =:= application_id_pfds orelse
       Type =:= pfd_context orelse
       Type =:= application_detection_information orelse
       Type =:= query_urr orelse
       Type =:= usage_report_smr orelse
       Type =:= usage_report_sdr orelse
       Type =:= usage_report_srr orelse
       Type =:= downlink_data_report orelse
       Type =:= create_bar orelse
       Type =:= update_bar_request orelse
       Type =:= remove_bar orelse
       Type =:= error_indication_report orelse
       Type =:= user_plane_path_failure_report orelse
       Type =:= update_duplicating_parameters ->
    put_ie({Type, ies_to_map(Group)}, M);
to_map(IE, M) ->
    put_ie(IE, M).

ies_to_map(IEs) when is_list(IEs) ->
    lists:foldl(fun to_map/2, #{}, IEs);
ies_to_map(IEs) ->
    IEs.

lager_pr(_, {Type, Group})
  when Type =:= create_pdr orelse
       Type =:= pdi orelse
       Type =:= create_far orelse
       Type =:= forwarding_parameters orelse
       Type =:= duplicating_parameters orelse
       Type =:= create_urr orelse
       Type =:= create_qer orelse
       Type =:= created_pdr orelse
       Type =:= update_pdr orelse
       Type =:= update_far orelse
       Type =:= update_forwarding_parameters orelse
       Type =:= update_bar_response orelse
       Type =:= update_urr orelse
       Type =:= update_qer orelse
       Type =:= remove_pdr orelse
       Type =:= remove_far orelse
       Type =:= remove_urr orelse
       Type =:= remove_qer orelse
       Type =:= load_control_information orelse
       Type =:= overload_control_information orelse
       Type =:= application_id_pfds orelse
       Type =:= pfd_context orelse
       Type =:= application_detection_information orelse
       Type =:= query_urr orelse
       Type =:= usage_report_smr orelse
       Type =:= usage_report_sdr orelse
       Type =:= usage_report_srr orelse
       Type =:= downlink_data_report orelse
       Type =:= create_bar orelse
       Type =:= update_bar_request orelse
       Type =:= remove_bar orelse
       Type =:= error_indication_report orelse
       Type =:= user_plane_path_failure_report orelse
       Type =:= update_duplicating_parameters ->
    lager:pr({Type, lager_pr(Group)}, ?MODULE);
lager_pr(_, Value) ->
    lager:pr(Value, ?MODULE).

lager_pr(IEs) when is_list(IEs) ->
    lists:map(lager_pr('Key', _), IEs);
lager_pr(IEs) when is_map(IEs) ->
    maps:map(fun lager_pr/2, IEs).

bool2int(false) -> 0;
bool2int(true)  -> 1.

is_set(Value) -> bool2int(Value =/= undefined).

is_set(Atom, True) when Atom =:= True ->
    1;
is_set(_, _) ->
    0.

if_set(Cond, If, _Else)
  when Cond == true; Cond == 1 ->
    If;
if_set(_Cond, _If, Else) ->
    Else.

maybe_atom(1, True) ->
    True;
maybe_atom(0, _True) ->
    undefined.

maybe_bin(<<Bin/binary>>, 0, _, _, IE) ->
    {IE, Bin};
maybe_bin(<<Bin/binary>>, 1, Len, Pos, IE) ->
    <<V:Len/bytes, Rest/binary>> = Bin,
    {setelement(Pos, IE, V), Rest}.

maybe_bin(Bin, Len, IE)
  when is_binary(Bin) andalso byte_size(Bin) =:= Len ->
    <<IE/binary, Bin:Len/bytes>>;
maybe_bin(undefined, _, IE) ->
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
	    Rest0/binary>>, IEs) ->
    DLen = Length - 2,
    <<Data:DLen/binary, Next/binary>> = Rest0,
    IE = decode_v1_element(Data, {EnterpriseId, Type}),
    decode_v1(Next, put_ie(IE, IEs));
decode_v1(Data, IEs) ->
    ct:pal("undecoded: ~p", [Data]),
    decode_v1(<<>>, put_ie({undecoded, Data}, IEs)).

decode_v1_grouped(Bin) ->
    decode_v1(Bin, #{}).

encode_v1_element(_K, V, Acc) ->
    encode_v1_element(V, Acc).

encode_tlv(Type, Bin, Acc)
  when is_integer(Type) ->
    Size = byte_size(Bin),
    <<Acc/binary, 0:1, Type:15, Size:16, Bin/binary>>;
encode_tlv({EnterpriseId, Type}, Bin, Acc)
  when is_integer(EnterpriseId),
       is_integer(Type) ->
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

decode_f_teid(<<_:4, ChId:1, Ch:1, IPv6:1, IPv4:1, Rest0/binary>>, _Type)
  when Ch =:= 1 ->
    IE0 = #f_teid{
	     teid = choose,
	     ipv4 = maybe_atom(IPv4, choose),
	     ipv6 = maybe_atom(IPv6, choose)
	    },
    {IE1, _Rest1} = maybe_unsigned_integer(Rest0, ChId, 8, #f_teid.choose_id, IE0),
    IE1;
decode_f_teid(<<_:4, ChId:1, Ch:1, IPv6:1, IPv4:1, TEID:32, Rest0/binary>>, _Type)
  when Ch =:= 0 andalso ChId =:= 0 ->
    IE0 = #f_teid{teid = TEID},
    {IE1, Rest1} = maybe_bin(Rest0, IPv4, 4, #f_teid.ipv4, IE0),
    {IE2, _Rest2} = maybe_bin(Rest1, IPv6, 16, #f_teid.ipv6, IE1),
    IE2.

encode_f_teid(#f_teid{teid = choose, ipv6 = IPv6, ipv4 = IPv4, choose_id = ChId}) ->
    IE0 = <<0:4,
	    (is_set(ChId)):1, 1:1, (is_set(IPv6, choose)):1, (is_set(IPv4, choose)):1>>,
    maybe_unsigned_integer(ChId, 8, IE0);
encode_f_teid(#f_teid{teid = TEID, ipv6 = IPv6, ipv4 = IPv4})
  when is_integer(TEID) ->
    IE0 = <<0:4, 0:1, 0:1, (is_set(IPv6)):1, (is_set(IPv4)):1, TEID:32>>,
    IE1 = maybe_bin(IPv4, 4, IE0),
    maybe_bin(IPv6, 16, IE1).

decode_sdf_filter(<<_Spare0:4, FL:1, SPI:1, TTC:1, FD:1, _Spare1:8, Rest0/binary>>, _Type) ->
    IE0 = #sdf_filter{},
    {IE1, Rest1} = maybe_len_bin(Rest0, FD, 16, #sdf_filter.flow_description, IE0),
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
    IE1 = maybe_len_bin(FD, 16, IE0),
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
    ct:pal("CSID: ~p, ~p", [CSID,  << <<X:16>> || X <- CSID >>]),
    <<IE0/binary, << <<X:16>> || X <- CSID >>/binary>>.

decode_dropped_dl_traffic_threshold(<<_:7, DLPA:1, Rest0/binary>>, _Type) ->
    IE0 = #dropped_dl_traffic_threshold{},
    {IE1, _Rest1} = maybe_unsigned_integer(Rest0, DLPA, 64,
					   #dropped_dl_traffic_threshold.value, IE0),
    IE1.

encode_dropped_dl_traffic_threshold(#dropped_dl_traffic_threshold{value = Value}) ->
    IE0 = <<0:7, (is_set(Value)):1>>,
    maybe_unsigned_integer(Value, 64, IE0).

decode_outer_header_creation(<<_:4, 0:2, IP:2, _:8, TEID:32/integer, Rest/binary>>, _Type)
  when IP /= 0 ->
    case {IP, Rest} of
	{1, <<IPv4:4/bytes, _/binary>>} ->
	    #outer_header_creation{type = 'GTP-U', teid = TEID, ipv4 = IPv4};
	{2, <<IPv6:16/bytes, _/binary>>} ->
	    #outer_header_creation{type = 'GTP-U', teid = TEID, ipv6 = IPv6};
	{3, <<IPv4:4/bytes, IPv6:16/bytes, _/binary>>} ->
	    #outer_header_creation{type = 'GTP-U', teid = TEID, ipv4 = IPv4, ipv6 = IPv6}
    end;
decode_outer_header_creation(<<_:4, IP:2, 0:2, _:8, Rest/binary>>, _Type)
  when IP /= 0 ->
    case {IP, Rest} of
	{1, <<IPv4:4/bytes, Port:16/integer, _/binary>>} ->
	    #outer_header_creation{type = 'UDP', ipv4 = IPv4, port = Port};
	{2, <<IPv6:16/bytes, Port:16/integer, _/binary>>} ->
	    #outer_header_creation{type = 'UDP', ipv6 = IPv6, port = Port}
    end.

encode_outer_header_creation(#outer_header_creation{type = 'GTP-U', teid = TEID,
						    ipv4 = IPv4, ipv6 = IPv6})
  when ?IS_IPv4(IPv4) andalso not ?IS_IPv6(IPv6) ->
    <<1:8, 0:8, TEID:32/integer, IPv4/binary>>;
encode_outer_header_creation(#outer_header_creation{type = 'GTP-U', teid = TEID,
						    ipv4 = IPv4, ipv6 = IPv6})
  when not ?IS_IPv4(IPv4) andalso ?IS_IPv6(IPv6) ->
    <<2:8, 0:8, TEID:32/integer, IPv6/binary>>;
encode_outer_header_creation(#outer_header_creation{type = 'GTP-U', teid = TEID,
						    ipv4 = IPv4, ipv6 = IPv6})
  when ?IS_IPv4(IPv4) andalso ?IS_IPv6(IPv6) ->
    <<3:8, 0:8, TEID:32/integer, IPv4/binary, IPv6/binary>>;

encode_outer_header_creation(#outer_header_creation{type = 'UDP', ipv4 = IPv4, port = Port})
  when ?IS_IPv4(IPv4) ->
    <<4:8, 0:8, IPv4:4/bytes, Port:16/integer>>;
encode_outer_header_creation(#outer_header_creation{type = 'UDP', ipv6 = IPv6, port = Port})
  when ?IS_IPv6(IPv6) ->
    <<8:8, 0:8, IPv6:16/bytes, Port:16/integer>>.

decode_ue_ip_address(<<_:5, Type:1, IPv4:1, IPv6:1, Rest0/binary>>, _Type) ->
    IE0 = if Type =:= 0 -> #ue_ip_address{type = src};
	     true ->       #ue_ip_address{type = dst}
	  end,
    {IE1, Rest1} = maybe_bin(Rest0, IPv4, 4, #ue_ip_address.ipv4, IE0),
    {IE2, _Rest2} = maybe_bin(Rest1, IPv6, 16, #ue_ip_address.ipv6, IE1),
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
	    {<<_:5, UlUnit:3/integer, UlRate:16/integer, R1/binary>>, 1} ->
		{IE0#packet_rate{
		  ul_time_unit = enum_v1_packet_rate_unit(UlUnit),
		  ul_max_packet_rate = UlRate}, R1};
	    _ ->
		{IE0, Rest0}
	end,
    case {Rest1, DL} of
	{<<_:5, DlUnit:3/integer, DlRate:16/integer, _/binary>>, 1} ->
	    IE1#packet_rate{
	      dl_time_unit = enum_v1_packet_rate_unit(DlUnit),
	      dl_max_packet_rate = DlRate};
	_ ->
	    IE1
    end.

encode_packet_rate(#packet_rate{
		      ul_time_unit = UlUnit, ul_max_packet_rate = UlRate,
		      dl_time_unit = DlUnit, dl_max_packet_rate = DlRate}) ->
    IE0 = <<0:6, (is_set(DlUnit)):1, (is_set(UlUnit)):1>>,
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

decode_failed_rule_id(<<_:4, 0:4, Id:16/integer, _/binary>>, _Type) ->
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
    <<0:4, 0:4, Id:16>>;
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
	case Rest0 of
	    <<Base:8, R1/binary>>
	      when TEIDRI /= 0 ->
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
	      network_instance = Rest3};
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
    if is_binary(Instance) ->
	    <<IE3/binary, Instance/binary>>;
       true ->
	    IE3
    end.

decode_mac_address(<<_:4, UDES:1, USOU:1, DEST:1, SOUR:1, Rest0/binary>>, _Type) ->
    IE0 = #mac_address{},
    {IE1, Rest1} = maybe_bin(Rest0, SOUR, 6, #mac_address.source_mac, IE0),
    {IE2, Rest2} = maybe_bin(Rest1, DEST, 6, #mac_address.destination_mac, IE1),
    {IE3, Rest3} = maybe_bin(Rest2, USOU, 6, #mac_address.upper_source_mac, IE2),
    {IE4, _}     = maybe_bin(Rest3, UDES, 6, #mac_address.upper_destination_mac, IE3),
    IE4.

encode_mac_address(#mac_address{source_mac = SOUR, destination_mac = DEST,
				upper_source_mac = USOU, upper_destination_mac = UDES}) ->
    IE0 = <<0:4, (is_set(UDES)):1, (is_set(USOU)):1, (is_set(DEST)):1, (is_set(SOUR)):1>>,
    IE1 = maybe_bin(SOUR, 6, IE0),
    IE2 = maybe_bin(DEST, 6, IE1),
    IE3 = maybe_bin(USOU, 6, IE2),
    maybe_bin(UDES, 6, IE3).

decode_vlan_tag(<<_:5, VID_F:1, DEI_F:1, PCP_F:1,
		  HiVID:4, DEI:1, PCP:3, VID:8, _/binary>>, Type) ->
    {Type,
     if_set(PCP_F, PCP, undefined),
     if_set(DEI_F, DEI, undefined),
     if_set(VID_F, (HiVID bsl 8) bor VID, undefined)}.

encode_vlan_tag({_Type, PCP, DEI, VID}) ->
    <<0:5, (is_set(VID)):1, (is_set(DEI)):1, (is_set(PCP)):1,
      (if_set(is_set(VID), is_integer(VID) andalso (VID bsr 8), 0)):4,
      (if_set(is_set(DEI), DEI, 0)):1,
      (if_set(is_set(PCP), PCP, 0)):3,
      (if_set(is_set(VID), is_integer(VID) andalso (VID band 16#ff), 0)):8>>.

decode_user_id(<<_:6, IMEI:1, IMSI:1, Rest0/binary>>, _Type) ->
    IE0 = #user_id{},
    {IE1, Rest1} = maybe_len_bin(Rest0, IMSI, 8, #user_id.imsi, IE0),
    {IE2, _}     = maybe_len_bin(Rest1, IMEI, 8, #user_id.imei, IE1),
    IE2.

encode_user_id(#user_id{imsi = IMSI, imei = IMEI}) ->
    IE0 = <<0:6,
	    (is_set(IMEI)):1, (is_set(IMSI)):1>>,
    IE1 = maybe_len_bin(IMSI, 8, IE0),
    maybe_len_bin(IMEI, 8, IE1).

%% The following code is auto-generated. DO NOT EDIT

%% -include("pfcp_packet_v1_gen.hrl").

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

enum_v1_pdn_type('IPv4') -> 1;
enum_v1_pdn_type('IPv6') -> 2;
enum_v1_pdn_type('IPv4v6') -> 3;
enum_v1_pdn_type('Non-IP') -> 4;
enum_v1_pdn_type(1) -> 'IPv4';
enum_v1_pdn_type(2) -> 'IPv6';
enum_v1_pdn_type(3) -> 'IPv4v6';
enum_v1_pdn_type(4) -> 'Non-IP';
enum_v1_pdn_type(X) when is_integer(X) -> X.

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

enum_v1_type('IPv4') -> 0;
enum_v1_type('IPv6') -> 1;
enum_v1_type('URL') -> 2;
enum_v1_type('SIP URI') -> 3;
enum_v1_type(0) -> 'IPv4';
enum_v1_type(1) -> 'IPv6';
enum_v1_type(2) -> 'URL';
enum_v1_type(3) -> 'SIP URI';
enum_v1_type(X) when is_integer(X) -> X.

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

%% decode pfcp_cause
decode_v1_element(<<M_cause:8/integer>>, 19) ->
    #pfcp_cause{cause = enum_v1_cause(M_cause)};

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
    #network_instance{instance = M_instance};

%% decode sdf_filter
decode_v1_element(<<Data/binary>>, 23) ->
    decode_sdf_filter(Data, sdf_filter);

%% decode application_id
decode_v1_element(<<M_id/binary>>, 24) ->
    #application_id{id = M_id};

%% decode gate_status
decode_v1_element(<<_:4,
		    M_ul:2/integer,
		    M_dl:2/integer,
		    _/binary>>, 25) ->
    #gate_status{ul = enum_v1_ul(M_ul),
		 dl = enum_v1_dl(M_dl)};

%% decode mbr
decode_v1_element(<<M_ul:40/integer,
		    M_dl:40/integer,
		    _/binary>>, 26) ->
    #mbr{ul = M_ul,
	 dl = M_dl};

%% decode gbr
decode_v1_element(<<M_ul:40/integer,
		    M_dl:40/integer,
		    _/binary>>, 27) ->
    #gbr{ul = M_ul,
	 dl = M_dl};

%% decode qer_correlation_id
decode_v1_element(<<M_id:32/integer,
		    _/binary>>, 28) ->
    #qer_correlation_id{id = M_id};

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
		    _:4,
		    M_mac_addresses_reporting:1/integer,
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
			mac_addresses_reporting = M_mac_addresses_reporting,
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
decode_v1_element(<<_:4,
		    M_upir:1/integer,
		    M_erir:1/integer,
		    M_usar:1/integer,
		    M_dldr:1/integer,
		    _/binary>>, 39) ->
    #report_type{upir = M_upir,
		 erir = M_erir,
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
		    _:4,
		    M_quoac:1/integer,
		    M_udbc:1/integer,
		    M_pdiu:1/integer,
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
			  quoac = M_quoac,
			  udbc = M_udbc,
			  pdiu = M_pdiu,
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
		    _:1,
		    M_macar:1/integer,
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
			  macar = M_macar,
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
decode_v1_element(<<M_time:32/integer,
		    _/binary>>, 69) ->
    #time_of_first_packet{time = M_time};

%% decode time_of_last_packet
decode_v1_element(<<M_time:32/integer,
		    _/binary>>, 70) ->
    #time_of_last_packet{time = M_time};

%% decode quota_holding_time
decode_v1_element(<<M_time:32/integer,
		    _/binary>>, 71) ->
    #quota_holding_time{time = M_time};

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
decode_v1_element(<<M_time:32/integer,
		    _/binary>>, 75) ->
    #start_time{time = M_time};

%% decode end_time
decode_v1_element(<<M_time:32/integer,
		    _/binary>>, 76) ->
    #end_time{time = M_time};

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
decode_v1_element(<<M_time:32/integer,
		    _/binary>>, 96) ->
    #recovery_time_stamp{time = M_time};

%% decode dl_flow_level_marking
decode_v1_element(<<Data/binary>>, 97) ->
    decode_dl_flow_level_marking(Data, dl_flow_level_marking);

%% decode header_enrichment
decode_v1_element(<<_:4,
		    M_header_type:4/integer,
		    M_name_len:8/integer, M_name:M_name_len/bytes,
		    M_value_len:8/integer, M_value:M_value_len/bytes,
		    _/binary>>, 98) ->
    #header_enrichment{header_type = enum_v1_header_type(M_header_type),
		       name = M_name,
		       value = M_value};

%% decode error_indication_report
decode_v1_element(<<M_group/binary>>, 99) ->
    #error_indication_report{group = decode_v1_grouped(M_group)};

%% decode measurement_information
decode_v1_element(<<_:5,
		    M_radi:1/integer,
		    M_inam:1/integer,
		    M_mbqe:1/integer,
		    _/binary>>, 100) ->
    #measurement_information{radi = M_radi,
			     inam = M_inam,
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
		    M_pdn_type:3/integer,
		    _/binary>>, 113) ->
    #pdn_type{pdn_type = enum_v1_pdn_type(M_pdn_type)};

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

%% decode user_plane_inactivity_timer
decode_v1_element(<<M_timer:32/integer,
		    _/binary>>, 117) ->
    #user_plane_inactivity_timer{timer = M_timer};

%% decode aggregated_urrs
decode_v1_element(<<M_group/binary>>, 118) ->
    #aggregated_urrs{group = decode_v1_grouped(M_group)};

%% decode multiplier
decode_v1_element(<<M_digits:40/integer,
		    M_exponent:40/integer>>, 119) ->
    #multiplier{digits = M_digits,
		exponent = M_exponent};

%% decode aggregated_urr_id
decode_v1_element(<<M_id:32/integer>>, 120) ->
    #aggregated_urr_id{id = M_id};

%% decode subsequent_volume_quota
decode_v1_element(<<Data/binary>>, 121) ->
    decode_volume_threshold(Data, subsequent_volume_quota);

%% decode subsequent_time_quota
decode_v1_element(<<M_quota:32/integer,
		    _/binary>>, 122) ->
    #subsequent_time_quota{quota = M_quota};

%% decode rqi
decode_v1_element(<<_:7,
		    M_rqi:1/integer,
		    _/binary>>, 123) ->
    #rqi{rqi = M_rqi};

%% decode qfi
decode_v1_element(<<M_qfi:8/integer,
		    _/binary>>, 124) ->
    #qfi{qfi = M_qfi};

%% decode query_urr_reference
decode_v1_element(<<M_reference:8/integer,
		    _/binary>>, 125) ->
    #query_urr_reference{reference = M_reference};

%% decode additional_usage_reports_information
decode_v1_element(<<M_auri:1/integer,
		    M_reports:15/integer,
		    _/binary>>, 126) ->
    #additional_usage_reports_information{auri = M_auri,
					  reports = M_reports};

%% decode create_traffic_endpoint
decode_v1_element(<<M_group/binary>>, 127) ->
    #create_traffic_endpoint{group = decode_v1_grouped(M_group)};

%% decode created_traffic_endpoint
decode_v1_element(<<M_group/binary>>, 128) ->
    #created_traffic_endpoint{group = decode_v1_grouped(M_group)};

%% decode update_traffic_endpoint
decode_v1_element(<<M_group/binary>>, 129) ->
    #update_traffic_endpoint{group = decode_v1_grouped(M_group)};

%% decode remove_traffic_endpoint
decode_v1_element(<<M_group/binary>>, 130) ->
    #remove_traffic_endpoint{group = decode_v1_grouped(M_group)};

%% decode traffic_endpoint_id
decode_v1_element(<<M_id:8/integer,
		    _/binary>>, 131) ->
    #traffic_endpoint_id{id = M_id};

%% decode ethernet_packet_filter
decode_v1_element(<<M_group/binary>>, 132) ->
    #ethernet_packet_filter{group = decode_v1_grouped(M_group)};

%% decode mac_address
decode_v1_element(<<Data/binary>>, 133) ->
    decode_mac_address(Data, mac_address);

%% decode c_tag
decode_v1_element(<<Data/binary>>, 134) ->
    decode_vlan_tag(Data, c_tag);

%% decode s_tag
decode_v1_element(<<Data/binary>>, 135) ->
    decode_vlan_tag(Data, s_tag);

%% decode ethertype
decode_v1_element(<<M_type:16/integer,
		    _/binary>>, 136) ->
    #ethertype{type = M_type};

%% decode proxying
decode_v1_element(<<_:6,
		    M_ins:1/integer,
		    M_arp:1/integer,
		    _/binary>>, 137) ->
    #proxying{ins = M_ins,
	      arp = M_arp};

%% decode ethernet_filter_id
decode_v1_element(<<M_id:32/integer,
		    _/binary>>, 138) ->
    #ethernet_filter_id{id = M_id};

%% decode ethernet_filter_properties
decode_v1_element(<<_:7,
		    M_bide:1/integer,
		    _/binary>>, 139) ->
    #ethernet_filter_properties{bide = M_bide};

%% decode suggested_buffering_packets_count
decode_v1_element(<<M_count:8/integer,
		    _/binary>>, 140) ->
    #suggested_buffering_packets_count{count = M_count};

%% decode user_id
decode_v1_element(<<Data/binary>>, 141) ->
    decode_user_id(Data, user_id);

%% decode ethernet_pdu_session_information
decode_v1_element(<<_:7,
		    M_ethi:1/integer,
		    _/binary>>, 142) ->
    #ethernet_pdu_session_information{ethi = M_ethi};

%% decode ethernet_traffic_information
decode_v1_element(<<M_group/binary>>, 143) ->
    #ethernet_traffic_information{group = decode_v1_grouped(M_group)};

%% decode mac_addresses_detected
decode_v1_element(<<M_macs_len:8/integer, M_macs_Rest/binary>>, 144) ->
    M_macs_size = M_macs_len * 6,
    <<M_macs:M_macs_size/bytes>> = M_macs_Rest,
    #mac_addresses_detected{macs = [X || <<X:6/bytes>> <= M_macs]};

%% decode mac_addresses_removed
decode_v1_element(<<M_macs_len:8/integer, M_macs_Rest/binary>>, 145) ->
    M_macs_size = M_macs_len * 6,
    <<M_macs:M_macs_size/bytes>> = M_macs_Rest,
    #mac_addresses_removed{macs = [X || <<X:6/bytes>> <= M_macs]};

%% decode ethernet_inactivity_timer
decode_v1_element(<<M_timer:32/integer,
		    _/binary>>, 146) ->
    #ethernet_inactivity_timer{timer = M_timer};

%% decode tp_packet_measurement
decode_v1_element(<<Data/binary>>, {18681,1}) ->
    decode_volume_threshold(Data, tp_packet_measurement);

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

encode_v1_element(#pfcp_cause{
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
    encode_tlv(22, <<M_instance/binary>>, Acc);

encode_v1_element(#sdf_filter{} = IE, Acc) ->
    encode_tlv(23, encode_sdf_filter(IE), Acc);

encode_v1_element(#application_id{
		       id = M_id}, Acc) ->
    encode_tlv(24, <<M_id/binary>>, Acc);

encode_v1_element(#gate_status{
		       ul = M_ul,
		       dl = M_dl}, Acc) ->
    encode_tlv(25, <<0:4,
		     (enum_v1_ul(M_ul)):2/integer,
		     (enum_v1_dl(M_dl)):2/integer>>, Acc);

encode_v1_element(#mbr{
		       ul = M_ul,
		       dl = M_dl}, Acc) ->
    encode_tlv(26, <<M_ul:40,
		     M_dl:40>>, Acc);

encode_v1_element(#gbr{
		       ul = M_ul,
		       dl = M_dl}, Acc) ->
    encode_tlv(27, <<M_ul:40,
		     M_dl:40>>, Acc);

encode_v1_element(#qer_correlation_id{
		       id = M_id}, Acc) ->
    encode_tlv(28, <<M_id:32>>, Acc);

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
		       mac_addresses_reporting = M_mac_addresses_reporting,
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
		     0:4,
		     M_mac_addresses_reporting:1,
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
		       upir = M_upir,
		       erir = M_erir,
		       usar = M_usar,
		       dldr = M_dldr}, Acc) ->
    encode_tlv(39, <<0:4,
		     M_upir:1,
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
		       quoac = M_quoac,
		       udbc = M_udbc,
		       pdiu = M_pdiu,
		       empu = M_empu}, Acc) ->
    encode_tlv(43, <<M_treu:1,
		     M_heeu:1,
		     M_pfdm:1,
		     M_ftup:1,
		     M_trst:1,
		     M_dlbd:1,
		     M_ddnd:1,
		     M_bucp:1,
		     0:4,
		     M_quoac:1,
		     M_udbc:1,
		     M_pdiu:1,
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
		       macar = M_macar,
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
		     0:1,
		     M_macar:1,
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
		       time = M_time}, Acc) ->
    encode_tlv(69, <<M_time:32>>, Acc);

encode_v1_element(#time_of_last_packet{
		       time = M_time}, Acc) ->
    encode_tlv(70, <<M_time:32>>, Acc);

encode_v1_element(#quota_holding_time{
		       time = M_time}, Acc) ->
    encode_tlv(71, <<M_time:32>>, Acc);

encode_v1_element(#dropped_dl_traffic_threshold{} = IE, Acc) ->
    encode_tlv(72, encode_dropped_dl_traffic_threshold(IE), Acc);

encode_v1_element(#volume_quota{} = IE, Acc) ->
    encode_tlv(73, encode_volume_threshold(IE), Acc);

encode_v1_element(#time_quota{
		       quota = M_quota}, Acc) ->
    encode_tlv(74, <<M_quota:32>>, Acc);

encode_v1_element(#start_time{
		       time = M_time}, Acc) ->
    encode_tlv(75, <<M_time:32>>, Acc);

encode_v1_element(#end_time{
		       time = M_time}, Acc) ->
    encode_tlv(76, <<M_time:32>>, Acc);

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
		       time = M_time}, Acc) ->
    encode_tlv(96, <<M_time:32>>, Acc);

encode_v1_element(#dl_flow_level_marking{} = IE, Acc) ->
    encode_tlv(97, encode_dl_flow_level_marking(IE), Acc);

encode_v1_element(#header_enrichment{
		       header_type = M_header_type,
		       name = M_name,
		       value = M_value}, Acc) ->
    encode_tlv(98, <<0:4,
		     (enum_v1_header_type(M_header_type)):4/integer,
		     (byte_size(M_name)):8/integer, M_name/binary,
		     (byte_size(M_value)):8/integer, M_value/binary>>, Acc);

encode_v1_element(#error_indication_report{
		       group = M_group}, Acc) ->
    encode_tlv(99, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#measurement_information{
		       radi = M_radi,
		       inam = M_inam,
		       mbqe = M_mbqe}, Acc) ->
    encode_tlv(100, <<0:5,
		      M_radi:1,
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
		       pdn_type = M_pdn_type}, Acc) ->
    encode_tlv(113, <<0:5,
		      (enum_v1_pdn_type(M_pdn_type)):3/integer>>, Acc);

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

encode_v1_element(#user_plane_inactivity_timer{
		       timer = M_timer}, Acc) ->
    encode_tlv(117, <<M_timer:32>>, Acc);

encode_v1_element(#aggregated_urrs{
		       group = M_group}, Acc) ->
    encode_tlv(118, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#multiplier{
		       digits = M_digits,
		       exponent = M_exponent}, Acc) ->
    encode_tlv(119, <<M_digits:40,
		      M_exponent:40>>, Acc);

encode_v1_element(#aggregated_urr_id{
		       id = M_id}, Acc) ->
    encode_tlv(120, <<M_id:32>>, Acc);

encode_v1_element(#subsequent_volume_quota{} = IE, Acc) ->
    encode_tlv(121, encode_volume_threshold(IE), Acc);

encode_v1_element(#subsequent_time_quota{
		       quota = M_quota}, Acc) ->
    encode_tlv(122, <<M_quota:32>>, Acc);

encode_v1_element(#rqi{
		       rqi = M_rqi}, Acc) ->
    encode_tlv(123, <<0:7,
		      M_rqi:1>>, Acc);

encode_v1_element(#qfi{
		       qfi = M_qfi}, Acc) ->
    encode_tlv(124, <<M_qfi:8>>, Acc);

encode_v1_element(#query_urr_reference{
		       reference = M_reference}, Acc) ->
    encode_tlv(125, <<M_reference:8>>, Acc);

encode_v1_element(#additional_usage_reports_information{
		       auri = M_auri,
		       reports = M_reports}, Acc) ->
    encode_tlv(126, <<M_auri:1,
		      M_reports:15>>, Acc);

encode_v1_element(#create_traffic_endpoint{
		       group = M_group}, Acc) ->
    encode_tlv(127, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#created_traffic_endpoint{
		       group = M_group}, Acc) ->
    encode_tlv(128, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#update_traffic_endpoint{
		       group = M_group}, Acc) ->
    encode_tlv(129, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#remove_traffic_endpoint{
		       group = M_group}, Acc) ->
    encode_tlv(130, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#traffic_endpoint_id{
		       id = M_id}, Acc) ->
    encode_tlv(131, <<M_id:8>>, Acc);

encode_v1_element(#ethernet_packet_filter{
		       group = M_group}, Acc) ->
    encode_tlv(132, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#mac_address{} = IE, Acc) ->
    encode_tlv(133, encode_mac_address(IE), Acc);

encode_v1_element(#c_tag{} = IE, Acc) ->
    encode_tlv(134, encode_vlan_tag(IE), Acc);

encode_v1_element(#s_tag{} = IE, Acc) ->
    encode_tlv(135, encode_vlan_tag(IE), Acc);

encode_v1_element(#ethertype{
		       type = M_type}, Acc) ->
    encode_tlv(136, <<M_type:16>>, Acc);

encode_v1_element(#proxying{
		       ins = M_ins,
		       arp = M_arp}, Acc) ->
    encode_tlv(137, <<0:6,
		      M_ins:1,
		      M_arp:1>>, Acc);

encode_v1_element(#ethernet_filter_id{
		       id = M_id}, Acc) ->
    encode_tlv(138, <<M_id:32>>, Acc);

encode_v1_element(#ethernet_filter_properties{
		       bide = M_bide}, Acc) ->
    encode_tlv(139, <<0:7,
		      M_bide:1>>, Acc);

encode_v1_element(#suggested_buffering_packets_count{
		       count = M_count}, Acc) ->
    encode_tlv(140, <<M_count:8>>, Acc);

encode_v1_element(#user_id{} = IE, Acc) ->
    encode_tlv(141, encode_user_id(IE), Acc);

encode_v1_element(#ethernet_pdu_session_information{
		       ethi = M_ethi}, Acc) ->
    encode_tlv(142, <<0:7,
		      M_ethi:1>>, Acc);

encode_v1_element(#ethernet_traffic_information{
		       group = M_group}, Acc) ->
    encode_tlv(143, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#mac_addresses_detected{
		       macs = M_macs}, Acc) ->
    encode_tlv(144, <<(length(M_macs)):8/integer, (<< <<X/binary>> || X <- M_macs>>)/binary>>, Acc);

encode_v1_element(#mac_addresses_removed{
		       macs = M_macs}, Acc) ->
    encode_tlv(145, <<(length(M_macs)):8/integer, (<< <<X/binary>> || X <- M_macs>>)/binary>>, Acc);

encode_v1_element(#ethernet_inactivity_timer{
		       timer = M_timer}, Acc) ->
    encode_tlv(146, <<M_timer:32>>, Acc);

encode_v1_element(#tp_packet_measurement{} = IE, Acc) ->
    encode_tlv({18681,1}, encode_volume_threshold(IE), Acc);

encode_v1_element(IEs, Acc) when is_list(IEs) ->
    encode_v1(IEs, Acc);

encode_v1_element({Tag, Value}, Acc) when is_binary(Value) ->
    encode_tlv(Tag, Value, Acc).

?PRETTY_PRINT(pretty_print_v1, create_pdr);
?PRETTY_PRINT(pretty_print_v1, pdi);
?PRETTY_PRINT(pretty_print_v1, create_far);
?PRETTY_PRINT(pretty_print_v1, forwarding_parameters);
?PRETTY_PRINT(pretty_print_v1, duplicating_parameters);
?PRETTY_PRINT(pretty_print_v1, create_urr);
?PRETTY_PRINT(pretty_print_v1, create_qer);
?PRETTY_PRINT(pretty_print_v1, created_pdr);
?PRETTY_PRINT(pretty_print_v1, update_pdr);
?PRETTY_PRINT(pretty_print_v1, update_far);
?PRETTY_PRINT(pretty_print_v1, update_forwarding_parameters);
?PRETTY_PRINT(pretty_print_v1, update_bar_response);
?PRETTY_PRINT(pretty_print_v1, update_urr);
?PRETTY_PRINT(pretty_print_v1, update_qer);
?PRETTY_PRINT(pretty_print_v1, remove_pdr);
?PRETTY_PRINT(pretty_print_v1, remove_far);
?PRETTY_PRINT(pretty_print_v1, remove_urr);
?PRETTY_PRINT(pretty_print_v1, remove_qer);
?PRETTY_PRINT(pretty_print_v1, pfcp_cause);
?PRETTY_PRINT(pretty_print_v1, source_interface);
?PRETTY_PRINT(pretty_print_v1, f_teid);
?PRETTY_PRINT(pretty_print_v1, network_instance);
?PRETTY_PRINT(pretty_print_v1, sdf_filter);
?PRETTY_PRINT(pretty_print_v1, application_id);
?PRETTY_PRINT(pretty_print_v1, gate_status);
?PRETTY_PRINT(pretty_print_v1, mbr);
?PRETTY_PRINT(pretty_print_v1, gbr);
?PRETTY_PRINT(pretty_print_v1, qer_correlation_id);
?PRETTY_PRINT(pretty_print_v1, precedence);
?PRETTY_PRINT(pretty_print_v1, transport_level_marking);
?PRETTY_PRINT(pretty_print_v1, volume_threshold);
?PRETTY_PRINT(pretty_print_v1, time_threshold);
?PRETTY_PRINT(pretty_print_v1, monitoring_time);
?PRETTY_PRINT(pretty_print_v1, subsequent_volume_threshold);
?PRETTY_PRINT(pretty_print_v1, subsequent_time_threshold);
?PRETTY_PRINT(pretty_print_v1, inactivity_detection_time);
?PRETTY_PRINT(pretty_print_v1, reporting_triggers);
?PRETTY_PRINT(pretty_print_v1, redirect_information);
?PRETTY_PRINT(pretty_print_v1, report_type);
?PRETTY_PRINT(pretty_print_v1, offending_ie);
?PRETTY_PRINT(pretty_print_v1, forwarding_policy);
?PRETTY_PRINT(pretty_print_v1, destination_interface);
?PRETTY_PRINT(pretty_print_v1, up_function_features);
?PRETTY_PRINT(pretty_print_v1, apply_action);
?PRETTY_PRINT(pretty_print_v1, downlink_data_service_information);
?PRETTY_PRINT(pretty_print_v1, downlink_data_notification_delay);
?PRETTY_PRINT(pretty_print_v1, dl_buffering_duration);
?PRETTY_PRINT(pretty_print_v1, dl_buffering_suggested_packet_count);
?PRETTY_PRINT(pretty_print_v1, sxsmreq_flags);
?PRETTY_PRINT(pretty_print_v1, sxsrrsp_flags);
?PRETTY_PRINT(pretty_print_v1, load_control_information);
?PRETTY_PRINT(pretty_print_v1, sequence_number);
?PRETTY_PRINT(pretty_print_v1, metric);
?PRETTY_PRINT(pretty_print_v1, overload_control_information);
?PRETTY_PRINT(pretty_print_v1, timer);
?PRETTY_PRINT(pretty_print_v1, pdr_id);
?PRETTY_PRINT(pretty_print_v1, f_seid);
?PRETTY_PRINT(pretty_print_v1, application_id_pfds);
?PRETTY_PRINT(pretty_print_v1, pfd_context);
?PRETTY_PRINT(pretty_print_v1, node_id);
?PRETTY_PRINT(pretty_print_v1, pfd_contents);
?PRETTY_PRINT(pretty_print_v1, measurement_method);
?PRETTY_PRINT(pretty_print_v1, usage_report_trigger);
?PRETTY_PRINT(pretty_print_v1, measurement_period);
?PRETTY_PRINT(pretty_print_v1, fq_csid);
?PRETTY_PRINT(pretty_print_v1, volume_measurement);
?PRETTY_PRINT(pretty_print_v1, duration_measurement);
?PRETTY_PRINT(pretty_print_v1, application_detection_information);
?PRETTY_PRINT(pretty_print_v1, time_of_first_packet);
?PRETTY_PRINT(pretty_print_v1, time_of_last_packet);
?PRETTY_PRINT(pretty_print_v1, quota_holding_time);
?PRETTY_PRINT(pretty_print_v1, dropped_dl_traffic_threshold);
?PRETTY_PRINT(pretty_print_v1, volume_quota);
?PRETTY_PRINT(pretty_print_v1, time_quota);
?PRETTY_PRINT(pretty_print_v1, start_time);
?PRETTY_PRINT(pretty_print_v1, end_time);
?PRETTY_PRINT(pretty_print_v1, query_urr);
?PRETTY_PRINT(pretty_print_v1, usage_report_smr);
?PRETTY_PRINT(pretty_print_v1, usage_report_sdr);
?PRETTY_PRINT(pretty_print_v1, usage_report_srr);
?PRETTY_PRINT(pretty_print_v1, urr_id);
?PRETTY_PRINT(pretty_print_v1, linked_urr_id);
?PRETTY_PRINT(pretty_print_v1, downlink_data_report);
?PRETTY_PRINT(pretty_print_v1, outer_header_creation);
?PRETTY_PRINT(pretty_print_v1, create_bar);
?PRETTY_PRINT(pretty_print_v1, update_bar_request);
?PRETTY_PRINT(pretty_print_v1, remove_bar);
?PRETTY_PRINT(pretty_print_v1, bar_id);
?PRETTY_PRINT(pretty_print_v1, cp_function_features);
?PRETTY_PRINT(pretty_print_v1, usage_information);
?PRETTY_PRINT(pretty_print_v1, application_instance_id);
?PRETTY_PRINT(pretty_print_v1, flow_information);
?PRETTY_PRINT(pretty_print_v1, ue_ip_address);
?PRETTY_PRINT(pretty_print_v1, packet_rate);
?PRETTY_PRINT(pretty_print_v1, outer_header_removal);
?PRETTY_PRINT(pretty_print_v1, recovery_time_stamp);
?PRETTY_PRINT(pretty_print_v1, dl_flow_level_marking);
?PRETTY_PRINT(pretty_print_v1, header_enrichment);
?PRETTY_PRINT(pretty_print_v1, error_indication_report);
?PRETTY_PRINT(pretty_print_v1, measurement_information);
?PRETTY_PRINT(pretty_print_v1, node_report_type);
?PRETTY_PRINT(pretty_print_v1, user_plane_path_failure_report);
?PRETTY_PRINT(pretty_print_v1, remote_gtp_u_peer);
?PRETTY_PRINT(pretty_print_v1, ur_seqn);
?PRETTY_PRINT(pretty_print_v1, update_duplicating_parameters);
?PRETTY_PRINT(pretty_print_v1, activate_predefined_rules);
?PRETTY_PRINT(pretty_print_v1, deactivate_predefined_rules);
?PRETTY_PRINT(pretty_print_v1, far_id);
?PRETTY_PRINT(pretty_print_v1, qer_id);
?PRETTY_PRINT(pretty_print_v1, oci_flags);
?PRETTY_PRINT(pretty_print_v1, sx_association_release_request);
?PRETTY_PRINT(pretty_print_v1, graceful_release_period);
?PRETTY_PRINT(pretty_print_v1, pdn_type);
?PRETTY_PRINT(pretty_print_v1, failed_rule_id);
?PRETTY_PRINT(pretty_print_v1, time_quota_mechanism);
?PRETTY_PRINT(pretty_print_v1, user_plane_ip_resource_information);
?PRETTY_PRINT(pretty_print_v1, user_plane_inactivity_timer);
?PRETTY_PRINT(pretty_print_v1, aggregated_urrs);
?PRETTY_PRINT(pretty_print_v1, multiplier);
?PRETTY_PRINT(pretty_print_v1, aggregated_urr_id);
?PRETTY_PRINT(pretty_print_v1, subsequent_volume_quota);
?PRETTY_PRINT(pretty_print_v1, subsequent_time_quota);
?PRETTY_PRINT(pretty_print_v1, rqi);
?PRETTY_PRINT(pretty_print_v1, qfi);
?PRETTY_PRINT(pretty_print_v1, query_urr_reference);
?PRETTY_PRINT(pretty_print_v1, additional_usage_reports_information);
?PRETTY_PRINT(pretty_print_v1, create_traffic_endpoint);
?PRETTY_PRINT(pretty_print_v1, created_traffic_endpoint);
?PRETTY_PRINT(pretty_print_v1, update_traffic_endpoint);
?PRETTY_PRINT(pretty_print_v1, remove_traffic_endpoint);
?PRETTY_PRINT(pretty_print_v1, traffic_endpoint_id);
?PRETTY_PRINT(pretty_print_v1, ethernet_packet_filter);
?PRETTY_PRINT(pretty_print_v1, mac_address);
?PRETTY_PRINT(pretty_print_v1, c_tag);
?PRETTY_PRINT(pretty_print_v1, s_tag);
?PRETTY_PRINT(pretty_print_v1, ethertype);
?PRETTY_PRINT(pretty_print_v1, proxying);
?PRETTY_PRINT(pretty_print_v1, ethernet_filter_id);
?PRETTY_PRINT(pretty_print_v1, ethernet_filter_properties);
?PRETTY_PRINT(pretty_print_v1, suggested_buffering_packets_count);
?PRETTY_PRINT(pretty_print_v1, user_id);
?PRETTY_PRINT(pretty_print_v1, ethernet_pdu_session_information);
?PRETTY_PRINT(pretty_print_v1, ethernet_traffic_information);
?PRETTY_PRINT(pretty_print_v1, mac_addresses_detected);
?PRETTY_PRINT(pretty_print_v1, mac_addresses_removed);
?PRETTY_PRINT(pretty_print_v1, ethernet_inactivity_timer);
?PRETTY_PRINT(pretty_print_v1, tp_packet_measurement);
pretty_print_v1(_, _) ->
    no.
