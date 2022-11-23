%% This Source Code Form is subject to the terms of the Mozilla Public
%% License, v. 2.0. If a copy of the MPL was not distributed with this
%% file, You can obtain one at http://mozilla.org/MPL/2.0/.

%% Copyright 2017-2019 Travelping GmbH <info@travelping.com>

-module(pfcp_packet).

-export([encode/1, encode_ies/1,
	 decode/1, decode/2, decode_ies/1, decode_ies/2,
	 msg_description_v1/1, to_map/1, ies_to_map/1]).
-export([validate/2]).
-export([pretty_print/1]).

-compile([{parse_transform, cut}, bin_opt_info]).
-compile({inline,[decode_fqdn/1, maybe/4,
		  decode_v1_grouped/1]}).

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

%%%===================================================================
%%% Validation
%%%===================================================================

validate(API, #pfcp{type = Type, ie = IEs}) ->
    V = maps:get(Type, maps:get(API, v1_msg_defs())),
    validate(API, Type, IEs, V).

validate(API, Type, Key, {P, Grp} = Present, IEs) when is_list(IEs) ->
    case lists:keytake(Key, 1, IEs) of
	{value, Value, IEsRest}
	  when P =:= 'M'; P =:= 'O'; P =:= 'C' ->
	    validate_grp(API, Type, Value, Grp),
	    validate(API, Type, Key, {'O', Grp}, IEsRest);
	{value, Value, _} ->
	    error(badarg, [API, Type, Present, Key, Value]);
	false when P =:= 'M' ->
	    error(badarg, [API, Type, Present, Key]);
	false ->
	    IEs
    end;
validate(API, Type, Key, {P, Grp} = Present, IEs) when is_map(IEs) ->
    case maps:take(Key, IEs) of
	{[], _} when P =:= 'M' ->
	    error(badarg, [API, Type, Present, Key, []]);
	{Value, IEsRest}
	  when P =:= 'M'; P =:= 'O'; P =:= 'C' ->
	    validate_grp(API, Type, Value, Grp),
	    IEsRest;
	{Value, _} when Value =/= [] ->
	    error(badarg, [API, Type, Present, Key, Value]);
	error when P =:= 'M' ->
	    error(badarg, [API, Type, Present, Key]);
	error ->
	    IEs
    end.

validate_grp(API, Type, IEs, V)
  when is_list(IEs) ->
    lists:foreach(fun(IE) -> validate_grp(API, Type, IE, V) end, IEs);
validate_grp(API, Type, IE, Atom)
  when is_atom(Atom) andalso element(1, IE) =:= Atom ->
    ok;
validate_grp(API, Type, {_, Group}, V)
  when (is_list(Group) orelse is_map(Group)) andalso is_map(V) ->
    validate(API, Type, Group, V);
validate_grp(API, Type, IE, V) ->
    error(badarg, [API, Type, IE, V]).

validate(API, Type, IEs, V) ->
    Rest = maps:fold(validate(API, Type, _, _, _), IEs, V),
    if is_map(Rest) ->
	    RRest = maps:filter(fun(_, Value) -> Value =/= [] end, Rest),
	    maps:size(RRest) /= 0 andalso error(badarg, [API, Type, RRest]),
	    ok;
       is_list(Rest) ->
	    length(Rest) /= 0 andalso error(badarg, [API, Type, Rest]),
	    ok
    end.

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

%% only intended for domain names, no support for anything outside
%% of the allowed character range
to_lower_char(C) when C >= $A andalso C =< $Z ->
    C bor 16#20;
to_lower_char(C) -> C.

to_lower(BinStr) when is_binary(BinStr) ->
    << << (to_lower_char(C)) >> || << C >> <= BinStr >>.

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

bool2int(false) -> 0;
bool2int(true)  -> 1.

%% =============================================

%% decoder funs for optional fields
maybe(Bin, 0, _Fun, IE) ->
    {IE, Bin};
maybe(Bin, 1, Fun, IE) ->
    Fun(Bin, IE).

len(Bin, Size, Fun, Pos, IE) ->
    <<Len:Size/integer, V:Len/bytes, Rest/binary>> = Bin,
    {setelement(Pos, IE, Fun(V)), Rest}.

bin(Bin, Len, Pos, IE) ->
    <<V:Len/bytes, Rest/binary>> = Bin,
    {setelement(Pos, IE, V), Rest}.

float(Bin, Size, Pos, IE) ->
    <<Int:Size/integer, Frac:Size/integer, Rest/binary>> = Bin,
    V = Int + Frac / (1 bsl 32),
    {setelement(Pos, IE, V), Rest}.

int(Bin, Len, Pos, IE) ->
    <<V:Len/integer, Rest/binary>> = Bin,
    {setelement(Pos, IE, V), Rest}.

enum(Bin, Len, Enum, Pos, IE) ->
    <<V:Len/integer, Rest/binary>> = Bin,
    {setelement(Pos, IE, Enum(V)), Rest}.

spare(Bin, Len, IE) ->
    <<_:Len, Rest/bitstring>> = Bin,
    {IE, Rest}.

%% length_bin(Bin, LenSize, Pos, IE) ->
%%     <<Len:LenSize/integer, Rest/binary>> = Bin,
%%     bin(Rest, Len, Pos, IE).

%% encoder funs for optional fields
maybe(true, Fun, IE) -> Fun(IE);
maybe(_, _, IE)      -> IE.

int(Int, Size, IE) ->
    <<IE/binary, Int:Size>>.

float(F, Size, IE) ->
    Int = trunc(F),
    Frac = round((F - Int) * (1 bsl 32)),
    <<IE/binary, Int:Size, Frac:Size>>.
bin(Bin, Size, IE) ->
    <<IE/binary, Bin:Size/bytes>>.

len(Size, Bin, IE) ->
    <<IE/binary, (byte_size(Bin)):Size/integer, Bin/binary>>.

%% spare(Len, IE) ->
%%     <<IE/binary, 0:Len>>.

%% =============================================

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
maybe_bin(_, _, IE) ->
    IE.

maybe_len_bin(<<Bin/binary>>, F, _, _, IE) when F =:= 0; F =:= false ->
    {IE, Bin};
maybe_len_bin(<<Bin/binary>>, F, Size, Pos, IE) when F =/= 0 ->
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

encode_min_int(Min, Int, little) ->
    case binary:encode_unsigned(Int, little) of
	B when bit_size(B) >= Min -> B;
	_ -> <<Int:Min/little>>
    end.

decode_v1(<<>>, IEs) ->
    IEs;
decode_v1(<<0:1, Type:15/integer, Length:16/integer, Data:Length/bytes, Next/binary>>, IEs) ->
    IE = decode_v1_element(Data, Type),
    decode_v1(Next, put_ie(IE, IEs));
decode_v1(<<1:1, Type:15/integer, Length:16/integer, EnterpriseId:16/integer,
	    Rest0/binary>>, IEs) ->
    DLen = Length - 2,
    <<Data:DLen/binary, Next/binary>> = Rest0,
    IE = decode_v1_element(Data, {EnterpriseId, Type}),
    decode_v1(Next, put_ie(IE, IEs));
decode_v1(Data, IEs) ->
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

decode_tbcd(Bin) ->
    decode_tbcd(Bin, <<>>).

tbcd_to_string(10)  -> $*;
tbcd_to_string(11)  -> $#;
tbcd_to_string(12)  -> $a;
tbcd_to_string(13)  -> $b;
tbcd_to_string(14)  -> $c;
tbcd_to_string(BCD) -> BCD + $0.

decode_tbcd(<<>>, BCD) ->
    BCD;
decode_tbcd(<<_:4, 15:4, _/binary>>, BCD) ->
    BCD;
decode_tbcd(<<15:4, Lo:4, _/binary>>, BCD) ->
    <<BCD/binary, (tbcd_to_string(Lo))>>;
decode_tbcd(<<Hi:4, Lo:4, Next/binary>>, BCD) ->
    decode_tbcd(Next, <<BCD/binary, (tbcd_to_string(Lo)), (tbcd_to_string(Hi))>>).

encode_tbcd(Number) ->
    encode_tbcd(Number, <<>>).

string_to_tbcd($*) -> 10;
string_to_tbcd($#) -> 11;
string_to_tbcd($a) -> 12;
string_to_tbcd($b) -> 13;
string_to_tbcd($c) -> 14;
string_to_tbcd(15) -> 15;
string_to_tbcd(BCD) -> BCD - $0.

encode_tbcd(<<>>, BCD) ->
    BCD;
encode_tbcd(<<D:8>>, BCD) ->
    <<BCD/binary, 2#1111:4, (string_to_tbcd(D)):4>>;
encode_tbcd(<<H:8, L:8, Next/binary>>, BCD) ->
    encode_tbcd(Next, <<BCD/binary, (string_to_tbcd(L)):4, (string_to_tbcd(H)):4>>).

decode_mcc(<<MCCHi:8, _:4, MCC3:4, _:8>>) ->
    decode_tbcd(<<MCCHi:8, 15:4, MCC3:4>>).

decode_mnc(<<_:8, MNC3:4, _:4, MNCHi:8>>) ->
    decode_tbcd(<<MNCHi:8, 15:4, MNC3:4>>).

encode_mccmnc(MCC, MNC) ->
    [MCC1, MCC2, MCC3 | _] = [ string_to_tbcd(X) || <<X:8>> <= MCC] ++ [15,15,15],
    [MNC1, MNC2, MNC3 | _] = [ string_to_tbcd(X) || <<X:8>> <= MNC] ++ [15,15,15],
    <<MCC2:4, MCC1:4, MNC3:4, MCC3:4, MNC2:4, MNC1:4>>.

decode_flags(<<>>, _, Acc) ->
    Acc;
decode_flags(<<_:1, Next/bits>>, ['_' | Flags], Acc) ->
    decode_flags(Next, Flags, Acc);
decode_flags(<<1:1, Next/bits>>, [F | Flags], Acc) ->
    decode_flags(Next, Flags, [{F, []} | Acc]);
decode_flags(<<_:1, Next/bits>>, [_ | Flags], Acc) ->
    decode_flags(Next, Flags, Acc);
decode_flags(Bin, [], Acc) ->
    case binary:decode_unsigned(Bin, little) of
	0 -> Acc;
	Value -> [{undecoded, Value}|Acc]
    end.

decode_flags(Bin, Flags) ->
    maps:from_list(decode_flags(Bin, Flags, [])).

encode_flags(Set, []) ->
    maps:get(undecoded, Set, 0);
encode_flags(Set, [F | N]) ->
    bool2int(is_map_key(F, Set)) + encode_flags(Set, N) * 2.

decode_network_instance(Instance) ->
    to_lower(Instance).

encode_network_instance(Instance) ->
    Instance.

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

decode_fqdn(FQDN) ->
    [ to_lower(Part) || <<Len:8, Part:Len/bytes>> <= FQDN ].

encode_fqdn(FQDN) ->
    << <<(size(Part)):8, Part/binary>> || Part <- FQDN >>.

decode_sdf_filter(<<_:3, BID:1, FL:1, SPI:1, TTC:1, FD:1, _Spare1:8, Rest0/binary>>, _Type) ->
    IE0 = #sdf_filter{},
    {IE1, Rest1} = maybe_len_bin(Rest0, FD, 16, #sdf_filter.flow_description, IE0),
    {IE2, Rest2} = maybe_unsigned_integer(Rest1, TTC, 16, #sdf_filter.tos_traffic_class, IE1),
    {IE3, Rest3} = maybe_unsigned_integer(Rest2, SPI, 32,
					  #sdf_filter.security_parameter_index, IE2),
    {IE4, Rest4} = maybe_unsigned_integer(Rest3, FL, 24, #sdf_filter.flow_label, IE3),
    {IE5, _Rest} = maybe_unsigned_integer(Rest4, BID, 32, #sdf_filter.filter_id, IE4),
    IE5.

encode_sdf_filter(#sdf_filter{
		     flow_description = FD, tos_traffic_class = TTC,
		     security_parameter_index = SPI,
		     flow_label = FL, filter_id = BID}) ->
    IE0 = <<0:3, (is_set(BID)):1,
	    (is_set(FL)):1, (is_set(SPI)):1, (is_set(TTC)):1, (is_set(FD)):1, 0:8>>,
    IE1 = maybe_len_bin(FD, 16, IE0),
    IE2 = maybe_unsigned_integer(TTC, 16, IE1),
    IE3 = maybe_unsigned_integer(SPI, 32, IE2),
    IE4 = maybe_unsigned_integer(FL, 24, IE3),
    maybe_unsigned_integer(BID, 32, IE4).

decode_volume_measurement(<<_:2, DLNOP:1, ULNOP:1, TONOP:1,
			  DLVOL:1, ULVOL:1, TOVOL:1, Rest0/binary>>, _Type) ->
    IE0 = #volume_measurement{},
    {IE1, Rest1} = maybe_unsigned_integer(Rest0, TOVOL, 64, #volume_measurement.total, IE0),
    {IE2, Rest2} = maybe_unsigned_integer(Rest1, ULVOL, 64, #volume_measurement.uplink, IE1),
    {IE3, Rest3} = maybe_unsigned_integer(Rest2, DLVOL, 64, #volume_measurement.downlink, IE2),
    {IE4, Rest4} =
	maybe_unsigned_integer(Rest3, TONOP, 64, #volume_measurement.total_pkts, IE3),
    {IE5, Rest5} =
	maybe_unsigned_integer(Rest4, ULNOP, 64, #volume_measurement.uplink_pkts, IE4),
    {IE6, _Rest} =
	maybe_unsigned_integer(Rest5, DLNOP, 64, #volume_measurement.downlink_pkts, IE5),
    IE6.

encode_volume_measurement(#volume_measurement{
			    total = Total, uplink = UL, downlink = DL,
			    total_pkts = TotalPkts, uplink_pkts = UlPkts,
			    downlink_pkts = DlPkts}) ->
    IE0 = <<0:2, (is_set(DlPkts)):1, (is_set(UlPkts)):1, (is_set(TotalPkts)):1,
	    (is_set(DL)):1, (is_set(UL)):1, (is_set(Total)):1>>,
    IE1 = maybe_unsigned_integer(Total, 64, IE0),
    IE2 = maybe_unsigned_integer(UL, 64, IE1),
    IE3 = maybe_unsigned_integer(DL, 64, IE2),
    IE4 = maybe_unsigned_integer(TotalPkts, 64, IE3),
    IE5 = maybe_unsigned_integer(UlPkts, 64, IE4),
    maybe_unsigned_integer(DlPkts, 64, IE5).

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

decode_downlink_data_service_information(<<_:6, QFI:1, PPI:1, Rest0/binary>>, _Type) ->
    IE0 = #downlink_data_service_information{},
    {IE1, Rest1} = maybe_unsigned_integer(Rest0, PPI, 8,
					  #downlink_data_service_information.value, IE0),
    {IE2, _Rest} = maybe_unsigned_integer(Rest1, QFI, 8,
					   #downlink_data_service_information.qfi, IE1),
    IE2.

encode_downlink_data_service_information(#downlink_data_service_information{
					    value = Value, qfi = QFI}) ->
    IE0 = <<0:6, (is_set(QFI)):1, (is_set(Value)):1>>,
    IE1 = maybe_unsigned_integer(Value, 8, IE0),
    _IE = maybe_unsigned_integer(QFI, 8, IE1).

%% decode dl_buffering_suggested_packet_count
decode_dl_buffering_suggested_packet_count(<<Count:8/integer>>, _Type) ->
    #dl_buffering_suggested_packet_count{count = Count};
decode_dl_buffering_suggested_packet_count(<<Count:16/integer>>, _Type) ->
    #dl_buffering_suggested_packet_count{count = Count}.

encode_dl_buffering_suggested_packet_count(
  #dl_buffering_suggested_packet_count{count = Count}) when Count < 256 ->
    <<Count:8>>;
encode_dl_buffering_suggested_packet_count(
  #dl_buffering_suggested_packet_count{count = Count}) ->
    <<Count:16>>.

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
    #node_id{id = decode_fqdn(FQDN)}.

encode_node_id(#node_id{id = IPv4})
  when is_binary(IPv4), byte_size(IPv4) == 4 ->
    <<0:4, 0:4, IPv4/binary>>;
encode_node_id(#node_id{id = IPv6})
  when is_binary(IPv6), byte_size(IPv6) == 16 ->
    <<0:4, 1:4, IPv6/binary>>;
encode_node_id(#node_id{id = FQDN})
  when is_list(FQDN) ->
    <<0:4, 2:4, (encode_fqdn(FQDN))/binary>>.

decode_pfd_contents(<<ADNP:1, AURL:1, AFD:1, DNP: 1, CP:1, DN:1, URL:1, FD:1, _:8, Rest0/binary>>, _Type) ->
    IE0 = #pfd_contents{},
    {IE1, Rest1} = maybe_len_bin(Rest0, FD, 16, #pfd_contents.flow, IE0),
    {IE2, Rest2} = maybe_len_bin(Rest1, URL, 16, #pfd_contents.url, IE1),
    {IE3, Rest3} = maybe_len_bin(Rest2, DN, 16, #pfd_contents.domain, IE2),
    {IE4, Rest4} = maybe_len_bin(Rest3, CP, 16, #pfd_contents.custom, IE3),
    {IE5, Rest5} = maybe_len_bin(Rest4, DNP, 16, #pfd_contents.dnp, IE4),
    {IE6, Rest6} = maybe_len_bin(Rest5, AFD, 16, #pfd_contents.aflow, IE5),
    {IE7, Rest7} = maybe_len_bin(Rest6, AURL, 16, #pfd_contents.aurl, IE6),
    {IE8, _Rest} = maybe_len_bin(Rest7, ADNP, 16, #pfd_contents.adnp, IE7),
    IE8.

encode_pfd_contents(#pfd_contents{flow = Flow, url = URL,
				  domain = Domain, custom = Custom,
				  dnp = DNP, aflow = AFD,
				  aurl = AURL, adnp = ADNP}) ->
    IE0 = <<(is_set(ADNP)):1, (is_set(AURL)):1,
	    (is_set(AFD)):1, (is_set(DNP)):1,
	    (is_set(Custom)):1, (is_set(Domain)):1,
	    (is_set(URL)):1, (is_set(Flow)):1,
	    0:8>>,
    IE1 = maybe_len_bin(Flow, 16, IE0),
    IE2 = maybe_len_bin(URL, 16, IE1),
    IE3 = maybe_len_bin(Domain, 16, IE2),
    IE4 = maybe_len_bin(Custom, 16, IE3),
    IE5 = maybe_len_bin(DNP, 16, IE4),
    IE6 = maybe_len_bin(AFD, 16, IE5),
    IE7 = maybe_len_bin(AURL, 16, IE6),
    _IE = maybe_len_bin(ADNP, 16, IE7).

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

decode_dropped_dl_traffic_threshold(<<_:6, DLBY:1, DLPA:1, Rest0/binary>>, _Type) ->
    IE0 = #dropped_dl_traffic_threshold{},
    {IE1, Rest1} = maybe_unsigned_integer(Rest0, DLPA, 64,
					   #dropped_dl_traffic_threshold.value, IE0),
    {IE2, _Rest} = maybe_unsigned_integer(Rest1, DLBY, 64,
					   #dropped_dl_traffic_threshold.bytes, IE1),
    IE2.

encode_dropped_dl_traffic_threshold(#dropped_dl_traffic_threshold{
				       value = Value, bytes = DLBY}) ->
    IE0 = <<0:6, (is_set(DLBY)):1, (is_set(Value)):1>>,
    IE1 = maybe_unsigned_integer(Value, 64, IE0),
    _IE = maybe_unsigned_integer(DLBY, 64, IE1).

decode_outer_header_creation(<<S_TAG:1, C_TAG:1, IPv6:1, IPv4:1,
			       UDPv6:1, UDPv4:1, GTPv6:1, GTPv4:1,
			       _:6, N6:1, N19:1, Rest0/binary>>, _Type) ->
    IsIP  = IPv4 bor IPv6,
    IsGTP = GTPv6 bor GTPv4,
    IsUDP = UDPv6 bor UDPv4,
    IsRAW = S_TAG bor C_TAG,

    IE0 = #outer_header_creation{n6 = (N6 =/= 0), n19 = (N19 =/= 0)},
    IE1 =
	if IsGTP =:= 1 ->
		IE0#outer_header_creation{type = 'GTP-U'};
	   IsUDP =:= 1 ->
		IE0#outer_header_creation{type = 'UDP'};
	   IsIP =:= 1 ->
		IE0#outer_header_creation{type = 'IP'};
	   IsRAW =:= 1 ->
		IE0#outer_header_creation{type = 'RAW'};
	   true ->
		IE0
	end,

    IsIP4 = IPv4 bor UDPv4 bor GTPv4,
    IsIP6 = IPv6 bor UDPv6 bor GTPv6,

    {IE2, Rest1} = maybe(Rest0, IsGTP, int(_, 32, #outer_header_creation.teid, _), IE1),
    {IE3, Rest2} = maybe(Rest1, IsIP4, bin(_,  4, #outer_header_creation.ipv4, _), IE2),
    {IE4, Rest3} = maybe(Rest2, IsIP6, bin(_, 16, #outer_header_creation.ipv6, _), IE3),
    {IE5, Rest4} = maybe(Rest3, IsUDP, int(_, 16, #outer_header_creation.port, _), IE4),
    {IE6, Rest5} = maybe(Rest4, C_TAG, bin(_,  3, #outer_header_creation.c_tag, _), IE5),
    {IE7, _Rest} = maybe(Rest5, S_TAG, bin(_,  3, #outer_header_creation.s_tag, _), IE6),
    IE7.

encode_outer_header_creation(#outer_header_creation{n6 = N6, n19 = N19,
						    type = Type, teid = TEID, ipv4 = IPv4, ipv6 = IPv6,
						    port = Port, c_tag = C_TAG, s_tag = S_TAG}) ->
    FlagGTPv6 = Type =:= 'GTP-U' andalso is_binary(IPv6),
    FlagGTPv4 = Type =:= 'GTP-U' andalso is_binary(IPv4),
    FlagUDPv6 = Type =:= 'UDP' andalso is_binary(IPv6),
    FlagUDPv4 = Type =:= 'UDP' andalso is_binary(IPv4),
    FlagIPv6 =  Type =:= 'IP'  andalso is_binary(IPv6),
    FlagIPv4 =  Type =:= 'IP'  andalso is_binary(IPv4),
    FlagS_TAG = Type =:= 'RAW' andalso is_binary(S_TAG),
    FlagC_TAG = Type =:= 'RAW' andalso is_binary(C_TAG),

    IE0 = <<(bool2int(FlagS_TAG)):1, (bool2int(FlagC_TAG)):1,
	    (bool2int(FlagIPv6)):1,  (bool2int(FlagIPv4)):1,
	    (bool2int(FlagUDPv6)):1, (bool2int(FlagUDPv4)):1,
	    (bool2int(FlagGTPv6)):1, (bool2int(FlagGTPv4)):1,
	    0:6, (bool2int(N6)):1, (bool2int(N19)):1>>,

    FlagIP4 = FlagGTPv4 orelse FlagUDPv4 orelse FlagIPv4,
    FlagIP6 = FlagGTPv6 orelse FlagUDPv6 orelse FlagIPv6,

    IE1 = maybe(Type =:= 'GTP-U', int(TEID, 32, _), IE0),
    IE2 = maybe(FlagIP4,          bin(IPv4,  4, _), IE1),
    IE3 = maybe(FlagIP6,          bin(IPv6, 16, _), IE2),
    IE4 = maybe(Type =:= 'UDP',   int(Port, 16, _), IE3),
    IE5 = maybe(FlagC_TAG,        bin(C_TAG, 3, _), IE4),
    _IE = maybe(FlagS_TAG,        bin(S_TAG, 3, _), IE5).

decode_ue_ip_address(<<_:1, IP6PL:1, CHV6:1, CHV4:1, IPv6D:1,
		       Type:1, IPv4:1, IPv6:1, Rest0/binary>>, _Type) ->
    IE0 = if Type =:= 0 -> #ue_ip_address{type = src};
	     true ->       #ue_ip_address{type = dst}
	  end,
    {IE1, Rest1} = if CHV4 =:= 0 -> maybe_bin(Rest0, IPv4, 4, #ue_ip_address.ipv4, IE0);
		      true       -> {IE0#ue_ip_address{ipv4 = choose}, Rest0}
		   end,
    {IE2, Rest2} = if CHV6 =:= 0 -> maybe_bin(Rest1, IPv6, 16, #ue_ip_address.ipv6, IE1);
		      true      -> {IE1#ue_ip_address{ipv6 = choose}, Rest1}
		   end,
    {IE3, Rest3} =
	maybe_unsigned_integer(Rest2, IPv6D, 8, #ue_ip_address.prefix_delegation, IE2),
    {IE4, _Rest} = maybe_unsigned_integer(Rest3, IP6PL, 8, #ue_ip_address.prefix_length, IE3),
    IE4.

encode_ue_ip_address(#ue_ip_address{type = Type, ipv4 = IPv4, ipv6 = IPv6,
				    prefix_delegation = IPv6D, prefix_length = IP6PL}) ->
    SD = case Type of
	     src -> 0;
	     dst -> 1;
	     undefined -> 0
	 end,
    IE0 = <<0:1,
	    (bool2int(is_integer(IP6PL))):1,
	    (is_set(IPv6, choose)):1, (is_set(IPv4, choose)):1,
	    (bool2int(is_integer(IPv6D))):1, SD:1,
	    (bool2int(is_binary(IPv4))):1, (bool2int(is_binary(IPv6))):1>>,
    IE1 = maybe_bin(IPv4, 4, IE0),
    IE2 = maybe_bin(IPv6, 16, IE1),
    IE3 = maybe_unsigned_integer(IPv6D, 8, IE2),
    _IE = maybe_unsigned_integer(IP6PL, 8, IE3).

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

decode_packet_rate(<<_:5, APRC:1, DL:1, UL:1, Rest0/binary>>, _Type) ->
    IE0 = #packet_rate{},
    {IE1, Rest1} = maybe(Rest0, UL, spare(_, 5, _), IE0),
    {IE2, Rest2} = maybe(Rest1, UL, enum(_,  3, fun enum_v1_packet_rate_unit/1,
					 #packet_rate.ul_time_unit, _), IE1),
    {IE3, Rest3} = maybe(Rest2, UL, int(_, 16, #packet_rate.ul_max_packet_rate, _), IE2),
    {IE4, Rest4} = maybe(Rest3, DL, spare(_, 5, _), IE3),
    {IE5, Rest5} = maybe(Rest4, DL, enum(_,  3, fun enum_v1_packet_rate_unit/1,
					 #packet_rate.dl_time_unit, _), IE4),
    {IE6, Rest6} = maybe(Rest5, DL, int(_, 16, #packet_rate.dl_max_packet_rate, _), IE5),
    {IE7, Rest7} = maybe(Rest6, APRC band UL, spare(_, 5, _), IE6),
    {IE8, Rest8} = maybe(Rest7, APRC band UL, enum(_,  3, fun enum_v1_packet_rate_unit/1,
					 #packet_rate.additional_ul_time_unit, _), IE7),
    {IE9, Rest9} = maybe(Rest8, APRC band UL,
			 int(_, 16, #packet_rate.additional_ul_max_packet_rate, _), IE8),
    {IE10, Rest10} = maybe(Rest9, APRC band DL, spare(_, 5, _), IE9),
    {IE11, Rest11} = maybe(Rest10, APRC band DL, enum(_,  3, fun enum_v1_packet_rate_unit/1,
					 #packet_rate.additional_dl_time_unit, _), IE10),
    {IE12, _Rest} = maybe(Rest11, APRC band DL,
			  int(_, 16, #packet_rate.additional_dl_max_packet_rate, _), IE11),
    IE12.

encode_packet_rate(#packet_rate{
		      ul_time_unit = UlUnit, ul_max_packet_rate = UlRate,
		      dl_time_unit = DlUnit, dl_max_packet_rate = DlRate,
		      additional_ul_time_unit = AddUlUnit,
		      additional_ul_max_packet_rate = AddUlRate,
		      additional_dl_time_unit = AddDlUnit,
		      additional_dl_max_packet_rate = AddDlRate}) ->
    FlagUL = UlUnit =/= undefined,
    FlagDL = DlUnit =/= undefined,
    FlagAPRC = (AddUlUnit =/= undefined) or (AddDlUnit =/= undefined),
    IE0 = <<0:5, (bool2int(FlagAPRC)):1, (bool2int(FlagDL)):1, (bool2int(FlagUL)):1>>,
    IE1 = maybe(FlagUL, int(enum_v1_packet_rate_unit(UlUnit), 8, _), IE0),
    IE2 = maybe(FlagUL, int(UlRate, 16, _), IE1),
    IE3 = maybe(FlagDL, int(enum_v1_packet_rate_unit(DlUnit), 8, _), IE2),
    IE4 = maybe(FlagDL, int(DlRate, 16, _), IE3),
    IE5 = maybe(FlagAPRC and FlagUL, int(enum_v1_packet_rate_unit(AddUlUnit), 8, _), IE4),
    IE6 = maybe(FlagAPRC and FlagUL, int(AddUlRate, 16, _), IE5),
    IE7 = maybe(FlagAPRC and FlagDL, int(enum_v1_packet_rate_unit(AddDlUnit), 8, _), IE6),
    _IE = maybe(FlagAPRC and FlagDL, int(AddDlRate, 16, _), IE7).

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

decode_remote_peer(<<_:4, NI:1, DI:1, IPv4:1, IPv6:1, Rest0/binary>>, _Type) ->
    IE0 = #remote_gtp_u_peer{},
    {IE1, Rest1} = maybe_bin(Rest0, IPv4, 4, #remote_gtp_u_peer.ipv4, IE0),
    {IE2, Rest2} = maybe_bin(Rest1, IPv6, 16, #remote_gtp_u_peer.ipv6, IE1),
    {IE3, Rest3} = maybe_len_bin(Rest2, DI, 8, #remote_gtp_u_peer.destination_interface, IE2),
    {IE4, _Rest} = maybe(Rest3, NI, len(_, 8, fun decode_network_instance/1, #remote_gtp_u_peer.network_instance, _), IE3),
    IE4.

encode_remote_peer(#remote_gtp_u_peer{ipv4 = IPv4, ipv6 = IPv6,
				      destination_interface = DI,
				      network_instance = NI}) ->
    IE0 = <<0:4, (bool2int(is_binary(NI))):1, (bool2int(is_binary(DI))):1,
	    (is_set(IPv4)):1, (is_set(IPv6)):1>>,
    IE1 = maybe_bin(IPv4, 4, IE0),
    IE2 = maybe_bin(IPv6, 16, IE1),
    IE3 = maybe_len_bin(DI, 8, IE2),
    _IE = maybe_len_bin(NI, 8, IE3).

decode_failed_rule_id(<<_:3, 0:5, Id:16/integer, _/binary>>, _Type) ->
    #failed_rule_id{type = pdr, id = Id};
decode_failed_rule_id(<<_:3, 1:5, Id:32/integer, _/binary>>, _Type) ->
    #failed_rule_id{type = far, id = Id};
decode_failed_rule_id(<<_:3, 2:5, Id:32/integer, _/binary>>, _Type) ->
    #failed_rule_id{type = qer, id = Id};
decode_failed_rule_id(<<_:3, 3:5, Id:32/integer, _/binary>>, _Type) ->
    #failed_rule_id{type = urr, id = Id};
decode_failed_rule_id(<<_:3, 4:5, Id:8/integer, _/binary>>, _Type) ->
    #failed_rule_id{type = bar, id = Id}.

encode_failed_rule_id(#failed_rule_id{type = pdr, id = Id}) ->
    <<0:3, 0:5, Id:16>>;
encode_failed_rule_id(#failed_rule_id{type = far, id = Id}) ->
    <<0:3, 1:5, Id:32>>;
encode_failed_rule_id(#failed_rule_id{type = qer, id = Id}) ->
    <<0:3, 2:5, Id:32>>;
encode_failed_rule_id(#failed_rule_id{type = urr, id = Id}) ->
    <<0:3, 3:5, Id:32>>;
encode_failed_rule_id(#failed_rule_id{type = bar, id = Id}) ->
    <<0:3, 4:5, Id:8>>.

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
	      network_instance = decode_network_instance(Rest3)};
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

decode_user_id(<<_:4, NAI:1, MSISDN:1, IMEI:1, IMSI:1, Rest0/binary>>, _Type) ->
    IE0 = #user_id{},
    {IE1, Rest1} = maybe(Rest0, IMSI, len(_, 8, fun decode_tbcd/1, #user_id.imsi, _), IE0),
    {IE2, Rest2} = maybe(Rest1, IMEI, len(_, 8, fun decode_tbcd/1, #user_id.imei, _), IE1),
    {IE3, Rest3} = maybe(Rest2, MSISDN, len(_, 8, fun decode_tbcd/1, #user_id.msisdn, _), IE2),
    {IE4, _Rest} = maybe_len_bin(Rest3, NAI, 8, #user_id.nai, IE3),
    IE4.

encode_user_id(#user_id{imsi = IMSI, imei = IMEI, msisdn = MSISDN, nai = NAI}) ->
    FlagIMSI = is_binary(IMSI),
    FlagIMEI = is_binary(IMEI),
    FlagMSISDN = is_binary(MSISDN),
    FlagNAI = is_binary(NAI),

    IE0 = <<0:4, (bool2int(FlagNAI)):1, (bool2int(FlagMSISDN)):1, (bool2int(FlagIMEI)):1, (bool2int(FlagIMSI)):1>>,
    IE1 = maybe(FlagIMSI, len(8, encode_tbcd(IMSI), _), IE0),
    IE2 = maybe(FlagIMEI, len(8, encode_tbcd(IMEI), _), IE1),
    IE3 = maybe(FlagMSISDN, len(8, encode_tbcd(MSISDN), _), IE2),
    _IE = maybe(FlagNAI, len(8, NAI, _), IE3).

decode_mac_addresses(<<MACsCnt:8, Rest0/binary>>, Type) ->
    Size = MACsCnt * 6,
    <<MACsBin:Size/bytes, Rest1/binary>> = Rest0,
    MACs = [X || <<X:6/bytes>> <= MACsBin],

    IE1 = {Type, MACs, undefined, undefined},
    {IE2, Rest2} = maybe_len_bin(Rest1, size(Rest1) > 0, 8, 3, IE1),
    {IE3, _Rest} = maybe_len_bin(Rest2, size(Rest2) > 0, 8, 4, IE2),
    IE3.

encode_mac_addresses({_Type, MACs, C_TAG, S_TAG}) ->
    IE0 = <<(length(MACs)):8/integer, (<< <<X:6/bytes>> || X <- MACs>>)/binary>>,
    IE1 = maybe_len_bin(C_TAG, 8, IE0),
    _IE = maybe_len_bin(S_TAG, 8, IE1).

decode_alternative_smf_ip_address(<<_:6, IPv4:1, IPv6:1, Rest0/binary>>, _Type) ->
    IE0 = #alternative_smf_ip_address{},
    {IE1, Rest1} = maybe(Rest0, IPv4, bin(_,  4, #alternative_smf_ip_address.ipv4, _), IE0),
    {IE2, _Rest} = maybe(Rest1, IPv6, bin(_, 16, #alternative_smf_ip_address.ipv6, _), IE1),
    IE2.

encode_alternative_smf_ip_address(#alternative_smf_ip_address{ipv4 = IPv4, ipv6 = IPv6}) ->
    FlagIPv4 = is_binary(IPv4),
    FlagIPv6 = is_binary(IPv6),

    IE0 = <<0:6, (bool2int(FlagIPv4)):1, (bool2int(FlagIPv6)):1>>,
    IE1 = maybe(FlagIPv4, bin(IPv4,  4, _), IE0),
    _IE = maybe(FlagIPv6, bin(IPv6, 16, _), IE1).

decode_cp_pfcp_entity_ip_address(<<_:6, IPv4:1, IPv6:1, Rest0/binary>>, _Type) ->
    IE0 = #cp_pfcp_entity_ip_address{},
    {IE1, Rest1} = maybe(Rest0, IPv4, bin(_,  4, #cp_pfcp_entity_ip_address.ipv4, _), IE0),
    {IE2, _Rest} = maybe(Rest1, IPv6, bin(_, 16, #cp_pfcp_entity_ip_address.ipv6, _), IE1),
    IE2.

encode_cp_pfcp_entity_ip_address(#cp_pfcp_entity_ip_address{ipv4 = IPv4, ipv6 = IPv6}) ->
    FlagIPv4 = is_binary(IPv4),
    FlagIPv6 = is_binary(IPv6),

    IE0 = <<0:6, (bool2int(FlagIPv4)):1, (bool2int(FlagIPv6)):1>>,
    IE1 = maybe(FlagIPv4, bin(IPv4,  4, _), IE0),
    _IE = maybe(FlagIPv6, bin(IPv6, 16, _), IE1).

decode_ip_multicast_address(<<_:4, 1:1, _:1, 0:1, 0:1, _/binary>>, _Type) ->
    #ip_multicast_address{ip = any};
decode_ip_multicast_address(<<_:4, 0:1, 0:1, 1:1, 0:1,
			      Start:4/bytes, _/binary>>, _Type) ->
    %% IPv4, single IP
    #ip_multicast_address{ip = Start};
decode_ip_multicast_address(<<_:4, 0:1, 1:1, 1:1, 0:1,
			      Start:4/bytes, End:4/bytes, _/binary>>, _Type) ->
    %% IPv4, range
    #ip_multicast_address{ip = {Start, End}};
decode_ip_multicast_address(<<_:4, 0:1, 0:1, 0:1, 1:1,
			      Start:16/bytes, _/binary>>, _Type) ->
    %% IPv6, single IP
    #ip_multicast_address{ip = Start};
decode_ip_multicast_address(<<_:4, 0:1, 1:1, 0:1, 1:1,
			      Start:16/bytes, End:16/bytes, _/binary>>, _Type) ->
    %% IPv6, range
    #ip_multicast_address{ip = {Start, End}}.

encode_ip_multicast_address(#ip_multicast_address{ip = any}) ->
    <<0:4, 1:1, 0:1, 0:1, 0:1>>;
encode_ip_multicast_address(#ip_multicast_address{ip = Start})
  when is_binary(Start), size(Start) == 4 ->
    <<0:4, 0:1, 0:1, 1:1, 0:1, Start/binary>>;
encode_ip_multicast_address(#ip_multicast_address{ip = {Start, End}})
  when is_binary(Start), size(Start) == 4,
       is_binary(End),   size(End)   == 4 ->
    <<0:4, 0:1, 1:1, 1:1, 0:1, Start/binary, End/binary>>;
encode_ip_multicast_address(#ip_multicast_address{ip = Start})
  when is_binary(Start), size(Start) == 16 ->
    <<0:4, 0:1, 0:1, 0:1, 1:1, Start/binary>>;
encode_ip_multicast_address(#ip_multicast_address{ip = {Start, End}})
  when is_binary(Start), size(Start) == 16,
       is_binary(End),   size(End)   == 16 ->
    <<0:4, 0:1, 1:1, 0:1, 1:1, Start/binary, End/binary>>.

decode_source_ip_address(IP, 1, <<MPL:8, _Rest/binary>>) ->
    #source_ip_address{ip = {IP, MPL}};
decode_source_ip_address(IP, 0, _Rest) ->
    #source_ip_address{ip = IP}.

decode_source_ip_address(<<_:5, MPL:1, 1:1, 0:1, IP:4/bytes, Rest0/binary>>, _Type) ->
    decode_source_ip_address(IP, MPL, Rest0);
decode_source_ip_address(<<_:5, MPL:1, 0:1, 1:1, IP:16/bytes, Rest0/binary>>, _Type) ->
    decode_source_ip_address(IP, MPL, Rest0).

encode_source_ip_address(IP, MPL) ->
    FlagMPL = is_integer(MPL),
    IPv4v6 = size(IP) == 4,

    IE0 = <<0:5, (bool2int(FlagMPL)):1, (bool2int(IPv4v6)):1,
	    (bool2int(not IPv4v6)):1, IP/binary>>,
    _IE = maybe(FlagMPL, int(MPL, 8, _), IE0).

encode_source_ip_address(#source_ip_address{ip = {IP, MPL}}) ->
    encode_source_ip_address(IP, MPL);
encode_source_ip_address(#source_ip_address{ip = IP}) ->
    encode_source_ip_address(IP, undefined).

decode_packet_rate_status(<<_:5, APR:1, DL:1, UL:1, Rest0/binary>>, _Type) ->
    IE0 = #packet_rate_status{},
    {IE1, Rest1} =
	maybe(Rest0, UL,
	      int(_, 16, #packet_rate_status.remaining_uplink_packets_allowed, _), IE0),
    {IE2, Rest2} =
	maybe(Rest1, DL,
	      int(_, 16, #packet_rate_status.remaining_downlink_packets_allowed, _), IE1),
    {IE3, Rest3} =
	maybe(Rest2, UL band APR,
	      int(_, 16, #packet_rate_status.remaining_additional_uplink_packets_allowed, _), IE2),
    {IE4, Rest4} =
	maybe(Rest3, DL band APR,
	      int(_, 16, #packet_rate_status.remaining_additional_downlink_packets_allowed, _), IE3),
    {IE5, _Rest} =
	maybe(Rest4, UL bor DL, float(_, 32, #packet_rate_status.validity_time, _), IE4),
    IE5.

encode_packet_rate_status(#packet_rate_status{
			     remaining_uplink_packets_allowed = UL,
			     remaining_downlink_packets_allowed = DL,
			     remaining_additional_uplink_packets_allowed = AUL,
			     remaining_additional_downlink_packets_allowed = ADL,
			     validity_time = Time
			    }) ->
    FlagUL = is_integer(UL),
    FlagDL = is_integer(DL),
    FlagAPR = is_integer(AUL) orelse is_integer(ADL),

    IE0 = <<0:5, (bool2int(FlagAPR)):1, (bool2int(FlagDL)):1, (bool2int(FlagUL)):1>>,
    IE1 = maybe(FlagUL, int(UL, 16, _), IE0),
    IE2 = maybe(FlagDL, int(DL, 16, _), IE1),
    IE3 = maybe(FlagUL and FlagAPR, int(AUL, 16, _), IE2),
    IE4 = maybe(FlagDL and FlagAPR, int(ADL, 16, _), IE3),
    _IE = maybe(FlagUL or FlagDL, float(Time, 32, _), IE4).

decode_tsn_bridge_id(<<_:7, MAC:1, Rest0/binary>>, _Type) ->
    IE0 = #tsn_bridge_id{},
    {IE1, _Rest} = maybe(Rest0, MAC, bin(_, 6, #tsn_bridge_id.mac, _), IE0),
    IE1.

encode_tsn_bridge_id(#tsn_bridge_id{mac = MAC}) ->
    FlagMAC = is_binary(MAC),

    IE0 = <<0:7, (bool2int(FlagMAC)):1>>,
    _IE = maybe(FlagMAC, bin(MAC, 6, _), IE0).

decode_mptcp_address_information(<<_:6, IPv6:1, IPv4:1, Type:8, Port:16, Rest0/binary>>, _Type) ->
    IE0 = #mptcp_address_information{proxy_type = Type, proxy_port = Port},
    {IE1, Rest1} = maybe(Rest0, IPv4, bin(_,  4, #mptcp_address_information.ipv4, _), IE0),
    {IE2, _Rest} = maybe(Rest1, IPv6, bin(_, 16, #mptcp_address_information.ipv6, _), IE1),
    IE2.

encode_mptcp_address_information(#mptcp_address_information{
				    proxy_type = Type, proxy_port = Port,
				    ipv4 = IPv4, ipv6 = IPv6}) ->
    FlagIPv4 = is_binary(IPv4),
    FlagIPv6 = is_binary(IPv6),

    IE0 = <<0:6, (bool2int(FlagIPv6)):1, (bool2int(FlagIPv4)):1, Type, Port:16>>,
    IE1 = maybe(FlagIPv4, bin(IPv4,  4, _), IE0),
    _IE = maybe(FlagIPv6, bin(IPv6, 16, _), IE1).

decode_ue_link_specific_ip_address(<<_:4, NV6:1, NV4:1, V6:1, V4:1, Rest0/binary>>, _Type) ->
    IE0 = #ue_link_specific_ip_address{},
    {IE1, Rest1} = maybe(Rest0, V4, bin(_,  4, #ue_link_specific_ip_address.tgpp_ipv4, _), IE0),
    {IE2, Rest2} = maybe(Rest1, V6, bin(_, 16, #ue_link_specific_ip_address.tgpp_ipv6, _), IE1),
    {IE3, Rest3} = maybe(Rest2, NV4, bin(_,  4, #ue_link_specific_ip_address.non_tgpp_ipv4, _), IE2),
    {IE4, _Rest} = maybe(Rest3, NV6, bin(_, 16, #ue_link_specific_ip_address.non_tgpp_ipv6, _), IE3),
    IE4.

encode_ue_link_specific_ip_address(#ue_link_specific_ip_address{
				      tgpp_ipv4 = V4, tgpp_ipv6 = V6,
				      non_tgpp_ipv4 = NV4, non_tgpp_ipv6 = NV6}) ->
    FlagV4 = is_binary(V4),
    FlagV6 = is_binary(V6),
    FlagNV4 = is_binary(NV4),
    FlagNV6 = is_binary(NV6),

    IE0 = <<0:4, (bool2int(FlagNV6)):1, (bool2int(FlagNV4)):1,
	    (bool2int(FlagV6)):1, (bool2int(FlagV4)):1>>,
    IE1 = maybe(FlagV4, bin(V4,  4, _), IE0),
    IE2 = maybe(FlagV6, bin(V6, 16, _), IE1),
    IE3 = maybe(FlagNV4, bin(NV4,  4, _), IE2),
    _IE = maybe(FlagNV6, bin(NV6, 16, _), IE3).

decode_pmf_address_information(<<_:5, MAC:1, V6:1, V4:1, Rest0/binary>>, _Type) ->
    IE0 = #pmf_address_information{},
    {IE1, Rest1} = maybe(Rest0, V4, bin(_,  4, #pmf_address_information.ipv4, _), IE0),
    {IE2, Rest2} = maybe(Rest1, V6, bin(_, 16, #pmf_address_information.ipv6, _), IE1),
    {IE3, Rest3} = maybe(Rest2, V4 bor V6, int(_, 16, #pmf_address_information.tgpp_port, _), IE2),
    {IE4, Rest4} = maybe(Rest3, V4 bor V6, int(_, 16, #pmf_address_information.non_tgpp_port, _), IE3),
    {IE5, Rest5} = maybe(Rest4, MAC, bin(_, 6, #pmf_address_information.tgpp_mac, _), IE4),
    {IE6, _Rest} = maybe(Rest5, MAC, bin(_, 6, #pmf_address_information.non_tgpp_mac, _), IE5),
    IE6.

encode_pmf_address_information(#pmf_address_information{
				  ipv4 = V4, ipv6 = V6,
				  tgpp_port = TgppPort, non_tgpp_port = NonTgppPort,
				  tgpp_mac = TgppMAC, non_tgpp_mac = NonTgppMAC}) ->
    FlagV4 = is_binary(V4),
    FlagV6 = is_binary(V6),
    FlagMAC = is_binary(TgppMAC) orelse is_binary(NonTgppMAC),

    IE0 = <<0:5, (bool2int(FlagMAC)):1, (bool2int(FlagV6)):1, (bool2int(FlagV4)):1>>,
    IE1 = maybe(FlagV4, bin(V4,  4, _), IE0),
    IE2 = maybe(FlagV6, bin(V6, 16, _), IE1),
    IE3 = maybe(FlagV4 or FlagV6, int(TgppPort, 16, _), IE2),
    IE4 = maybe(FlagV4 or FlagV6, int(NonTgppPort, 16, _), IE3),
    IE5 = maybe(FlagMAC, bin(TgppMAC, 6, _), IE4),
    _IE = maybe(FlagMAC, bin(NonTgppMAC, 6, _), IE5).

decode_packet_delay_thresholds(<<_:5, RP:1, UL:1, DL:1, Rest0/binary>>, _Type) ->
    IE0 = #packet_delay_thresholds{},
    {IE1, Rest1} =
	maybe(Rest0, DL,
	      int(_, 32, #packet_delay_thresholds.downlink_packet_delay_threshold, _), IE0),
    {IE2, Rest2} =
	maybe(Rest1, UL,
	      int(_, 32, #packet_delay_thresholds.uplink_packet_delay_threshold, _), IE1),
    {IE3, _Rest} =
	maybe(Rest2, RP,
	      int(_, 32, #packet_delay_thresholds.round_trip_packet_delay_threshold, _), IE2),
    IE3.

encode_packet_delay_thresholds(#packet_delay_thresholds{
				  downlink_packet_delay_threshold = DL,
				  uplink_packet_delay_threshold = UL,
				  round_trip_packet_delay_threshold = RP}) ->
    FlagUL = is_integer(UL),
    FlagDL = is_integer(DL),
    FlagRP = is_integer(RP),

    IE0 = <<0:5, (bool2int(FlagRP)):1, (bool2int(FlagUL)):1, (bool2int(FlagDL)):1>>,
    IE1 = maybe(FlagDL, int(DL, 32, _), IE0),
    IE2 = maybe(FlagUL, int(UL, 32, _), IE1),
    _IE = maybe(FlagRP, int(RP, 32, _), IE2).

decode_qos_monitoring_measurement(<<_:4, PLMF:1, RP:1, UL:1, DL:1, Rest0/binary>>, _Type) ->
    IE0 = #qos_monitoring_measurement{packet_delay_measurement_failure = (PLMF /= 0)},
    {IE1, Rest1} =
	maybe(Rest0, DL,
	      int(_, 32, #qos_monitoring_measurement.downlink_packet_delay, _), IE0),
    {IE2, Rest2} =
	maybe(Rest1, UL,
	      int(_, 32, #qos_monitoring_measurement.uplink_packet_delay, _), IE1),
    {IE3, _Rest} =
	maybe(Rest2, RP,
	      int(_, 32, #qos_monitoring_measurement.round_trip_packet_delay, _), IE2),
    IE3.

encode_qos_monitoring_measurement(#qos_monitoring_measurement{
				     packet_delay_measurement_failure = PLMF,
				     downlink_packet_delay = DL,
				     uplink_packet_delay = UL,
				     round_trip_packet_delay = RP}) ->
    FlagUL = is_integer(UL),
    FlagDL = is_integer(DL),
    FlagRP = is_integer(RP),

    IE0 = <<0:4, (bool2int(PLMF)):1, (bool2int(FlagRP)):1,
	    (bool2int(FlagUL)):1, (bool2int(FlagDL)):1>>,
    IE1 = maybe(FlagDL, int(DL, 32, _), IE0),
    IE2 = maybe(FlagUL, int(UL, 32, _), IE1),
    _IE = maybe(FlagRP, int(RP, 32, _), IE2).

decode_number_of_ue_ip_addresses(<<_:6, IPv6:1, IPv4:1, Rest0/binary>>, _Type) ->
    IE0 = #number_of_ue_ip_addresses{},
    {IE1, Rest1} = maybe_unsigned_integer(Rest0, IPv4, 32, #number_of_ue_ip_addresses.ipv4, IE0),
    {IE2, _Rest} = maybe_unsigned_integer(Rest1, IPv6, 32, #number_of_ue_ip_addresses.ipv6, IE1),
    IE2.

encode_number_of_ue_ip_addresses(#number_of_ue_ip_addresses{ipv6 = IPv6, ipv4 = IPv4} = IE) ->
    FlagIPv6 = is_integer(IPv6),
    FlagIPv4 = is_integer(IPv4),

    IE0 = <<0:6, (bool2int(FlagIPv6)):1, (bool2int(FlagIPv4)):1>>,
    IE1 = maybe(FlagIPv4, int(IPv4, 32, _), IE0),
    _IE = maybe(FlagIPv6, int(IPv6, 32, _), IE1).

decode_ppp_protocol(<<_:5, Control:1, Data:1, Specific:1, Rest0/binary>>, _Type) ->
    IE0 = #ppp_protocol{
	     flags =
		 sets:from_list([control || Control =:= 1] ++ [data || Data =:= 1],
				[{version, 2}])
	     },
    {IE1, _Rest} = maybe_unsigned_integer(Rest0, Specific, 16, #ppp_protocol.protocol, IE0),
    IE1.

encode_ppp_protocol(#ppp_protocol{flags = Flags, protocol = Protocol}) ->
    Specific = is_integer(Protocol),

    IE0 = <<0:5, (bool2int(is_map_key(control, Flags))):1,
	    (bool2int(is_map_key(data, Flags))):1, (bool2int(Specific)):1>>,
    _IE = maybe(Specific, int(Protocol, 16, _), IE0).

decode_l2tp_tunnel_endpoint(<<0:5, 1:1, 0:1, 0:1, Id:16, _IPv4:4/bytes, _IPv6:16/bytes, _/binary>>, _Type) ->
    #l2tp_tunnel_endpoint{tunnel_id = Id, endpoint = choose};
decode_l2tp_tunnel_endpoint(<<0:5, 0:1, 0:1, 1:1, Id:16, IPv4:4/bytes, _IPv6:16/bytes, _/binary>>, _Type) ->
    #l2tp_tunnel_endpoint{tunnel_id = Id, endpoint = IPv4};
decode_l2tp_tunnel_endpoint(<<0:5, 0:1, 1:1, 0:1, Id:16, _IPv4:4/bytes, IPv6:16/bytes, _/binary>>, _Type) ->
    #l2tp_tunnel_endpoint{tunnel_id = Id, endpoint = IPv6}.

encode_l2tp_tunnel_endpoint(#l2tp_tunnel_endpoint{tunnel_id = Id, endpoint = choose}) ->
    _IE = <<0:5, 1:1, 0:1, 0:1, Id:16,
	    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>;
encode_l2tp_tunnel_endpoint(#l2tp_tunnel_endpoint{tunnel_id = Id, endpoint = IP})
  when ?IS_IPv4(IP) ->
    IE0 = <<0:5, 0:1, 0:1, 1:1, Id:16>>,
    IE1 = bin(IP, 4, IE0),
    _IE = <<IE1/binary, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0>>;
encode_l2tp_tunnel_endpoint(#l2tp_tunnel_endpoint{tunnel_id = Id, endpoint = IP})
  when ?IS_IPv6(IP) ->
    IE0 = <<0:5, 0:1, 1:1, 0:1, Id:16, 0, 0, 0, 0>>,
    _IE = bin(IP, 16, IE0).

decode_bbf_nat_external_port_range(IE, _Type) ->
    Ranges = [{Start, End} || <<Start:16, End:16>> <= IE],
    #bbf_nat_external_port_range{ranges = Ranges}.

encode_bbf_nat_external_port_range(#bbf_nat_external_port_range{ranges = Ranges}) ->
    << <<Start:16, End:16>> || {Start, End} <- Ranges >>.

decode_bbf_nat_port_forward(IE, _Type) ->
    Forwards = [{InsideIP, InsidePort, OutsidePort, Protocol} ||
		   <<InsideIP:4/bytes, InsidePort:16, OutsidePort:16, Protocol:8>> <= IE],
    #bbf_nat_port_forward{forwards = Forwards}.

encode_bbf_nat_port_forward(#bbf_nat_port_forward{forwards = Forwards}) ->
    << <<InsideIP:4/bytes, InsidePort:16, OutsidePort:16, Protocol:8>> ||
	{InsideIP, InsidePort, OutsidePort, Protocol} <- Forwards >>.

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

enum_v1_access_availability_information_status(unavailable) -> 0;
enum_v1_access_availability_information_status(available) -> 1;
enum_v1_access_availability_information_status(0) -> unavailable;
enum_v1_access_availability_information_status(1) -> available;
enum_v1_access_availability_information_status(X) when is_integer(X) -> X.

enum_v1_access_availability_information_type('TGPP') -> 0;
enum_v1_access_availability_information_type('Non-TGPP') -> 1;
enum_v1_access_availability_information_type(0) -> 'TGPP';
enum_v1_access_availability_information_type(1) -> 'Non-TGPP';
enum_v1_access_availability_information_type(X) when is_integer(X) -> X.

enum_v1_bbf_outer_header_removal_header('Ethernet') -> 1;
enum_v1_bbf_outer_header_removal_header('PPPoE / Ethernet') -> 2;
enum_v1_bbf_outer_header_removal_header('PPP / PPPoE / Ethernet') -> 3;
enum_v1_bbf_outer_header_removal_header('L2TP') -> 4;
enum_v1_bbf_outer_header_removal_header('PPP / L2TP') -> 5;
enum_v1_bbf_outer_header_removal_header(1) -> 'Ethernet';
enum_v1_bbf_outer_header_removal_header(2) -> 'PPPoE / Ethernet';
enum_v1_bbf_outer_header_removal_header(3) -> 'PPP / PPPoE / Ethernet';
enum_v1_bbf_outer_header_removal_header(4) -> 'L2TP';
enum_v1_bbf_outer_header_removal_header(5) -> 'PPP / L2TP';
enum_v1_bbf_outer_header_removal_header(X) when is_integer(X) -> X.

enum_v1_destination_interface_interface('Access') -> 0;
enum_v1_destination_interface_interface('Core') -> 1;
enum_v1_destination_interface_interface('SGi-LAN') -> 2;
enum_v1_destination_interface_interface('CP-function') -> 3;
enum_v1_destination_interface_interface('LI-function') -> 4;
enum_v1_destination_interface_interface('5G VN Internal') -> 5;
enum_v1_destination_interface_interface(0) -> 'Access';
enum_v1_destination_interface_interface(1) -> 'Core';
enum_v1_destination_interface_interface(2) -> 'SGi-LAN';
enum_v1_destination_interface_interface(3) -> 'CP-function';
enum_v1_destination_interface_interface(4) -> 'LI-function';
enum_v1_destination_interface_interface(5) -> '5G VN Internal';
enum_v1_destination_interface_interface(X) when is_integer(X) -> X.

enum_v1_dl_buffering_duration_dl_buffer_unit('2 seconds') -> 0;
enum_v1_dl_buffering_duration_dl_buffer_unit('1 minute') -> 1;
enum_v1_dl_buffering_duration_dl_buffer_unit('10 minutes') -> 2;
enum_v1_dl_buffering_duration_dl_buffer_unit('1 hour') -> 3;
enum_v1_dl_buffering_duration_dl_buffer_unit('10 hours') -> 4;
enum_v1_dl_buffering_duration_dl_buffer_unit(infinite) -> 7;
enum_v1_dl_buffering_duration_dl_buffer_unit(0) -> '2 seconds';
enum_v1_dl_buffering_duration_dl_buffer_unit(1) -> '1 minute';
enum_v1_dl_buffering_duration_dl_buffer_unit(2) -> '10 minutes';
enum_v1_dl_buffering_duration_dl_buffer_unit(3) -> '1 hour';
enum_v1_dl_buffering_duration_dl_buffer_unit(4) -> '10 hours';
enum_v1_dl_buffering_duration_dl_buffer_unit(7) -> infinite;
enum_v1_dl_buffering_duration_dl_buffer_unit(X) when is_integer(X) -> X.

enum_v1_flow_information_direction('Unspecified') -> 0;
enum_v1_flow_information_direction('Downlink') -> 1;
enum_v1_flow_information_direction('Uplink') -> 2;
enum_v1_flow_information_direction('Bidirectional') -> 3;
enum_v1_flow_information_direction(0) -> 'Unspecified';
enum_v1_flow_information_direction(1) -> 'Downlink';
enum_v1_flow_information_direction(2) -> 'Uplink';
enum_v1_flow_information_direction(3) -> 'Bidirectional';
enum_v1_flow_information_direction(X) when is_integer(X) -> X.

enum_v1_gate_status_dl('OPEN') -> 0;
enum_v1_gate_status_dl('CLOSED') -> 1;
enum_v1_gate_status_dl(0) -> 'OPEN';
enum_v1_gate_status_dl(1) -> 'CLOSED';
enum_v1_gate_status_dl(X) when is_integer(X) -> X.

enum_v1_gate_status_ul('OPEN') -> 0;
enum_v1_gate_status_ul('CLOSED') -> 1;
enum_v1_gate_status_ul(0) -> 'OPEN';
enum_v1_gate_status_ul(1) -> 'CLOSED';
enum_v1_gate_status_ul(X) when is_integer(X) -> X.

enum_v1_graceful_release_period_release_timer_unit('2 seconds') -> 0;
enum_v1_graceful_release_period_release_timer_unit('1 minute') -> 1;
enum_v1_graceful_release_period_release_timer_unit('10 minutes') -> 2;
enum_v1_graceful_release_period_release_timer_unit('1 hour') -> 3;
enum_v1_graceful_release_period_release_timer_unit('10 hours') -> 4;
enum_v1_graceful_release_period_release_timer_unit(infinite) -> 7;
enum_v1_graceful_release_period_release_timer_unit(0) -> '2 seconds';
enum_v1_graceful_release_period_release_timer_unit(1) -> '1 minute';
enum_v1_graceful_release_period_release_timer_unit(2) -> '10 minutes';
enum_v1_graceful_release_period_release_timer_unit(3) -> '1 hour';
enum_v1_graceful_release_period_release_timer_unit(4) -> '10 hours';
enum_v1_graceful_release_period_release_timer_unit(7) -> infinite;
enum_v1_graceful_release_period_release_timer_unit(X) when is_integer(X) -> X.

enum_v1_header_enrichment_header_type('HTTP') -> 0;
enum_v1_header_enrichment_header_type(0) -> 'HTTP';
enum_v1_header_enrichment_header_type(X) when is_integer(X) -> X.

enum_v1_outer_header_removal_header('GTP-U/UDP/IPv4') -> 0;
enum_v1_outer_header_removal_header('GTP-U/UDP/IPv6') -> 1;
enum_v1_outer_header_removal_header('UDP/IPv4') -> 2;
enum_v1_outer_header_removal_header('UDP/IPv6') -> 3;
enum_v1_outer_header_removal_header('IPv4') -> 4;
enum_v1_outer_header_removal_header('IPv6') -> 5;
enum_v1_outer_header_removal_header('GTP-U/UDP/IP') -> 6;
enum_v1_outer_header_removal_header('VLAN S-TAG') -> 7;
enum_v1_outer_header_removal_header('S-TAG and C-TAG') -> 8;
enum_v1_outer_header_removal_header(0) -> 'GTP-U/UDP/IPv4';
enum_v1_outer_header_removal_header(1) -> 'GTP-U/UDP/IPv6';
enum_v1_outer_header_removal_header(2) -> 'UDP/IPv4';
enum_v1_outer_header_removal_header(3) -> 'UDP/IPv6';
enum_v1_outer_header_removal_header(4) -> 'IPv4';
enum_v1_outer_header_removal_header(5) -> 'IPv6';
enum_v1_outer_header_removal_header(6) -> 'GTP-U/UDP/IP';
enum_v1_outer_header_removal_header(7) -> 'VLAN S-TAG';
enum_v1_outer_header_removal_header(8) -> 'S-TAG and C-TAG';
enum_v1_outer_header_removal_header(X) when is_integer(X) -> X.

enum_v1_pdn_type_pdn_type('IPv4') -> 1;
enum_v1_pdn_type_pdn_type('IPv6') -> 2;
enum_v1_pdn_type_pdn_type('IPv4v6') -> 3;
enum_v1_pdn_type_pdn_type('Non-IP') -> 4;
enum_v1_pdn_type_pdn_type('Ethernet') -> 5;
enum_v1_pdn_type_pdn_type(1) -> 'IPv4';
enum_v1_pdn_type_pdn_type(2) -> 'IPv6';
enum_v1_pdn_type_pdn_type(3) -> 'IPv4v6';
enum_v1_pdn_type_pdn_type(4) -> 'Non-IP';
enum_v1_pdn_type_pdn_type(5) -> 'Ethernet';
enum_v1_pdn_type_pdn_type(X) when is_integer(X) -> X.

enum_v1_pfcp_cause_cause('Reserved') -> 0;
enum_v1_pfcp_cause_cause('Request accepted') -> 1;
enum_v1_pfcp_cause_cause('More Usage Report to send') -> 2;
enum_v1_pfcp_cause_cause('Request rejected') -> 64;
enum_v1_pfcp_cause_cause('Session context not found') -> 65;
enum_v1_pfcp_cause_cause('Mandatory IE missing') -> 66;
enum_v1_pfcp_cause_cause('Conditional IE missing') -> 67;
enum_v1_pfcp_cause_cause('Invalid length') -> 68;
enum_v1_pfcp_cause_cause('Mandatory IE incorrect') -> 69;
enum_v1_pfcp_cause_cause('Invalid Forwarding Policy') -> 70;
enum_v1_pfcp_cause_cause('Invalid F-TEID allocation option') -> 71;
enum_v1_pfcp_cause_cause('No established Sx Association') -> 72;
enum_v1_pfcp_cause_cause('Rule creation/modification Failure') -> 73;
enum_v1_pfcp_cause_cause('PFCP entity in congestion') -> 74;
enum_v1_pfcp_cause_cause('No resources available') -> 75;
enum_v1_pfcp_cause_cause('Service not supported') -> 76;
enum_v1_pfcp_cause_cause('System failure') -> 77;
enum_v1_pfcp_cause_cause('Redirection Requested') -> 78;
enum_v1_pfcp_cause_cause('All dynamic addresses are occupied') -> 79;
enum_v1_pfcp_cause_cause(0) -> 'Reserved';
enum_v1_pfcp_cause_cause(1) -> 'Request accepted';
enum_v1_pfcp_cause_cause(2) -> 'More Usage Report to send';
enum_v1_pfcp_cause_cause(64) -> 'Request rejected';
enum_v1_pfcp_cause_cause(65) -> 'Session context not found';
enum_v1_pfcp_cause_cause(66) -> 'Mandatory IE missing';
enum_v1_pfcp_cause_cause(67) -> 'Conditional IE missing';
enum_v1_pfcp_cause_cause(68) -> 'Invalid length';
enum_v1_pfcp_cause_cause(69) -> 'Mandatory IE incorrect';
enum_v1_pfcp_cause_cause(70) -> 'Invalid Forwarding Policy';
enum_v1_pfcp_cause_cause(71) -> 'Invalid F-TEID allocation option';
enum_v1_pfcp_cause_cause(72) -> 'No established Sx Association';
enum_v1_pfcp_cause_cause(73) -> 'Rule creation/modification Failure';
enum_v1_pfcp_cause_cause(74) -> 'PFCP entity in congestion';
enum_v1_pfcp_cause_cause(75) -> 'No resources available';
enum_v1_pfcp_cause_cause(76) -> 'Service not supported';
enum_v1_pfcp_cause_cause(77) -> 'System failure';
enum_v1_pfcp_cause_cause(78) -> 'Redirection Requested';
enum_v1_pfcp_cause_cause(79) -> 'All dynamic addresses are occupied';
enum_v1_pfcp_cause_cause(X) when is_integer(X) -> X.

enum_v1_redirect_information_type('IPv4') -> 0;
enum_v1_redirect_information_type('IPv6') -> 1;
enum_v1_redirect_information_type('URL') -> 2;
enum_v1_redirect_information_type('SIP URI') -> 3;
enum_v1_redirect_information_type('IPv4 and IPv6 addresses') -> 4;
enum_v1_redirect_information_type(0) -> 'IPv4';
enum_v1_redirect_information_type(1) -> 'IPv6';
enum_v1_redirect_information_type(2) -> 'URL';
enum_v1_redirect_information_type(3) -> 'SIP URI';
enum_v1_redirect_information_type(4) -> 'IPv4 and IPv6 addresses';
enum_v1_redirect_information_type(X) when is_integer(X) -> X.

enum_v1_source_interface_interface('Access') -> 0;
enum_v1_source_interface_interface('Core') -> 1;
enum_v1_source_interface_interface('SGi-LAN') -> 2;
enum_v1_source_interface_interface('CP-function') -> 3;
enum_v1_source_interface_interface('5G VN Internal') -> 4;
enum_v1_source_interface_interface(0) -> 'Access';
enum_v1_source_interface_interface(1) -> 'Core';
enum_v1_source_interface_interface(2) -> 'SGi-LAN';
enum_v1_source_interface_interface(3) -> 'CP-function';
enum_v1_source_interface_interface(4) -> '5G VN Internal';
enum_v1_source_interface_interface(X) when is_integer(X) -> X.

enum_v1_steering_functionality_functionality('ATSSS-LL') -> 0;
enum_v1_steering_functionality_functionality('MPTCP') -> 1;
enum_v1_steering_functionality_functionality(0) -> 'ATSSS-LL';
enum_v1_steering_functionality_functionality(1) -> 'MPTCP';
enum_v1_steering_functionality_functionality(X) when is_integer(X) -> X.

enum_v1_steering_mode_mode('Active-Standby') -> 0;
enum_v1_steering_mode_mode('Smallest Delay') -> 1;
enum_v1_steering_mode_mode('Load Balancing') -> 2;
enum_v1_steering_mode_mode('Priority-based') -> 3;
enum_v1_steering_mode_mode(0) -> 'Active-Standby';
enum_v1_steering_mode_mode(1) -> 'Smallest Delay';
enum_v1_steering_mode_mode(2) -> 'Load Balancing';
enum_v1_steering_mode_mode(3) -> 'Priority-based';
enum_v1_steering_mode_mode(X) when is_integer(X) -> X.

enum_v1_tgpp_interface_type_type('S1-U') -> 0;
enum_v1_tgpp_interface_type_type('S5 /S8-U') -> 1;
enum_v1_tgpp_interface_type_type('S4-U') -> 2;
enum_v1_tgpp_interface_type_type('S11-U') -> 3;
enum_v1_tgpp_interface_type_type('S12-U') -> 4;
enum_v1_tgpp_interface_type_type('Gn/Gp-U') -> 5;
enum_v1_tgpp_interface_type_type('S2a-U') -> 6;
enum_v1_tgpp_interface_type_type('S2b-U') -> 7;
enum_v1_tgpp_interface_type_type('eNodeB GTP-U interface for DL data forwarding') -> 8;
enum_v1_tgpp_interface_type_type('eNodeB GTP-U interface for UL data forwarding') -> 9;
enum_v1_tgpp_interface_type_type('SGW/UPF GTP-U interface for DL data forwarding') -> 10;
enum_v1_tgpp_interface_type_type('N3 3GPP Access') -> 11;
enum_v1_tgpp_interface_type_type('N3 Trusted Non-3GPP Access') -> 12;
enum_v1_tgpp_interface_type_type('N3 Untrusted Non-3GPP Access') -> 13;
enum_v1_tgpp_interface_type_type('N3 for data forwarding') -> 14;
enum_v1_tgpp_interface_type_type('N9') -> 15;
enum_v1_tgpp_interface_type_type('SGi') -> 16;
enum_v1_tgpp_interface_type_type('N6') -> 17;
enum_v1_tgpp_interface_type_type('N19') -> 18;
enum_v1_tgpp_interface_type_type('S8-U') -> 19;
enum_v1_tgpp_interface_type_type('Gp-U') -> 20;
enum_v1_tgpp_interface_type_type(0) -> 'S1-U';
enum_v1_tgpp_interface_type_type(1) -> 'S5 /S8-U';
enum_v1_tgpp_interface_type_type(2) -> 'S4-U';
enum_v1_tgpp_interface_type_type(3) -> 'S11-U';
enum_v1_tgpp_interface_type_type(4) -> 'S12-U';
enum_v1_tgpp_interface_type_type(5) -> 'Gn/Gp-U';
enum_v1_tgpp_interface_type_type(6) -> 'S2a-U';
enum_v1_tgpp_interface_type_type(7) -> 'S2b-U';
enum_v1_tgpp_interface_type_type(8) -> 'eNodeB GTP-U interface for DL data forwarding';
enum_v1_tgpp_interface_type_type(9) -> 'eNodeB GTP-U interface for UL data forwarding';
enum_v1_tgpp_interface_type_type(10) -> 'SGW/UPF GTP-U interface for DL data forwarding';
enum_v1_tgpp_interface_type_type(11) -> 'N3 3GPP Access';
enum_v1_tgpp_interface_type_type(12) -> 'N3 Trusted Non-3GPP Access';
enum_v1_tgpp_interface_type_type(13) -> 'N3 Untrusted Non-3GPP Access';
enum_v1_tgpp_interface_type_type(14) -> 'N3 for data forwarding';
enum_v1_tgpp_interface_type_type(15) -> 'N9';
enum_v1_tgpp_interface_type_type(16) -> 'SGi';
enum_v1_tgpp_interface_type_type(17) -> 'N6';
enum_v1_tgpp_interface_type_type(18) -> 'N19';
enum_v1_tgpp_interface_type_type(19) -> 'S8-U';
enum_v1_tgpp_interface_type_type(20) -> 'Gp-U';
enum_v1_tgpp_interface_type_type(X) when is_integer(X) -> X.

enum_v1_time_quota_mechanism_base_time_interval_type('CTP') -> 0;
enum_v1_time_quota_mechanism_base_time_interval_type('DTP') -> 1;
enum_v1_time_quota_mechanism_base_time_interval_type(0) -> 'CTP';
enum_v1_time_quota_mechanism_base_time_interval_type(1) -> 'DTP';
enum_v1_time_quota_mechanism_base_time_interval_type(X) when is_integer(X) -> X.

enum_v1_timer_timer_unit('2 seconds') -> 0;
enum_v1_timer_timer_unit('1 minute') -> 1;
enum_v1_timer_timer_unit('10 minutes') -> 2;
enum_v1_timer_timer_unit('1 hour') -> 3;
enum_v1_timer_timer_unit('10 hours') -> 4;
enum_v1_timer_timer_unit(infinite) -> 7;
enum_v1_timer_timer_unit(0) -> '2 seconds';
enum_v1_timer_timer_unit(1) -> '1 minute';
enum_v1_timer_timer_unit(2) -> '10 minutes';
enum_v1_timer_timer_unit(3) -> '1 hour';
enum_v1_timer_timer_unit(4) -> '10 hours';
enum_v1_timer_timer_unit(7) -> infinite;
enum_v1_timer_timer_unit(X) when is_integer(X) -> X.

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
    #pfcp_cause{cause = enum_v1_pfcp_cause_cause(M_cause)};

%% decode source_interface
decode_v1_element(<<_:4,
		    M_interface:4/integer,
		    _/binary>>, 20) ->
    #source_interface{interface = enum_v1_source_interface_interface(M_interface)};

%% decode f_teid
decode_v1_element(<<Data/binary>>, 21) ->
    decode_f_teid(Data, f_teid);

%% decode network_instance
decode_v1_element(<<M_instance/binary>>, 22) ->
    #network_instance{instance = decode_network_instance(M_instance)};

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
    #gate_status{ul = enum_v1_gate_status_ul(M_ul),
		 dl = enum_v1_gate_status_dl(M_dl)};

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
decode_v1_element(<<M_flags/binary>>, 37) ->
    #reporting_triggers{flags = decode_flags(M_flags, ['LIUSA','DROTH','STOPT','START','QUHTI',
                               'TIMTH','VOLTH','PERIO','QUVTI','IPMJL',
                               'EVEQU','EVETH','MACAR','ENVCL','TIMQU',
                               'VOLQU','_','_','_','_','_','_','UPINT',
                               'REEMR'])};

%% decode redirect_information
decode_v1_element(<<_:4,
		    M_type:4/integer,
		    M_address_len:16/integer, M_address:M_address_len/bytes,
		    M_other_address_len:16/integer, M_other_address:M_other_address_len/bytes,
		    _/binary>>, 38) ->
    #redirect_information{type = enum_v1_redirect_information_type(M_type),
			  address = M_address,
			  other_address = M_other_address};

%% decode report_type
decode_v1_element(<<M_flags/binary>>, 39) ->
    #report_type{flags = decode_flags(M_flags, ['_','UISR','SESR','PMIR','UPIR','ERIR','USAR',
                               'DLDR'])};

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
    #destination_interface{interface = enum_v1_destination_interface_interface(M_interface)};

%% decode up_function_features
decode_v1_element(<<M_flags/binary>>, 43) ->
    #up_function_features{flags = decode_flags(M_flags, ['TREU','HEEU','PFDM','FTUP','TRST','DLBD',
                               'DDND','BUCP','EPFAR','PFDE','FRRT','TRACE',
                               'QUOAC','UDBC','PDIU','EMPU','GCOM','BUNDL',
                               'MTE','MNOP','SSET','UEIP','ADPDP','DPDRA',
                               'MPTCP','TSCU','IP6PL','IPTV','NORP','VTIME',
                               'RTTL','MPAS','RDS','DDDS','ETHAR','CIOT',
                               'MT-EDT','GPQM','QFQM','ATSSS-LL','_','_','_',
                               '_','_','_','_','RTTWP'])};

%% decode apply_action
decode_v1_element(<<M_flags/binary>>, 44) ->
    #apply_action{flags = decode_flags(M_flags, ['DFRT','IPMD','IPMA','DUPL','NOCP','BUFF',
                               'FORW','DROP','_','_','_','_','_','DDPN',
                               'BDPN','EDRT'])};

%% decode downlink_data_service_information
decode_v1_element(<<Data/binary>>, 45) ->
    decode_downlink_data_service_information(Data, downlink_data_service_information);

%% decode downlink_data_notification_delay
decode_v1_element(<<M_delay:8/integer,
		    _/binary>>, 46) ->
    #downlink_data_notification_delay{delay = M_delay};

%% decode dl_buffering_duration
decode_v1_element(<<M_dl_buffer_unit:3/integer,
		    M_dl_buffer_value:5/integer,
		    _/binary>>, 47) ->
    #dl_buffering_duration{dl_buffer_unit = enum_v1_dl_buffering_duration_dl_buffer_unit(M_dl_buffer_unit),
			   dl_buffer_value = M_dl_buffer_value};

%% decode dl_buffering_suggested_packet_count
decode_v1_element(<<Data/binary>>, 48) ->
    decode_dl_buffering_suggested_packet_count(Data, dl_buffering_suggested_packet_count);

%% decode sxsmreq_flags
decode_v1_element(<<M_flags/binary>>, 49) ->
    #sxsmreq_flags{flags = decode_flags(M_flags, ['_','_','_','_','_','QAURR','SNDEM','DROBU'])};

%% decode sxsrrsp_flags
decode_v1_element(<<M_flags/binary>>, 50) ->
    #sxsrrsp_flags{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','DROBU'])};

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
    #timer{timer_unit = enum_v1_timer_timer_unit(M_timer_unit),
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
decode_v1_element(<<M_flags/binary>>, 62) ->
    #measurement_method{flags = decode_flags(M_flags, ['_','_','_','_','_','EVENT','VOLUM','DURAT'])};

%% decode usage_report_trigger
decode_v1_element(<<M_flags/binary>>, 63) ->
    #usage_report_trigger{flags = decode_flags(M_flags, ['IMMER','DROTH','STOPT','START','QUHTI',
                               'TIMTH','VOLTH','PERIO','EVETH','MACAR',
                               'ENVCL','MONIT','TERMR','LIUSA','TIMQU',
                               'VOLQU','_','_','_','EMRRE','QUVTI','IPMJL',
                               'TEBUR','EVEQU'])};

%% decode measurement_period
decode_v1_element(<<M_period:32/integer,
		    _/binary>>, 64) ->
    #measurement_period{period = M_period};

%% decode fq_csid
decode_v1_element(<<Data/binary>>, 65) ->
    decode_fq_csid(Data, fq_csid);

%% decode volume_measurement
decode_v1_element(<<Data/binary>>, 66) ->
    decode_volume_measurement(Data, volume_measurement);

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
decode_v1_element(<<M_flags/binary>>, 89) ->
    #cp_function_features{flags = decode_flags(M_flags, ['UIAUR','ARDR','MPAS','BUNDL','SSET','EPFAR',
                               'OVRL','LOAD'])};

%% decode usage_information
decode_v1_element(<<M_flags/binary>>, 90) ->
    #usage_information{flags = decode_flags(M_flags, ['_','_','_','_','UBE','UAE','AFT','BEF'])};

%% decode application_instance_id
decode_v1_element(<<M_id/binary>>, 91) ->
    #application_instance_id{id = M_id};

%% decode flow_information
decode_v1_element(<<_:4,
		    M_direction:4/integer,
		    M_flow_len:16/integer, M_flow:M_flow_len/bytes,
		    _/binary>>, 92) ->
    #flow_information{direction = enum_v1_flow_information_direction(M_direction),
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
    #outer_header_removal{header = enum_v1_outer_header_removal_header(M_header)};

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
    #header_enrichment{header_type = enum_v1_header_enrichment_header_type(M_header_type),
		       name = M_name,
		       value = M_value};

%% decode error_indication_report
decode_v1_element(<<M_group/binary>>, 99) ->
    #error_indication_report{group = decode_v1_grouped(M_group)};

%% decode measurement_information
decode_v1_element(<<M_flags/binary>>, 100) ->
    #measurement_information{flags = decode_flags(M_flags, ['_','_','_','MNOP','ISTM','RADI','INAM','MBQE'])};

%% decode node_report_type
decode_v1_element(<<M_flags/binary>>, 101) ->
    #node_report_type{flags = decode_flags(M_flags, ['_','_','_','_','GPQR','CKDR','UPRR','UPFR'])};

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
decode_v1_element(<<M_flags/binary>>, 110) ->
    #oci_flags{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','AOCI'])};

%% decode sx_association_release_request
decode_v1_element(<<M_flags/binary>>, 111) ->
    #sx_association_release_request{flags = decode_flags(M_flags, ['_','_','_','_','_','_','URSS','SARR'])};

%% decode graceful_release_period
decode_v1_element(<<M_release_timer_unit:3/integer,
		    M_release_timer_value:5/integer,
		    _/binary>>, 112) ->
    #graceful_release_period{release_timer_unit = enum_v1_graceful_release_period_release_timer_unit(M_release_timer_unit),
			     release_timer_value = M_release_timer_value};

%% decode pdn_type
decode_v1_element(<<_:5,
		    M_pdn_type:3/integer,
		    _/binary>>, 113) ->
    #pdn_type{pdn_type = enum_v1_pdn_type_pdn_type(M_pdn_type)};

%% decode failed_rule_id
decode_v1_element(<<Data/binary>>, 114) ->
    decode_failed_rule_id(Data, failed_rule_id);

%% decode time_quota_mechanism
decode_v1_element(<<_:6,
		    M_base_time_interval_type:2/integer,
		    M_interval:32/integer,
		    _/binary>>, 115) ->
    #time_quota_mechanism{base_time_interval_type = enum_v1_time_quota_mechanism_base_time_interval_type(M_base_time_interval_type),
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
decode_v1_element(<<M_digits:64/signed-integer,
		    M_exponent:32/signed-integer>>, 119) ->
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
decode_v1_element(<<M_flags/binary>>, 123) ->
    #rqi{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','RQI'])};

%% decode qfi
decode_v1_element(<<_:2,
		    M_qfi:6/integer,
		    _/binary>>, 124) ->
    #qfi{qfi = M_qfi};

%% decode query_urr_reference
decode_v1_element(<<M_reference:32/integer,
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
decode_v1_element(<<M_flags/binary>>, 137) ->
    #proxying{flags = decode_flags(M_flags, ['_','_','_','_','_','_','INS','ARP'])};

%% decode ethernet_filter_id
decode_v1_element(<<M_id:32/integer,
		    _/binary>>, 138) ->
    #ethernet_filter_id{id = M_id};

%% decode ethernet_filter_properties
decode_v1_element(<<M_flags/binary>>, 139) ->
    #ethernet_filter_properties{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','BIDE'])};

%% decode suggested_buffering_packets_count
decode_v1_element(<<M_count:8/integer,
		    _/binary>>, 140) ->
    #suggested_buffering_packets_count{count = M_count};

%% decode user_id
decode_v1_element(<<Data/binary>>, 141) ->
    decode_user_id(Data, user_id);

%% decode ethernet_pdu_session_information
decode_v1_element(<<M_flags/binary>>, 142) ->
    #ethernet_pdu_session_information{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','ETHI'])};

%% decode ethernet_traffic_information
decode_v1_element(<<M_group/binary>>, 143) ->
    #ethernet_traffic_information{group = decode_v1_grouped(M_group)};

%% decode mac_addresses_detected
decode_v1_element(<<Data/binary>>, 144) ->
    decode_mac_addresses(Data, mac_addresses_detected);

%% decode mac_addresses_removed
decode_v1_element(<<Data/binary>>, 145) ->
    decode_mac_addresses(Data, mac_addresses_removed);

%% decode ethernet_inactivity_timer
decode_v1_element(<<M_timer:32/integer,
		    _/binary>>, 146) ->
    #ethernet_inactivity_timer{timer = M_timer};

%% decode additional_monitoring_time
decode_v1_element(<<M_group/binary>>, 147) ->
    #additional_monitoring_time{group = decode_v1_grouped(M_group)};

%% decode event_quota
decode_v1_element(<<M_quota:32/integer,
		    _/binary>>, 148) ->
    #event_quota{quota = M_quota};

%% decode event_threshold
decode_v1_element(<<M_threshold:32/integer,
		    _/binary>>, 149) ->
    #event_threshold{threshold = M_threshold};

%% decode subsequent_event_quota
decode_v1_element(<<M_quota:32/integer,
		    _/binary>>, 150) ->
    #subsequent_event_quota{quota = M_quota};

%% decode subsequent_event_threshold
decode_v1_element(<<M_threshold:32/integer,
		    _/binary>>, 151) ->
    #subsequent_event_threshold{threshold = M_threshold};

%% decode trace_information
decode_v1_element(<<M_mccmnc:3/bytes,
		    M_trace_id:3/binary,
		    M_events_len:8/integer, M_events:M_events_len/bytes,
		    M_session_trace_depth:8/integer,
		    M_interfaces_len:8/integer, M_interfaces:M_interfaces_len/bytes,
		    M_ip_address_len:8/integer, M_ip_address:M_ip_address_len/bytes,
		    _/binary>>, 152) ->
    #trace_information{mcc = decode_mcc(M_mccmnc),
		       mnc = decode_mnc(M_mccmnc),
		       trace_id = M_trace_id,
		       events = M_events,
		       session_trace_depth = M_session_trace_depth,
		       interfaces = M_interfaces,
		       ip_address = M_ip_address};

%% decode framed_route
decode_v1_element(<<M_value/binary>>, 153) ->
    #framed_route{value = M_value};

%% decode framed_routing
decode_v1_element(<<M_value:32/integer>>, 154) ->
    #framed_routing{value = M_value};

%% decode framed_ipv6_route
decode_v1_element(<<M_value/binary>>, 155) ->
    #framed_ipv6_route{value = M_value};

%% decode event_time_stamp
decode_v1_element(<<M_time:32/integer,
		    _/binary>>, 156) ->
    #event_time_stamp{time = M_time};

%% decode averaging_window
decode_v1_element(<<M_window:32/integer,
		    _/binary>>, 157) ->
    #averaging_window{window = M_window};

%% decode paging_policy_indicator
decode_v1_element(<<_:5,
		    M_ppi:3/integer,
		    _/binary>>, 158) ->
    #paging_policy_indicator{ppi = M_ppi};

%% decode apn_dnn
decode_v1_element(<<M_apn/binary>>, 159) ->
    #apn_dnn{apn = decode_fqdn(M_apn)};

%% decode tgpp_interface_type
decode_v1_element(<<_:2,
		    M_type:6/integer,
		    _/binary>>, 160) ->
    #tgpp_interface_type{type = enum_v1_tgpp_interface_type_type(M_type)};

%% decode pfcpsrreq_flags
decode_v1_element(<<M_flags/binary>>, 161) ->
    #pfcpsrreq_flags{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','PSDBU'])};

%% decode pfcpaureq_flags
decode_v1_element(<<M_flags/binary>>, 162) ->
    #pfcpaureq_flags{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','PARPS'])};

%% decode activation_time
decode_v1_element(<<M_time:32/integer,
		    _/binary>>, 163) ->
    #activation_time{time = M_time};

%% decode deactivation_time
decode_v1_element(<<M_time:32/integer,
		    _/binary>>, 164) ->
    #deactivation_time{time = M_time};

%% decode create_mar
decode_v1_element(<<M_group/binary>>, 165) ->
    #create_mar{group = decode_v1_grouped(M_group)};

%% decode tgpp_access_forwarding_action_information
decode_v1_element(<<M_group/binary>>, 166) ->
    #tgpp_access_forwarding_action_information{group = decode_v1_grouped(M_group)};

%% decode non_tgpp_access_forwarding_action_information
decode_v1_element(<<M_group/binary>>, 167) ->
    #non_tgpp_access_forwarding_action_information{group = decode_v1_grouped(M_group)};

%% decode remove_mar
decode_v1_element(<<M_group/binary>>, 168) ->
    #remove_mar{group = decode_v1_grouped(M_group)};

%% decode update_mar
decode_v1_element(<<M_group/binary>>, 169) ->
    #update_mar{group = decode_v1_grouped(M_group)};

%% decode mar_id
decode_v1_element(<<M_id:16/integer,
		    _/binary>>, 170) ->
    #mar_id{id = M_id};

%% decode steering_functionality
decode_v1_element(<<_:4,
		    M_functionality:4/integer,
		    _/binary>>, 171) ->
    #steering_functionality{functionality = enum_v1_steering_functionality_functionality(M_functionality)};

%% decode steering_mode
decode_v1_element(<<_:4,
		    M_mode:4/integer,
		    _/binary>>, 172) ->
    #steering_mode{mode = enum_v1_steering_mode_mode(M_mode)};

%% decode weight
decode_v1_element(<<M_value:32/integer>>, 173) ->
    #weight{value = M_value};

%% decode priority
decode_v1_element(<<_:4,
		    M_priority:4/integer,
		    _/binary>>, 174) ->
    #priority{priority = M_priority};

%% decode update_tgpp_access_forwarding_action_information
decode_v1_element(<<M_group/binary>>, 175) ->
    #update_tgpp_access_forwarding_action_information{group = decode_v1_grouped(M_group)};

%% decode update_non_tgpp_access_forwarding_action_information
decode_v1_element(<<M_group/binary>>, 176) ->
    #update_non_tgpp_access_forwarding_action_information{group = decode_v1_grouped(M_group)};

%% decode ue_ip_address_pool_identity
decode_v1_element(<<M_identity_len:16/integer, M_identity:M_identity_len/bytes,
		    _/binary>>, 177) ->
    #ue_ip_address_pool_identity{identity = M_identity};

%% decode alternative_smf_ip_address
decode_v1_element(<<Data/binary>>, 178) ->
    decode_alternative_smf_ip_address(Data, alternative_smf_ip_address);

%% decode packet_replication_and_detection_carry_on_information
decode_v1_element(<<M_flags/binary>>, 179) ->
    #packet_replication_and_detection_carry_on_information{flags = decode_flags(M_flags, ['_','_','_','_','DCARONI','PRIN6I','PRIN19I',
                               'PRIUEAI'])};

%% decode smf_set_id
decode_v1_element(<<_:8,
		    M_fqdn/binary>>, 180) ->
    #smf_set_id{fqdn = decode_fqdn(M_fqdn)};

%% decode quota_validity_time
decode_v1_element(<<M_time:32/integer,
		    _/binary>>, 181) ->
    #quota_validity_time{time = M_time};

%% decode number_of_reports
decode_v1_element(<<M_reports:16/integer,
		    _/binary>>, 182) ->
    #number_of_reports{reports = M_reports};

%% decode pfcp_session_retention_information
decode_v1_element(<<M_group/binary>>, 183) ->
    #pfcp_session_retention_information{group = decode_v1_grouped(M_group)};

%% decode pfcpasrsp_flags
decode_v1_element(<<M_flags/binary>>, 184) ->
    #pfcpasrsp_flags{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','PSREI'])};

%% decode cp_pfcp_entity_ip_address
decode_v1_element(<<Data/binary>>, 185) ->
    decode_cp_pfcp_entity_ip_address(Data, cp_pfcp_entity_ip_address);

%% decode pfcpsereq_flags
decode_v1_element(<<M_flags/binary>>, 186) ->
    #pfcpsereq_flags{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','RESTI'])};

%% decode user_plane_path_recovery_report
decode_v1_element(<<M_group/binary>>, 187) ->
    #user_plane_path_recovery_report{group = decode_v1_grouped(M_group)};

%% decode ip_multicast_addressing_info
decode_v1_element(<<M_group/binary>>, 188) ->
    #ip_multicast_addressing_info{group = decode_v1_grouped(M_group)};

%% decode join_ip_multicast_information
decode_v1_element(<<M_group/binary>>, 189) ->
    #join_ip_multicast_information{group = decode_v1_grouped(M_group)};

%% decode leave_ip_multicast_information
decode_v1_element(<<M_group/binary>>, 190) ->
    #leave_ip_multicast_information{group = decode_v1_grouped(M_group)};

%% decode ip_multicast_address
decode_v1_element(<<Data/binary>>, 191) ->
    decode_ip_multicast_address(Data, ip_multicast_address);

%% decode source_ip_address
decode_v1_element(<<Data/binary>>, 192) ->
    decode_source_ip_address(Data, source_ip_address);

%% decode packet_rate_status
decode_v1_element(<<Data/binary>>, 193) ->
    decode_packet_rate_status(Data, packet_rate_status);

%% decode create_bridge_info_for_tsc
decode_v1_element(<<M_flags/binary>>, 194) ->
    #create_bridge_info_for_tsc{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','BII'])};

%% decode created_bridge_info_for_tsc
decode_v1_element(<<M_group/binary>>, 195) ->
    #created_bridge_info_for_tsc{group = decode_v1_grouped(M_group)};

%% decode ds_tt_port_number
decode_v1_element(<<M_value:32/integer>>, 196) ->
    #ds_tt_port_number{value = M_value};

%% decode nw_tt_port_number
decode_v1_element(<<M_value:32/integer>>, 197) ->
    #nw_tt_port_number{value = M_value};

%% decode tsn_bridge_id
decode_v1_element(<<Data/binary>>, 198) ->
    decode_tsn_bridge_id(Data, tsn_bridge_id);

%% decode port_management_information_for_tsc
decode_v1_element(<<M_group/binary>>, 199) ->
    #port_management_information_for_tsc{group = decode_v1_grouped(M_group)};

%% decode port_management_information_for_tsc_smr
decode_v1_element(<<M_group/binary>>, 200) ->
    #port_management_information_for_tsc_smr{group = decode_v1_grouped(M_group)};

%% decode port_management_information_for_tsc_sdr
decode_v1_element(<<M_group/binary>>, 201) ->
    #port_management_information_for_tsc_sdr{group = decode_v1_grouped(M_group)};

%% decode port_management_information_container
decode_v1_element(<<M_value/binary>>, 202) ->
    #port_management_information_container{value = M_value};

%% decode clock_drift_control_information
decode_v1_element(<<M_group/binary>>, 203) ->
    #clock_drift_control_information{group = decode_v1_grouped(M_group)};

%% decode requested_clock_drift_information
decode_v1_element(<<M_flags/binary>>, 204) ->
    #requested_clock_drift_information{flags = decode_flags(M_flags, ['_','_','_','_','_','_','RRCR','RRTO'])};

%% decode clock_drift_report
decode_v1_element(<<M_group/binary>>, 205) ->
    #clock_drift_report{group = decode_v1_grouped(M_group)};

%% decode tsn_time_domain_number
decode_v1_element(<<M_number:8/integer,
		    _/binary>>, 206) ->
    #tsn_time_domain_number{number = M_number};

%% decode time_offset_threshold
decode_v1_element(<<M_threshold:64/signed-integer,
		    _/binary>>, 207) ->
    #time_offset_threshold{threshold = M_threshold};

%% decode cumulative_rateratio_threshold
decode_v1_element(<<M_threshold:32/integer,
		    _/binary>>, 208) ->
    #cumulative_rateratio_threshold{threshold = M_threshold};

%% decode time_offset_measurement
decode_v1_element(<<M_measurement:64/signed-integer,
		    _/binary>>, 209) ->
    #time_offset_measurement{measurement = M_measurement};

%% decode cumulative_rateratio_measurement
decode_v1_element(<<M_measurement:32/integer,
		    _/binary>>, 210) ->
    #cumulative_rateratio_measurement{measurement = M_measurement};

%% decode remove_srr
decode_v1_element(<<M_group/binary>>, 211) ->
    #remove_srr{group = decode_v1_grouped(M_group)};

%% decode create_srr
decode_v1_element(<<M_group/binary>>, 212) ->
    #create_srr{group = decode_v1_grouped(M_group)};

%% decode update_srr
decode_v1_element(<<M_group/binary>>, 213) ->
    #update_srr{group = decode_v1_grouped(M_group)};

%% decode session_report
decode_v1_element(<<M_group/binary>>, 214) ->
    #session_report{group = decode_v1_grouped(M_group)};

%% decode srr_id
decode_v1_element(<<M_id:8/integer,
		    _/binary>>, 215) ->
    #srr_id{id = M_id};

%% decode access_availability_control_information
decode_v1_element(<<M_group/binary>>, 216) ->
    #access_availability_control_information{group = decode_v1_grouped(M_group)};

%% decode requested_access_availability_information
decode_v1_element(<<M_flags/binary>>, 217) ->
    #requested_access_availability_information{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','RRCA'])};

%% decode access_availability_report
decode_v1_element(<<M_group/binary>>, 218) ->
    #access_availability_report{group = decode_v1_grouped(M_group)};

%% decode access_availability_information
decode_v1_element(<<_:4,
		    M_status:2/integer,
		    M_type:2/integer,
		    _/binary>>, 219) ->
    #access_availability_information{status = enum_v1_access_availability_information_status(M_status),
				     type = enum_v1_access_availability_information_type(M_type)};

%% decode provide_atsss_control_information
decode_v1_element(<<M_group/binary>>, 220) ->
    #provide_atsss_control_information{group = decode_v1_grouped(M_group)};

%% decode atsss_control_parameters
decode_v1_element(<<M_group/binary>>, 221) ->
    #atsss_control_parameters{group = decode_v1_grouped(M_group)};

%% decode mptcp_control_information
decode_v1_element(<<M_flags/binary>>, 222) ->
    #mptcp_control_information{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','TCI'])};

%% decode atsss_ll_control_information
decode_v1_element(<<M_flags/binary>>, 223) ->
    #atsss_ll_control_information{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','LLI'])};

%% decode pmf_control_information
decode_v1_element(<<M_flags/binary>>, 224) ->
    #pmf_control_information{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','PMFI'])};

%% decode mptcp_parameters
decode_v1_element(<<M_group/binary>>, 225) ->
    #mptcp_parameters{group = decode_v1_grouped(M_group)};

%% decode atsss_ll_parameters
decode_v1_element(<<M_group/binary>>, 226) ->
    #atsss_ll_parameters{group = decode_v1_grouped(M_group)};

%% decode pmf_parameters
decode_v1_element(<<M_group/binary>>, 227) ->
    #pmf_parameters{group = decode_v1_grouped(M_group)};

%% decode mptcp_address_information
decode_v1_element(<<Data/binary>>, 228) ->
    decode_mptcp_address_information(Data, mptcp_address_information);

%% decode ue_link_specific_ip_address
decode_v1_element(<<Data/binary>>, 229) ->
    decode_ue_link_specific_ip_address(Data, ue_link_specific_ip_address);

%% decode pmf_address_information
decode_v1_element(<<Data/binary>>, 230) ->
    decode_pmf_address_information(Data, pmf_address_information);

%% decode atsss_ll_information
decode_v1_element(<<M_flags/binary>>, 231) ->
    #atsss_ll_information{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','LLI'])};

%% decode data_network_access_identifier
decode_v1_element(<<M_value/binary>>, 232) ->
    #data_network_access_identifier{value = M_value};

%% decode ue_ip_address_pool_information
decode_v1_element(<<M_group/binary>>, 233) ->
    #ue_ip_address_pool_information{group = decode_v1_grouped(M_group)};

%% decode average_packet_delay
decode_v1_element(<<M_delay:32/integer,
		    _/binary>>, 234) ->
    #average_packet_delay{delay = M_delay};

%% decode minimum_packet_delay
decode_v1_element(<<M_delay:32/integer,
		    _/binary>>, 235) ->
    #minimum_packet_delay{delay = M_delay};

%% decode maximum_packet_delay
decode_v1_element(<<M_delay:32/integer,
		    _/binary>>, 236) ->
    #maximum_packet_delay{delay = M_delay};

%% decode qos_report_trigger
decode_v1_element(<<M_flags/binary>>, 237) ->
    #qos_report_trigger{flags = decode_flags(M_flags, ['_','_','_','_','_','IRE','THR','PER'])};

%% decode gtp_u_path_qos_control_information
decode_v1_element(<<M_group/binary>>, 238) ->
    #gtp_u_path_qos_control_information{group = decode_v1_grouped(M_group)};

%% decode gtp_u_path_qos_report
decode_v1_element(<<M_group/binary>>, 239) ->
    #gtp_u_path_qos_report{group = decode_v1_grouped(M_group)};

%% decode path_report_qos_information
decode_v1_element(<<M_group/binary>>, 240) ->
    #path_report_qos_information{group = decode_v1_grouped(M_group)};

%% decode gtp_u_path_interface_type
decode_v1_element(<<M_flags/binary>>, 241) ->
    #gtp_u_path_interface_type{flags = decode_flags(M_flags, ['_','_','_','_','_','_','N3','N9'])};

%% decode qos_monitoring_per_qos_flow_control_information
decode_v1_element(<<M_group/binary>>, 242) ->
    #qos_monitoring_per_qos_flow_control_information{group = decode_v1_grouped(M_group)};

%% decode requested_qos_monitoring
decode_v1_element(<<M_flags/binary>>, 243) ->
    #requested_qos_monitoring{flags = decode_flags(M_flags, ['_','_','_','_','_','RP','UL','DL'])};

%% decode reporting_frequency
decode_v1_element(<<M_flags/binary>>, 244) ->
    #reporting_frequency{flags = decode_flags(M_flags, ['_','_','_','_','_','SESRL','PERIO','EVETT'])};

%% decode packet_delay_thresholds
decode_v1_element(<<Data/binary>>, 245) ->
    decode_packet_delay_thresholds(Data, packet_delay_thresholds);

%% decode minimum_wait_time
decode_v1_element(<<M_time:32/integer,
		    _/binary>>, 246) ->
    #minimum_wait_time{time = M_time};

%% decode qos_monitoring_report
decode_v1_element(<<M_group/binary>>, 247) ->
    #qos_monitoring_report{group = decode_v1_grouped(M_group)};

%% decode qos_monitoring_measurement
decode_v1_element(<<Data/binary>>, 248) ->
    decode_qos_monitoring_measurement(Data, qos_monitoring_measurement);

%% decode mt_edt_control_information
decode_v1_element(<<M_flags/binary>>, 249) ->
    #mt_edt_control_information{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','RDSI'])};

%% decode dl_data_packets_size
decode_v1_element(<<M_size:16/integer,
		    _/binary>>, 250) ->
    #dl_data_packets_size{size = M_size};

%% decode qer_control_indications
decode_v1_element(<<M_flags/binary>>, 251) ->
    #qer_control_indications{flags = decode_flags(M_flags, ['_','_','_','_','_','NORD','MOED','RCSRT'])};

%% decode packet_rate_status_report
decode_v1_element(<<M_group/binary>>, 252) ->
    #packet_rate_status_report{group = decode_v1_grouped(M_group)};

%% decode nf_instance_id
decode_v1_element(<<M_value:16/binary>>, 253) ->
    #nf_instance_id{value = M_value};

%% decode ethernet_context_information
decode_v1_element(<<M_group/binary>>, 254) ->
    #ethernet_context_information{group = decode_v1_grouped(M_group)};

%% decode redundant_transmission_parameters
decode_v1_element(<<M_group/binary>>, 255) ->
    #redundant_transmission_parameters{group = decode_v1_grouped(M_group)};

%% decode updated_pdr
decode_v1_element(<<M_group/binary>>, 256) ->
    #updated_pdr{group = decode_v1_grouped(M_group)};

%% decode s_nssai
decode_v1_element(<<M_sst:8/integer,
		    M_sd:24/integer>>, 257) ->
    #s_nssai{sst = M_sst,
	     sd = M_sd};

%% decode ip_version
decode_v1_element(<<M_flags/binary>>, 258) ->
    #ip_version{flags = decode_flags(M_flags, ['_','_','_','_','_','_','V6','V4'])};

%% decode pfcpasreq_flags
decode_v1_element(<<M_flags/binary>>, 259) ->
    #pfcpasreq_flags{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','UUPSI'])};

%% decode data_status
decode_v1_element(<<M_flags/binary>>, 260) ->
    #data_status{flags = decode_flags(M_flags, ['_','_','_','_','_','_','BUFF','DROP'])};

%% decode provide_rds_configuration_information
decode_v1_element(<<M_group/binary>>, 261) ->
    #provide_rds_configuration_information{group = decode_v1_grouped(M_group)};

%% decode rds_configuration_information
decode_v1_element(<<M_flags/binary>>, 262) ->
    #rds_configuration_information{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','RDS'])};

%% decode query_packet_rate_status_ie_smreq
decode_v1_element(<<M_group/binary>>, 263) ->
    #query_packet_rate_status_ie_smreq{group = decode_v1_grouped(M_group)};

%% decode packet_rate_status_report_ie_smresp
decode_v1_element(<<M_group/binary>>, 264) ->
    #packet_rate_status_report_ie_smresp{group = decode_v1_grouped(M_group)};

%% decode mptcp_applicable_indication
decode_v1_element(<<M_flags/binary>>, 265) ->
    #mptcp_applicable_indication{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','MAI'])};

%% decode bridge_management_information_container
decode_v1_element(<<M_value/binary>>, 266) ->
    #bridge_management_information_container{value = M_value};

%% decode ue_ip_address_usage_information
decode_v1_element(<<M_group/binary>>, 267) ->
    #ue_ip_address_usage_information{group = decode_v1_grouped(M_group)};

%% decode number_of_ue_ip_addresses
decode_v1_element(<<Data/binary>>, 268) ->
    decode_number_of_ue_ip_addresses(Data, number_of_ue_ip_addresses);

%% decode validity_timer
decode_v1_element(<<M_validity_timer:16/integer,
		    _/binary>>, 269) ->
    #validity_timer{validity_timer = M_validity_timer};

%% decode redundant_transmission_forwarding
decode_v1_element(<<M_group/binary>>, 270) ->
    #redundant_transmission_forwarding{group = decode_v1_grouped(M_group)};

%% decode transport_delay_reporting
decode_v1_element(<<M_group/binary>>, 271) ->
    #transport_delay_reporting{group = decode_v1_grouped(M_group)};

%% decode bbf_up_function_features
decode_v1_element(<<M_flags/binary>>, {3561,0}) ->
    #bbf_up_function_features{flags = decode_flags(M_flags, ['_','NAT-UP','NAT-CP','LCP keepalive offload',
                               'LNS','LAC','IPoE','PPPoE'])};

%% decode logical_port
decode_v1_element(<<M_port/binary>>, {3561,1}) ->
    #logical_port{port = M_port};

%% decode bbf_outer_header_creation
decode_v1_element(<<M_flags:16/bits,
		    M_tunnel_id:16/integer,
		    M_session_id:16/integer,
		    _/binary>>, {3561,2}) ->
    #bbf_outer_header_creation{flags = decode_flags(M_flags, ['_','_','_','_','CPR-NSH','Traffic-Endpoint',
                               'L2TP','PPP']),
			       tunnel_id = M_tunnel_id,
			       session_id = M_session_id};

%% decode bbf_outer_header_removal
decode_v1_element(<<M_header:8/integer,
		    _/binary>>, {3561,3}) ->
    #bbf_outer_header_removal{header = enum_v1_bbf_outer_header_removal_header(M_header)};

%% decode pppoe_session_id
decode_v1_element(<<M_id:16/integer,
		    _/binary>>, {3561,4}) ->
    #pppoe_session_id{id = M_id};

%% decode ppp_protocol
decode_v1_element(<<Data/binary>>, {3561,5}) ->
    decode_ppp_protocol(Data, ppp_protocol);

%% decode verification_timers
decode_v1_element(<<M_interval:16/integer,
		    M_count:8/integer,
		    _/binary>>, {3561,6}) ->
    #verification_timers{interval = M_interval,
			 count = M_count};

%% decode ppp_lcp_magic_number
decode_v1_element(<<M_tx:32/integer,
		    M_rx:32/integer,
		    _/binary>>, {3561,7}) ->
    #ppp_lcp_magic_number{tx = M_tx,
			  rx = M_rx};

%% decode mtu
decode_v1_element(<<M_mtu:16/integer,
		    _/binary>>, {3561,8}) ->
    #mtu{mtu = M_mtu};

%% decode l2tp_tunnel_endpoint
decode_v1_element(<<Data/binary>>, {3561,9}) ->
    decode_l2tp_tunnel_endpoint(Data, l2tp_tunnel_endpoint);

%% decode l2tp_session_id
decode_v1_element(<<M_id:16/integer,
		    _/binary>>, {3561,10}) ->
    #l2tp_session_id{id = M_id};

%% decode l2tp_type
decode_v1_element(<<M_flags/binary>>, {3561,11}) ->
    #l2tp_type{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_',type])};

%% decode ppp_lcp_connectivity
decode_v1_element(<<M_group/binary>>, {3561,12}) ->
    #ppp_lcp_connectivity{group = decode_v1_grouped(M_group)};

%% decode l2tp_tunnel
decode_v1_element(<<M_group/binary>>, {3561,13}) ->
    #l2tp_tunnel{group = decode_v1_grouped(M_group)};

%% decode bbf_nat_outside_address
decode_v1_element(<<M_ipv4:4/bytes>>, {3561,14}) ->
    #bbf_nat_outside_address{ipv4 = M_ipv4};

%% decode bbf_apply_action
decode_v1_element(<<M_flags/binary>>, {3561,15}) ->
    #bbf_apply_action{flags = decode_flags(M_flags, ['_','_','_','_','_','_','_','NAT'])};

%% decode bbf_nat_external_port_range
decode_v1_element(<<Data/binary>>, {3561,16}) ->
    decode_bbf_nat_external_port_range(Data, bbf_nat_external_port_range);

%% decode bbf_nat_port_forward
decode_v1_element(<<Data/binary>>, {3561,17}) ->
    decode_bbf_nat_port_forward(Data, bbf_nat_port_forward);

%% decode bbf_nat_port_block
decode_v1_element(<<M_block/binary>>, {3561,18}) ->
    #bbf_nat_port_block{block = M_block};

%% decode bbf_dynamic_port_block_starting_port
decode_v1_element(<<M_start:16/integer,
		    _/binary>>, {3561,19}) ->
    #bbf_dynamic_port_block_starting_port{start = M_start};

%% decode tp_packet_measurement
decode_v1_element(<<Data/binary>>, {18681,1}) ->
    decode_volume_threshold(Data, tp_packet_measurement);

%% decode tp_build_identifier
decode_v1_element(<<M_id/binary>>, {18681,2}) ->
    #tp_build_identifier{id = M_id};

%% decode tp_now
decode_v1_element(<<M_seconds:32/integer,
		    M_fraction:32/integer,
		    _/binary>>, {18681,3}) ->
    #tp_now{seconds = M_seconds,
	    fraction = M_fraction};

%% decode tp_start_time
decode_v1_element(<<M_seconds:32/integer,
		    M_fraction:32/integer,
		    _/binary>>, {18681,4}) ->
    #tp_start_time{seconds = M_seconds,
		   fraction = M_fraction};

%% decode tp_stop_time
decode_v1_element(<<M_seconds:32/integer,
		    M_fraction:32/integer,
		    _/binary>>, {18681,5}) ->
    #tp_stop_time{seconds = M_seconds,
		  fraction = M_fraction};

%% decode tp_error_report
decode_v1_element(<<M_group/binary>>, {18681,6}) ->
    #tp_error_report{group = decode_v1_grouped(M_group)};

%% decode tp_error_message
decode_v1_element(<<M_message/binary>>, {18681,7}) ->
    #tp_error_message{message = M_message};

%% decode tp_file_name
decode_v1_element(<<M_file_name/binary>>, {18681,8}) ->
    #tp_file_name{file_name = M_file_name};

%% decode tp_line_number
decode_v1_element(<<M_line:32/integer,
		    _/binary>>, {18681,9}) ->
    #tp_line_number{line = M_line};

%% decode tp_created_nat_binding
decode_v1_element(<<M_group/binary>>, {18681,10}) ->
    #tp_created_nat_binding{group = decode_v1_grouped(M_group)};

%% decode tp_ipfix_policy
decode_v1_element(<<M_policy/binary>>, {18681,11}) ->
    #tp_ipfix_policy{policy = M_policy};

%% decode tp_trace_information
decode_v1_element(<<M_group/binary>>, {18681,12}) ->
    #tp_trace_information{group = decode_v1_grouped(M_group)};

%% decode tp_trace_parent
decode_v1_element(<<M_parent/binary>>, {18681,13}) ->
    #tp_trace_parent{parent = M_parent};

%% decode tp_trace_state
decode_v1_element(<<M_state/binary>>, {18681,14}) ->
    #tp_trace_state{state = M_state};

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
    encode_tlv(19, <<(enum_v1_pfcp_cause_cause(M_cause)):8/integer>>, Acc);

encode_v1_element(#source_interface{
		       interface = M_interface}, Acc) ->
    encode_tlv(20, <<0:4,
		     (enum_v1_source_interface_interface(M_interface)):4/integer>>, Acc);

encode_v1_element(#f_teid{} = IE, Acc) ->
    encode_tlv(21, encode_f_teid(IE), Acc);

encode_v1_element(#network_instance{
		       instance = M_instance}, Acc) ->
    encode_tlv(22, <<(encode_network_instance(M_instance))/binary>>, Acc);

encode_v1_element(#sdf_filter{} = IE, Acc) ->
    encode_tlv(23, encode_sdf_filter(IE), Acc);

encode_v1_element(#application_id{
		       id = M_id}, Acc) ->
    encode_tlv(24, <<M_id/binary>>, Acc);

encode_v1_element(#gate_status{
		       ul = M_ul,
		       dl = M_dl}, Acc) ->
    encode_tlv(25, <<0:4,
		     (enum_v1_gate_status_ul(M_ul)):2/integer,
		     (enum_v1_gate_status_dl(M_dl)):2/integer>>, Acc);

encode_v1_element(#mbr{
		       ul = M_ul,
		       dl = M_dl}, Acc) ->
    encode_tlv(26, <<M_ul:40/integer,
		     M_dl:40/integer>>, Acc);

encode_v1_element(#gbr{
		       ul = M_ul,
		       dl = M_dl}, Acc) ->
    encode_tlv(27, <<M_ul:40/integer,
		     M_dl:40/integer>>, Acc);

encode_v1_element(#qer_correlation_id{
		       id = M_id}, Acc) ->
    encode_tlv(28, <<M_id:32/integer>>, Acc);

encode_v1_element(#precedence{
		       precedence = M_precedence}, Acc) ->
    encode_tlv(29, <<M_precedence:32/integer>>, Acc);

encode_v1_element(#transport_level_marking{
		       tos = M_tos}, Acc) ->
    encode_tlv(30, <<M_tos:16/integer>>, Acc);

encode_v1_element(#volume_threshold{} = IE, Acc) ->
    encode_tlv(31, encode_volume_threshold(IE), Acc);

encode_v1_element(#time_threshold{
		       threshold = M_threshold}, Acc) ->
    encode_tlv(32, <<M_threshold:32/integer>>, Acc);

encode_v1_element(#monitoring_time{
		       time = M_time}, Acc) ->
    encode_tlv(33, <<M_time:32/integer>>, Acc);

encode_v1_element(#subsequent_volume_threshold{} = IE, Acc) ->
    encode_tlv(34, encode_volume_threshold(IE), Acc);

encode_v1_element(#subsequent_time_threshold{
		       threshold = M_threshold}, Acc) ->
    encode_tlv(35, <<M_threshold:32/integer>>, Acc);

encode_v1_element(#inactivity_detection_time{
		       time = M_time}, Acc) ->
    encode_tlv(36, <<M_time:32/integer>>, Acc);

encode_v1_element(#reporting_triggers{
		       flags = M_flags}, Acc) ->
    encode_tlv(37, <<(encode_min_int(16, encode_flags(M_flags, ['PERIO','VOLTH','TIMTH','QUHTI',
                                           'START','STOPT','DROTH','LIUSA',
                                           'VOLQU','TIMQU','ENVCL','MACAR',
                                           'EVETH','EVEQU','IPMJL','QUVTI',
                                           'REEMR','UPINT','_','_','_','_',
                                           '_','_']), little))/binary>>, Acc);

encode_v1_element(#redirect_information{
		       type = M_type,
		       address = M_address,
		       other_address = M_other_address}, Acc) ->
    encode_tlv(38, <<0:4,
		     (enum_v1_redirect_information_type(M_type)):4/integer,
		     (byte_size(M_address)):16/integer, M_address/binary,
		     (byte_size(M_other_address)):16/integer, M_other_address/binary>>, Acc);

encode_v1_element(#report_type{
		       flags = M_flags}, Acc) ->
    encode_tlv(39, <<(encode_min_int(16, encode_flags(M_flags, ['DLDR','USAR','ERIR','UPIR','PMIR',
                                           'SESR','UISR','_']), little))/binary>>, Acc);

encode_v1_element(#offending_ie{
		       type = M_type}, Acc) ->
    encode_tlv(40, <<M_type:16/integer>>, Acc);

encode_v1_element(#forwarding_policy{
		       policy_identifier = M_policy_identifier}, Acc) ->
    encode_tlv(41, <<(byte_size(M_policy_identifier)):8/integer, M_policy_identifier/binary>>, Acc);

encode_v1_element(#destination_interface{
		       interface = M_interface}, Acc) ->
    encode_tlv(42, <<0:4,
		     (enum_v1_destination_interface_interface(M_interface)):4/integer>>, Acc);

encode_v1_element(#up_function_features{
		       flags = M_flags}, Acc) ->
    encode_tlv(43, <<(encode_min_int(8, encode_flags(M_flags, ['BUCP','DDND','DLBD','TRST','FTUP',
                                          'PFDM','HEEU','TREU','EMPU','PDIU',
                                          'UDBC','QUOAC','TRACE','FRRT',
                                          'PFDE','EPFAR','DPDRA','ADPDP',
                                          'UEIP','SSET','MNOP','MTE','BUNDL',
                                          'GCOM','MPAS','RTTL','VTIME','NORP',
                                          'IPTV','IP6PL','TSCU','MPTCP',
                                          'ATSSS-LL','QFQM','GPQM','MT-EDT',
                                          'CIOT','ETHAR','DDDS','RDS','RTTWP',
                                          '_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#apply_action{
		       flags = M_flags}, Acc) ->
    encode_tlv(44, <<(encode_min_int(8, encode_flags(M_flags, ['DROP','FORW','BUFF','NOCP','DUPL',
                                          'IPMA','IPMD','DFRT','EDRT','BDPN',
                                          'DDPN','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#downlink_data_service_information{} = IE, Acc) ->
    encode_tlv(45, encode_downlink_data_service_information(IE), Acc);

encode_v1_element(#downlink_data_notification_delay{
		       delay = M_delay}, Acc) ->
    encode_tlv(46, <<M_delay:8/integer>>, Acc);

encode_v1_element(#dl_buffering_duration{
		       dl_buffer_unit = M_dl_buffer_unit,
		       dl_buffer_value = M_dl_buffer_value}, Acc) ->
    encode_tlv(47, <<(enum_v1_dl_buffering_duration_dl_buffer_unit(M_dl_buffer_unit)):3/integer,
		     M_dl_buffer_value:5/integer>>, Acc);

encode_v1_element(#dl_buffering_suggested_packet_count{} = IE, Acc) ->
    encode_tlv(48, encode_dl_buffering_suggested_packet_count(IE), Acc);

encode_v1_element(#sxsmreq_flags{
		       flags = M_flags}, Acc) ->
    encode_tlv(49, <<(encode_min_int(8, encode_flags(M_flags, ['DROBU','SNDEM','QAURR','_','_','_',
                                          '_','_']), little))/binary>>, Acc);

encode_v1_element(#sxsrrsp_flags{
		       flags = M_flags}, Acc) ->
    encode_tlv(50, <<(encode_min_int(8, encode_flags(M_flags, ['DROBU','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#load_control_information{
		       group = M_group}, Acc) ->
    encode_tlv(51, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#sequence_number{
		       number = M_number}, Acc) ->
    encode_tlv(52, <<M_number:32/integer>>, Acc);

encode_v1_element(#metric{
		       metric = M_metric}, Acc) ->
    encode_tlv(53, <<M_metric:8/integer>>, Acc);

encode_v1_element(#overload_control_information{
		       group = M_group}, Acc) ->
    encode_tlv(54, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#timer{
		       timer_unit = M_timer_unit,
		       timer_value = M_timer_value}, Acc) ->
    encode_tlv(55, <<(enum_v1_timer_timer_unit(M_timer_unit)):3/integer,
		     M_timer_value:5/integer>>, Acc);

encode_v1_element(#pdr_id{
		       id = M_id}, Acc) ->
    encode_tlv(56, <<M_id:16/integer>>, Acc);

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
		       flags = M_flags}, Acc) ->
    encode_tlv(62, <<(encode_min_int(8, encode_flags(M_flags, ['DURAT','VOLUM','EVENT','_','_','_',
                                          '_','_']), little))/binary>>, Acc);

encode_v1_element(#usage_report_trigger{
		       flags = M_flags}, Acc) ->
    encode_tlv(63, <<(encode_min_int(16, encode_flags(M_flags, ['PERIO','VOLTH','TIMTH','QUHTI',
                                           'START','STOPT','DROTH','IMMER',
                                           'VOLQU','TIMQU','LIUSA','TERMR',
                                           'MONIT','ENVCL','MACAR','EVETH',
                                           'EVEQU','TEBUR','IPMJL','QUVTI',
                                           'EMRRE','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#measurement_period{
		       period = M_period}, Acc) ->
    encode_tlv(64, <<M_period:32/integer>>, Acc);

encode_v1_element(#fq_csid{} = IE, Acc) ->
    encode_tlv(65, encode_fq_csid(IE), Acc);

encode_v1_element(#volume_measurement{} = IE, Acc) ->
    encode_tlv(66, encode_volume_measurement(IE), Acc);

encode_v1_element(#duration_measurement{
		       duration = M_duration}, Acc) ->
    encode_tlv(67, <<M_duration:32/integer>>, Acc);

encode_v1_element(#application_detection_information{
		       group = M_group}, Acc) ->
    encode_tlv(68, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#time_of_first_packet{
		       time = M_time}, Acc) ->
    encode_tlv(69, <<M_time:32/integer>>, Acc);

encode_v1_element(#time_of_last_packet{
		       time = M_time}, Acc) ->
    encode_tlv(70, <<M_time:32/integer>>, Acc);

encode_v1_element(#quota_holding_time{
		       time = M_time}, Acc) ->
    encode_tlv(71, <<M_time:32/integer>>, Acc);

encode_v1_element(#dropped_dl_traffic_threshold{} = IE, Acc) ->
    encode_tlv(72, encode_dropped_dl_traffic_threshold(IE), Acc);

encode_v1_element(#volume_quota{} = IE, Acc) ->
    encode_tlv(73, encode_volume_threshold(IE), Acc);

encode_v1_element(#time_quota{
		       quota = M_quota}, Acc) ->
    encode_tlv(74, <<M_quota:32/integer>>, Acc);

encode_v1_element(#start_time{
		       time = M_time}, Acc) ->
    encode_tlv(75, <<M_time:32/integer>>, Acc);

encode_v1_element(#end_time{
		       time = M_time}, Acc) ->
    encode_tlv(76, <<M_time:32/integer>>, Acc);

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
    encode_tlv(81, <<M_id:32/integer>>, Acc);

encode_v1_element(#linked_urr_id{
		       id = M_id}, Acc) ->
    encode_tlv(82, <<M_id:32/integer>>, Acc);

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
    encode_tlv(88, <<M_id:8/integer>>, Acc);

encode_v1_element(#cp_function_features{
		       flags = M_flags}, Acc) ->
    encode_tlv(89, <<(encode_min_int(8, encode_flags(M_flags, ['LOAD','OVRL','EPFAR','SSET',
                                          'BUNDL','MPAS','ARDR','UIAUR']), little))/binary>>, Acc);

encode_v1_element(#usage_information{
		       flags = M_flags}, Acc) ->
    encode_tlv(90, <<(encode_min_int(8, encode_flags(M_flags, ['BEF','AFT','UAE','UBE','_','_','_',
                                          '_']), little))/binary>>, Acc);

encode_v1_element(#application_instance_id{
		       id = M_id}, Acc) ->
    encode_tlv(91, <<M_id/binary>>, Acc);

encode_v1_element(#flow_information{
		       direction = M_direction,
		       flow = M_flow}, Acc) ->
    encode_tlv(92, <<0:4,
		     (enum_v1_flow_information_direction(M_direction)):4/integer,
		     (byte_size(M_flow)):16/integer, M_flow/binary>>, Acc);

encode_v1_element(#ue_ip_address{} = IE, Acc) ->
    encode_tlv(93, encode_ue_ip_address(IE), Acc);

encode_v1_element(#packet_rate{} = IE, Acc) ->
    encode_tlv(94, encode_packet_rate(IE), Acc);

encode_v1_element(#outer_header_removal{
		       header = M_header}, Acc) ->
    encode_tlv(95, <<(enum_v1_outer_header_removal_header(M_header)):8/integer>>, Acc);

encode_v1_element(#recovery_time_stamp{
		       time = M_time}, Acc) ->
    encode_tlv(96, <<M_time:32/integer>>, Acc);

encode_v1_element(#dl_flow_level_marking{} = IE, Acc) ->
    encode_tlv(97, encode_dl_flow_level_marking(IE), Acc);

encode_v1_element(#header_enrichment{
		       header_type = M_header_type,
		       name = M_name,
		       value = M_value}, Acc) ->
    encode_tlv(98, <<0:4,
		     (enum_v1_header_enrichment_header_type(M_header_type)):4/integer,
		     (byte_size(M_name)):8/integer, M_name/binary,
		     (byte_size(M_value)):8/integer, M_value/binary>>, Acc);

encode_v1_element(#error_indication_report{
		       group = M_group}, Acc) ->
    encode_tlv(99, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#measurement_information{
		       flags = M_flags}, Acc) ->
    encode_tlv(100, <<(encode_min_int(8, encode_flags(M_flags, ['MBQE','INAM','RADI','ISTM','MNOP',
                                          '_','_','_']), little))/binary>>, Acc);

encode_v1_element(#node_report_type{
		       flags = M_flags}, Acc) ->
    encode_tlv(101, <<(encode_min_int(8, encode_flags(M_flags, ['UPFR','UPRR','CKDR','GPQR','_','_',
                                          '_','_']), little))/binary>>, Acc);

encode_v1_element(#user_plane_path_failure_report{
		       group = M_group}, Acc) ->
    encode_tlv(102, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#remote_gtp_u_peer{} = IE, Acc) ->
    encode_tlv(103, encode_remote_peer(IE), Acc);

encode_v1_element(#ur_seqn{
		       number = M_number}, Acc) ->
    encode_tlv(104, <<M_number:32/integer>>, Acc);

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
    encode_tlv(108, <<M_id:32/integer>>, Acc);

encode_v1_element(#qer_id{
		       id = M_id}, Acc) ->
    encode_tlv(109, <<M_id:32/integer>>, Acc);

encode_v1_element(#oci_flags{
		       flags = M_flags}, Acc) ->
    encode_tlv(110, <<(encode_min_int(8, encode_flags(M_flags, ['AOCI','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#sx_association_release_request{
		       flags = M_flags}, Acc) ->
    encode_tlv(111, <<(encode_min_int(8, encode_flags(M_flags, ['SARR','URSS','_','_','_','_','_',
                                          '_']), little))/binary>>, Acc);

encode_v1_element(#graceful_release_period{
		       release_timer_unit = M_release_timer_unit,
		       release_timer_value = M_release_timer_value}, Acc) ->
    encode_tlv(112, <<(enum_v1_graceful_release_period_release_timer_unit(M_release_timer_unit)):3/integer,
		      M_release_timer_value:5/integer>>, Acc);

encode_v1_element(#pdn_type{
		       pdn_type = M_pdn_type}, Acc) ->
    encode_tlv(113, <<0:5,
		      (enum_v1_pdn_type_pdn_type(M_pdn_type)):3/integer>>, Acc);

encode_v1_element(#failed_rule_id{} = IE, Acc) ->
    encode_tlv(114, encode_failed_rule_id(IE), Acc);

encode_v1_element(#time_quota_mechanism{
		       base_time_interval_type = M_base_time_interval_type,
		       interval = M_interval}, Acc) ->
    encode_tlv(115, <<0:6,
		      (enum_v1_time_quota_mechanism_base_time_interval_type(M_base_time_interval_type)):2/integer,
		      M_interval:32/integer>>, Acc);

encode_v1_element(#user_plane_ip_resource_information{} = IE, Acc) ->
    encode_tlv(116, encode_user_plane_ip_resource_information(IE), Acc);

encode_v1_element(#user_plane_inactivity_timer{
		       timer = M_timer}, Acc) ->
    encode_tlv(117, <<M_timer:32/integer>>, Acc);

encode_v1_element(#aggregated_urrs{
		       group = M_group}, Acc) ->
    encode_tlv(118, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#multiplier{
		       digits = M_digits,
		       exponent = M_exponent}, Acc) ->
    encode_tlv(119, <<M_digits:64/signed-integer,
		      M_exponent:32/signed-integer>>, Acc);

encode_v1_element(#aggregated_urr_id{
		       id = M_id}, Acc) ->
    encode_tlv(120, <<M_id:32/integer>>, Acc);

encode_v1_element(#subsequent_volume_quota{} = IE, Acc) ->
    encode_tlv(121, encode_volume_threshold(IE), Acc);

encode_v1_element(#subsequent_time_quota{
		       quota = M_quota}, Acc) ->
    encode_tlv(122, <<M_quota:32/integer>>, Acc);

encode_v1_element(#rqi{
		       flags = M_flags}, Acc) ->
    encode_tlv(123, <<(encode_min_int(8, encode_flags(M_flags, ['RQI','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#qfi{
		       qfi = M_qfi}, Acc) ->
    encode_tlv(124, <<0:2,
		      M_qfi:6/integer>>, Acc);

encode_v1_element(#query_urr_reference{
		       reference = M_reference}, Acc) ->
    encode_tlv(125, <<M_reference:32/integer>>, Acc);

encode_v1_element(#additional_usage_reports_information{
		       auri = M_auri,
		       reports = M_reports}, Acc) ->
    encode_tlv(126, <<M_auri:1/integer,
		      M_reports:15/integer>>, Acc);

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
    encode_tlv(131, <<M_id:8/integer>>, Acc);

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
    encode_tlv(136, <<M_type:16/integer>>, Acc);

encode_v1_element(#proxying{
		       flags = M_flags}, Acc) ->
    encode_tlv(137, <<(encode_min_int(8, encode_flags(M_flags, ['ARP','INS','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#ethernet_filter_id{
		       id = M_id}, Acc) ->
    encode_tlv(138, <<M_id:32/integer>>, Acc);

encode_v1_element(#ethernet_filter_properties{
		       flags = M_flags}, Acc) ->
    encode_tlv(139, <<(encode_min_int(8, encode_flags(M_flags, ['BIDE','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#suggested_buffering_packets_count{
		       count = M_count}, Acc) ->
    encode_tlv(140, <<M_count:8/integer>>, Acc);

encode_v1_element(#user_id{} = IE, Acc) ->
    encode_tlv(141, encode_user_id(IE), Acc);

encode_v1_element(#ethernet_pdu_session_information{
		       flags = M_flags}, Acc) ->
    encode_tlv(142, <<(encode_min_int(8, encode_flags(M_flags, ['ETHI','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#ethernet_traffic_information{
		       group = M_group}, Acc) ->
    encode_tlv(143, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#mac_addresses_detected{} = IE, Acc) ->
    encode_tlv(144, encode_mac_addresses(IE), Acc);

encode_v1_element(#mac_addresses_removed{} = IE, Acc) ->
    encode_tlv(145, encode_mac_addresses(IE), Acc);

encode_v1_element(#ethernet_inactivity_timer{
		       timer = M_timer}, Acc) ->
    encode_tlv(146, <<M_timer:32/integer>>, Acc);

encode_v1_element(#additional_monitoring_time{
		       group = M_group}, Acc) ->
    encode_tlv(147, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#event_quota{
		       quota = M_quota}, Acc) ->
    encode_tlv(148, <<M_quota:32/integer>>, Acc);

encode_v1_element(#event_threshold{
		       threshold = M_threshold}, Acc) ->
    encode_tlv(149, <<M_threshold:32/integer>>, Acc);

encode_v1_element(#subsequent_event_quota{
		       quota = M_quota}, Acc) ->
    encode_tlv(150, <<M_quota:32/integer>>, Acc);

encode_v1_element(#subsequent_event_threshold{
		       threshold = M_threshold}, Acc) ->
    encode_tlv(151, <<M_threshold:32/integer>>, Acc);

encode_v1_element(#trace_information{
		       mcc = M_mcc,
		       mnc = M_mnc,
		       trace_id = M_trace_id,
		       events = M_events,
		       session_trace_depth = M_session_trace_depth,
		       interfaces = M_interfaces,
		       ip_address = M_ip_address}, Acc) ->
    encode_tlv(152, <<(encode_mccmnc(M_mcc, M_mnc))/binary,
		      M_trace_id:3/binary,
		      (byte_size(M_events)):8/integer, M_events/binary,
		      M_session_trace_depth:8/integer,
		      (byte_size(M_interfaces)):8/integer, M_interfaces/binary,
		      (byte_size(M_ip_address)):8/integer, M_ip_address/binary>>, Acc);

encode_v1_element(#framed_route{
		       value = M_value}, Acc) ->
    encode_tlv(153, <<M_value/binary>>, Acc);

encode_v1_element(#framed_routing{
		       value = M_value}, Acc) ->
    encode_tlv(154, <<M_value:32/integer>>, Acc);

encode_v1_element(#framed_ipv6_route{
		       value = M_value}, Acc) ->
    encode_tlv(155, <<M_value/binary>>, Acc);

encode_v1_element(#event_time_stamp{
		       time = M_time}, Acc) ->
    encode_tlv(156, <<M_time:32/integer>>, Acc);

encode_v1_element(#averaging_window{
		       window = M_window}, Acc) ->
    encode_tlv(157, <<M_window:32/integer>>, Acc);

encode_v1_element(#paging_policy_indicator{
		       ppi = M_ppi}, Acc) ->
    encode_tlv(158, <<0:5,
		      M_ppi:3/integer>>, Acc);

encode_v1_element(#apn_dnn{
		       apn = M_apn}, Acc) ->
    encode_tlv(159, <<(encode_fqdn(M_apn))/binary>>, Acc);

encode_v1_element(#tgpp_interface_type{
		       type = M_type}, Acc) ->
    encode_tlv(160, <<0:2,
		      (enum_v1_tgpp_interface_type_type(M_type)):6/integer>>, Acc);

encode_v1_element(#pfcpsrreq_flags{
		       flags = M_flags}, Acc) ->
    encode_tlv(161, <<(encode_min_int(8, encode_flags(M_flags, ['PSDBU','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#pfcpaureq_flags{
		       flags = M_flags}, Acc) ->
    encode_tlv(162, <<(encode_min_int(8, encode_flags(M_flags, ['PARPS','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#activation_time{
		       time = M_time}, Acc) ->
    encode_tlv(163, <<M_time:32/integer>>, Acc);

encode_v1_element(#deactivation_time{
		       time = M_time}, Acc) ->
    encode_tlv(164, <<M_time:32/integer>>, Acc);

encode_v1_element(#create_mar{
		       group = M_group}, Acc) ->
    encode_tlv(165, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#tgpp_access_forwarding_action_information{
		       group = M_group}, Acc) ->
    encode_tlv(166, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#non_tgpp_access_forwarding_action_information{
		       group = M_group}, Acc) ->
    encode_tlv(167, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#remove_mar{
		       group = M_group}, Acc) ->
    encode_tlv(168, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#update_mar{
		       group = M_group}, Acc) ->
    encode_tlv(169, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#mar_id{
		       id = M_id}, Acc) ->
    encode_tlv(170, <<M_id:16/integer>>, Acc);

encode_v1_element(#steering_functionality{
		       functionality = M_functionality}, Acc) ->
    encode_tlv(171, <<0:4,
		      (enum_v1_steering_functionality_functionality(M_functionality)):4/integer>>, Acc);

encode_v1_element(#steering_mode{
		       mode = M_mode}, Acc) ->
    encode_tlv(172, <<0:4,
		      (enum_v1_steering_mode_mode(M_mode)):4/integer>>, Acc);

encode_v1_element(#weight{
		       value = M_value}, Acc) ->
    encode_tlv(173, <<M_value:32/integer>>, Acc);

encode_v1_element(#priority{
		       priority = M_priority}, Acc) ->
    encode_tlv(174, <<0:4,
		      M_priority:4/integer>>, Acc);

encode_v1_element(#update_tgpp_access_forwarding_action_information{
		       group = M_group}, Acc) ->
    encode_tlv(175, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#update_non_tgpp_access_forwarding_action_information{
		       group = M_group}, Acc) ->
    encode_tlv(176, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#ue_ip_address_pool_identity{
		       identity = M_identity}, Acc) ->
    encode_tlv(177, <<(byte_size(M_identity)):16/integer, M_identity/binary>>, Acc);

encode_v1_element(#alternative_smf_ip_address{} = IE, Acc) ->
    encode_tlv(178, encode_alternative_smf_ip_address(IE), Acc);

encode_v1_element(#packet_replication_and_detection_carry_on_information{
		       flags = M_flags}, Acc) ->
    encode_tlv(179, <<(encode_min_int(8, encode_flags(M_flags, ['PRIUEAI','PRIN19I','PRIN6I',
                                          'DCARONI','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#smf_set_id{
		       fqdn = M_fqdn}, Acc) ->
    encode_tlv(180, <<0:8,
		      (encode_fqdn(M_fqdn))/binary>>, Acc);

encode_v1_element(#quota_validity_time{
		       time = M_time}, Acc) ->
    encode_tlv(181, <<M_time:32/integer>>, Acc);

encode_v1_element(#number_of_reports{
		       reports = M_reports}, Acc) ->
    encode_tlv(182, <<M_reports:16/integer>>, Acc);

encode_v1_element(#pfcp_session_retention_information{
		       group = M_group}, Acc) ->
    encode_tlv(183, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#pfcpasrsp_flags{
		       flags = M_flags}, Acc) ->
    encode_tlv(184, <<(encode_min_int(8, encode_flags(M_flags, ['PSREI','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#cp_pfcp_entity_ip_address{} = IE, Acc) ->
    encode_tlv(185, encode_cp_pfcp_entity_ip_address(IE), Acc);

encode_v1_element(#pfcpsereq_flags{
		       flags = M_flags}, Acc) ->
    encode_tlv(186, <<(encode_min_int(8, encode_flags(M_flags, ['RESTI','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#user_plane_path_recovery_report{
		       group = M_group}, Acc) ->
    encode_tlv(187, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#ip_multicast_addressing_info{
		       group = M_group}, Acc) ->
    encode_tlv(188, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#join_ip_multicast_information{
		       group = M_group}, Acc) ->
    encode_tlv(189, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#leave_ip_multicast_information{
		       group = M_group}, Acc) ->
    encode_tlv(190, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#ip_multicast_address{} = IE, Acc) ->
    encode_tlv(191, encode_ip_multicast_address(IE), Acc);

encode_v1_element(#source_ip_address{} = IE, Acc) ->
    encode_tlv(192, encode_source_ip_address(IE), Acc);

encode_v1_element(#packet_rate_status{} = IE, Acc) ->
    encode_tlv(193, encode_packet_rate_status(IE), Acc);

encode_v1_element(#create_bridge_info_for_tsc{
		       flags = M_flags}, Acc) ->
    encode_tlv(194, <<(encode_min_int(8, encode_flags(M_flags, ['BII','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#created_bridge_info_for_tsc{
		       group = M_group}, Acc) ->
    encode_tlv(195, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#ds_tt_port_number{
		       value = M_value}, Acc) ->
    encode_tlv(196, <<M_value:32/integer>>, Acc);

encode_v1_element(#nw_tt_port_number{
		       value = M_value}, Acc) ->
    encode_tlv(197, <<M_value:32/integer>>, Acc);

encode_v1_element(#tsn_bridge_id{} = IE, Acc) ->
    encode_tlv(198, encode_tsn_bridge_id(IE), Acc);

encode_v1_element(#port_management_information_for_tsc{
		       group = M_group}, Acc) ->
    encode_tlv(199, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#port_management_information_for_tsc_smr{
		       group = M_group}, Acc) ->
    encode_tlv(200, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#port_management_information_for_tsc_sdr{
		       group = M_group}, Acc) ->
    encode_tlv(201, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#port_management_information_container{
		       value = M_value}, Acc) ->
    encode_tlv(202, <<M_value/binary>>, Acc);

encode_v1_element(#clock_drift_control_information{
		       group = M_group}, Acc) ->
    encode_tlv(203, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#requested_clock_drift_information{
		       flags = M_flags}, Acc) ->
    encode_tlv(204, <<(encode_min_int(8, encode_flags(M_flags, ['RRTO','RRCR','_','_','_','_','_',
                                          '_']), little))/binary>>, Acc);

encode_v1_element(#clock_drift_report{
		       group = M_group}, Acc) ->
    encode_tlv(205, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#tsn_time_domain_number{
		       number = M_number}, Acc) ->
    encode_tlv(206, <<M_number:8/integer>>, Acc);

encode_v1_element(#time_offset_threshold{
		       threshold = M_threshold}, Acc) ->
    encode_tlv(207, <<M_threshold:64/signed-integer>>, Acc);

encode_v1_element(#cumulative_rateratio_threshold{
		       threshold = M_threshold}, Acc) ->
    encode_tlv(208, <<M_threshold:32/integer>>, Acc);

encode_v1_element(#time_offset_measurement{
		       measurement = M_measurement}, Acc) ->
    encode_tlv(209, <<M_measurement:64/signed-integer>>, Acc);

encode_v1_element(#cumulative_rateratio_measurement{
		       measurement = M_measurement}, Acc) ->
    encode_tlv(210, <<M_measurement:32/integer>>, Acc);

encode_v1_element(#remove_srr{
		       group = M_group}, Acc) ->
    encode_tlv(211, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#create_srr{
		       group = M_group}, Acc) ->
    encode_tlv(212, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#update_srr{
		       group = M_group}, Acc) ->
    encode_tlv(213, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#session_report{
		       group = M_group}, Acc) ->
    encode_tlv(214, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#srr_id{
		       id = M_id}, Acc) ->
    encode_tlv(215, <<M_id:8/integer>>, Acc);

encode_v1_element(#access_availability_control_information{
		       group = M_group}, Acc) ->
    encode_tlv(216, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#requested_access_availability_information{
		       flags = M_flags}, Acc) ->
    encode_tlv(217, <<(encode_min_int(8, encode_flags(M_flags, ['RRCA','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#access_availability_report{
		       group = M_group}, Acc) ->
    encode_tlv(218, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#access_availability_information{
		       status = M_status,
		       type = M_type}, Acc) ->
    encode_tlv(219, <<0:4,
		      (enum_v1_access_availability_information_status(M_status)):2/integer,
		      (enum_v1_access_availability_information_type(M_type)):2/integer>>, Acc);

encode_v1_element(#provide_atsss_control_information{
		       group = M_group}, Acc) ->
    encode_tlv(220, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#atsss_control_parameters{
		       group = M_group}, Acc) ->
    encode_tlv(221, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#mptcp_control_information{
		       flags = M_flags}, Acc) ->
    encode_tlv(222, <<(encode_min_int(8, encode_flags(M_flags, ['TCI','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#atsss_ll_control_information{
		       flags = M_flags}, Acc) ->
    encode_tlv(223, <<(encode_min_int(8, encode_flags(M_flags, ['LLI','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#pmf_control_information{
		       flags = M_flags}, Acc) ->
    encode_tlv(224, <<(encode_min_int(8, encode_flags(M_flags, ['PMFI','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#mptcp_parameters{
		       group = M_group}, Acc) ->
    encode_tlv(225, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#atsss_ll_parameters{
		       group = M_group}, Acc) ->
    encode_tlv(226, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#pmf_parameters{
		       group = M_group}, Acc) ->
    encode_tlv(227, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#mptcp_address_information{} = IE, Acc) ->
    encode_tlv(228, encode_mptcp_address_information(IE), Acc);

encode_v1_element(#ue_link_specific_ip_address{} = IE, Acc) ->
    encode_tlv(229, encode_ue_link_specific_ip_address(IE), Acc);

encode_v1_element(#pmf_address_information{} = IE, Acc) ->
    encode_tlv(230, encode_pmf_address_information(IE), Acc);

encode_v1_element(#atsss_ll_information{
		       flags = M_flags}, Acc) ->
    encode_tlv(231, <<(encode_min_int(8, encode_flags(M_flags, ['LLI','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#data_network_access_identifier{
		       value = M_value}, Acc) ->
    encode_tlv(232, <<M_value/binary>>, Acc);

encode_v1_element(#ue_ip_address_pool_information{
		       group = M_group}, Acc) ->
    encode_tlv(233, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#average_packet_delay{
		       delay = M_delay}, Acc) ->
    encode_tlv(234, <<M_delay:32/integer>>, Acc);

encode_v1_element(#minimum_packet_delay{
		       delay = M_delay}, Acc) ->
    encode_tlv(235, <<M_delay:32/integer>>, Acc);

encode_v1_element(#maximum_packet_delay{
		       delay = M_delay}, Acc) ->
    encode_tlv(236, <<M_delay:32/integer>>, Acc);

encode_v1_element(#qos_report_trigger{
		       flags = M_flags}, Acc) ->
    encode_tlv(237, <<(encode_min_int(8, encode_flags(M_flags, ['PER','THR','IRE','_','_','_','_',
                                          '_']), little))/binary>>, Acc);

encode_v1_element(#gtp_u_path_qos_control_information{
		       group = M_group}, Acc) ->
    encode_tlv(238, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#gtp_u_path_qos_report{
		       group = M_group}, Acc) ->
    encode_tlv(239, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#path_report_qos_information{
		       group = M_group}, Acc) ->
    encode_tlv(240, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#gtp_u_path_interface_type{
		       flags = M_flags}, Acc) ->
    encode_tlv(241, <<(encode_min_int(8, encode_flags(M_flags, ['N9','N3','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#qos_monitoring_per_qos_flow_control_information{
		       group = M_group}, Acc) ->
    encode_tlv(242, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#requested_qos_monitoring{
		       flags = M_flags}, Acc) ->
    encode_tlv(243, <<(encode_min_int(8, encode_flags(M_flags, ['DL','UL','RP','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#reporting_frequency{
		       flags = M_flags}, Acc) ->
    encode_tlv(244, <<(encode_min_int(8, encode_flags(M_flags, ['EVETT','PERIO','SESRL','_','_','_',
                                          '_','_']), little))/binary>>, Acc);

encode_v1_element(#packet_delay_thresholds{} = IE, Acc) ->
    encode_tlv(245, encode_packet_delay_thresholds(IE), Acc);

encode_v1_element(#minimum_wait_time{
		       time = M_time}, Acc) ->
    encode_tlv(246, <<M_time:32/integer>>, Acc);

encode_v1_element(#qos_monitoring_report{
		       group = M_group}, Acc) ->
    encode_tlv(247, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#qos_monitoring_measurement{} = IE, Acc) ->
    encode_tlv(248, encode_qos_monitoring_measurement(IE), Acc);

encode_v1_element(#mt_edt_control_information{
		       flags = M_flags}, Acc) ->
    encode_tlv(249, <<(encode_min_int(8, encode_flags(M_flags, ['RDSI','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#dl_data_packets_size{
		       size = M_size}, Acc) ->
    encode_tlv(250, <<M_size:16/integer>>, Acc);

encode_v1_element(#qer_control_indications{
		       flags = M_flags}, Acc) ->
    encode_tlv(251, <<(encode_min_int(8, encode_flags(M_flags, ['RCSRT','MOED','NORD','_','_','_',
                                          '_','_']), little))/binary>>, Acc);

encode_v1_element(#packet_rate_status_report{
		       group = M_group}, Acc) ->
    encode_tlv(252, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#nf_instance_id{
		       value = M_value}, Acc) ->
    encode_tlv(253, <<M_value:16/binary>>, Acc);

encode_v1_element(#ethernet_context_information{
		       group = M_group}, Acc) ->
    encode_tlv(254, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#redundant_transmission_parameters{
		       group = M_group}, Acc) ->
    encode_tlv(255, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#updated_pdr{
		       group = M_group}, Acc) ->
    encode_tlv(256, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#s_nssai{
		       sst = M_sst,
		       sd = M_sd}, Acc) ->
    encode_tlv(257, <<M_sst:8/integer,
		      M_sd:24/integer>>, Acc);

encode_v1_element(#ip_version{
		       flags = M_flags}, Acc) ->
    encode_tlv(258, <<(encode_min_int(8, encode_flags(M_flags, ['V4','V6','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#pfcpasreq_flags{
		       flags = M_flags}, Acc) ->
    encode_tlv(259, <<(encode_min_int(8, encode_flags(M_flags, ['UUPSI','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#data_status{
		       flags = M_flags}, Acc) ->
    encode_tlv(260, <<(encode_min_int(8, encode_flags(M_flags, ['DROP','BUFF','_','_','_','_','_',
                                          '_']), little))/binary>>, Acc);

encode_v1_element(#provide_rds_configuration_information{
		       group = M_group}, Acc) ->
    encode_tlv(261, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#rds_configuration_information{
		       flags = M_flags}, Acc) ->
    encode_tlv(262, <<(encode_min_int(8, encode_flags(M_flags, ['RDS','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#query_packet_rate_status_ie_smreq{
		       group = M_group}, Acc) ->
    encode_tlv(263, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#packet_rate_status_report_ie_smresp{
		       group = M_group}, Acc) ->
    encode_tlv(264, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#mptcp_applicable_indication{
		       flags = M_flags}, Acc) ->
    encode_tlv(265, <<(encode_min_int(8, encode_flags(M_flags, ['MAI','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#bridge_management_information_container{
		       value = M_value}, Acc) ->
    encode_tlv(266, <<M_value/binary>>, Acc);

encode_v1_element(#ue_ip_address_usage_information{
		       group = M_group}, Acc) ->
    encode_tlv(267, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#number_of_ue_ip_addresses{} = IE, Acc) ->
    encode_tlv(268, encode_number_of_ue_ip_addresses(IE), Acc);

encode_v1_element(#validity_timer{
		       validity_timer = M_validity_timer}, Acc) ->
    encode_tlv(269, <<M_validity_timer:16/integer>>, Acc);

encode_v1_element(#redundant_transmission_forwarding{
		       group = M_group}, Acc) ->
    encode_tlv(270, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#transport_delay_reporting{
		       group = M_group}, Acc) ->
    encode_tlv(271, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#bbf_up_function_features{
		       flags = M_flags}, Acc) ->
    encode_tlv({3561,0}, <<(encode_min_int(32, encode_flags(M_flags, ['PPPoE','IPoE','LAC','LNS',
                                           'LCP keepalive offload','NAT-CP',
                                           'NAT-UP','_']), little))/binary>>, Acc);

encode_v1_element(#logical_port{
		       port = M_port}, Acc) ->
    encode_tlv({3561,1}, <<M_port/binary>>, Acc);

encode_v1_element(#bbf_outer_header_creation{
		       flags = M_flags,
		       tunnel_id = M_tunnel_id,
		       session_id = M_session_id}, Acc) ->
    encode_tlv({3561,2}, <<(encode_min_int(16, encode_flags(M_flags, ['PPP','L2TP','Traffic-Endpoint',
                                           'CPR-NSH','_','_','_','_']), little))/binary,
			   M_tunnel_id:16/integer,
			   M_session_id:16/integer>>, Acc);

encode_v1_element(#bbf_outer_header_removal{
		       header = M_header}, Acc) ->
    encode_tlv({3561,3}, <<(enum_v1_bbf_outer_header_removal_header(M_header)):8/integer>>, Acc);

encode_v1_element(#pppoe_session_id{
		       id = M_id}, Acc) ->
    encode_tlv({3561,4}, <<M_id:16/integer>>, Acc);

encode_v1_element(#ppp_protocol{} = IE, Acc) ->
    encode_tlv({3561,5}, encode_ppp_protocol(IE), Acc);

encode_v1_element(#verification_timers{
		       interval = M_interval,
		       count = M_count}, Acc) ->
    encode_tlv({3561,6}, <<M_interval:16/integer,
			   M_count:8/integer>>, Acc);

encode_v1_element(#ppp_lcp_magic_number{
		       tx = M_tx,
		       rx = M_rx}, Acc) ->
    encode_tlv({3561,7}, <<M_tx:32/integer,
			   M_rx:32/integer>>, Acc);

encode_v1_element(#mtu{
		       mtu = M_mtu}, Acc) ->
    encode_tlv({3561,8}, <<M_mtu:16/integer>>, Acc);

encode_v1_element(#l2tp_tunnel_endpoint{} = IE, Acc) ->
    encode_tlv({3561,9}, encode_l2tp_tunnel_endpoint(IE), Acc);

encode_v1_element(#l2tp_session_id{
		       id = M_id}, Acc) ->
    encode_tlv({3561,10}, <<M_id:16/integer>>, Acc);

encode_v1_element(#l2tp_type{
		       flags = M_flags}, Acc) ->
    encode_tlv({3561,11}, <<(encode_min_int(8, encode_flags(M_flags, [type,'_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#ppp_lcp_connectivity{
		       group = M_group}, Acc) ->
    encode_tlv({3561,12}, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#l2tp_tunnel{
		       group = M_group}, Acc) ->
    encode_tlv({3561,13}, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#bbf_nat_outside_address{
		       ipv4 = M_ipv4}, Acc) ->
    encode_tlv({3561,14}, <<M_ipv4:4/bytes>>, Acc);

encode_v1_element(#bbf_apply_action{
		       flags = M_flags}, Acc) ->
    encode_tlv({3561,15}, <<(encode_min_int(8, encode_flags(M_flags, ['NAT','_','_','_','_','_','_','_']), little))/binary>>, Acc);

encode_v1_element(#bbf_nat_external_port_range{} = IE, Acc) ->
    encode_tlv({3561,16}, encode_bbf_nat_external_port_range(IE), Acc);

encode_v1_element(#bbf_nat_port_forward{} = IE, Acc) ->
    encode_tlv({3561,17}, encode_bbf_nat_port_forward(IE), Acc);

encode_v1_element(#bbf_nat_port_block{
		       block = M_block}, Acc) ->
    encode_tlv({3561,18}, <<M_block/binary>>, Acc);

encode_v1_element(#bbf_dynamic_port_block_starting_port{
		       start = M_start}, Acc) ->
    encode_tlv({3561,19}, <<M_start:16/integer>>, Acc);

encode_v1_element(#tp_packet_measurement{} = IE, Acc) ->
    encode_tlv({18681,1}, encode_volume_threshold(IE), Acc);

encode_v1_element(#tp_build_identifier{
		       id = M_id}, Acc) ->
    encode_tlv({18681,2}, <<M_id/binary>>, Acc);

encode_v1_element(#tp_now{
		       seconds = M_seconds,
		       fraction = M_fraction}, Acc) ->
    encode_tlv({18681,3}, <<M_seconds:32/integer,
			    M_fraction:32/integer>>, Acc);

encode_v1_element(#tp_start_time{
		       seconds = M_seconds,
		       fraction = M_fraction}, Acc) ->
    encode_tlv({18681,4}, <<M_seconds:32/integer,
			    M_fraction:32/integer>>, Acc);

encode_v1_element(#tp_stop_time{
		       seconds = M_seconds,
		       fraction = M_fraction}, Acc) ->
    encode_tlv({18681,5}, <<M_seconds:32/integer,
			    M_fraction:32/integer>>, Acc);

encode_v1_element(#tp_error_report{
		       group = M_group}, Acc) ->
    encode_tlv({18681,6}, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#tp_error_message{
		       message = M_message}, Acc) ->
    encode_tlv({18681,7}, <<M_message/binary>>, Acc);

encode_v1_element(#tp_file_name{
		       file_name = M_file_name}, Acc) ->
    encode_tlv({18681,8}, <<M_file_name/binary>>, Acc);

encode_v1_element(#tp_line_number{
		       line = M_line}, Acc) ->
    encode_tlv({18681,9}, <<M_line:32/integer>>, Acc);

encode_v1_element(#tp_created_nat_binding{
		       group = M_group}, Acc) ->
    encode_tlv({18681,10}, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#tp_ipfix_policy{
		       policy = M_policy}, Acc) ->
    encode_tlv({18681,11}, <<M_policy/binary>>, Acc);

encode_v1_element(#tp_trace_information{
		       group = M_group}, Acc) ->
    encode_tlv({18681,12}, <<(encode_v1_grouped(M_group))/binary>>, Acc);

encode_v1_element(#tp_trace_parent{
		       parent = M_parent}, Acc) ->
    encode_tlv({18681,13}, <<M_parent/binary>>, Acc);

encode_v1_element(#tp_trace_state{
		       state = M_state}, Acc) ->
    encode_tlv({18681,14}, <<M_state/binary>>, Acc);

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
?PRETTY_PRINT(pretty_print_v1, additional_monitoring_time);
?PRETTY_PRINT(pretty_print_v1, event_quota);
?PRETTY_PRINT(pretty_print_v1, event_threshold);
?PRETTY_PRINT(pretty_print_v1, subsequent_event_quota);
?PRETTY_PRINT(pretty_print_v1, subsequent_event_threshold);
?PRETTY_PRINT(pretty_print_v1, trace_information);
?PRETTY_PRINT(pretty_print_v1, framed_route);
?PRETTY_PRINT(pretty_print_v1, framed_routing);
?PRETTY_PRINT(pretty_print_v1, framed_ipv6_route);
?PRETTY_PRINT(pretty_print_v1, event_time_stamp);
?PRETTY_PRINT(pretty_print_v1, averaging_window);
?PRETTY_PRINT(pretty_print_v1, paging_policy_indicator);
?PRETTY_PRINT(pretty_print_v1, apn_dnn);
?PRETTY_PRINT(pretty_print_v1, tgpp_interface_type);
?PRETTY_PRINT(pretty_print_v1, pfcpsrreq_flags);
?PRETTY_PRINT(pretty_print_v1, pfcpaureq_flags);
?PRETTY_PRINT(pretty_print_v1, activation_time);
?PRETTY_PRINT(pretty_print_v1, deactivation_time);
?PRETTY_PRINT(pretty_print_v1, create_mar);
?PRETTY_PRINT(pretty_print_v1, tgpp_access_forwarding_action_information);
?PRETTY_PRINT(pretty_print_v1, non_tgpp_access_forwarding_action_information);
?PRETTY_PRINT(pretty_print_v1, remove_mar);
?PRETTY_PRINT(pretty_print_v1, update_mar);
?PRETTY_PRINT(pretty_print_v1, mar_id);
?PRETTY_PRINT(pretty_print_v1, steering_functionality);
?PRETTY_PRINT(pretty_print_v1, steering_mode);
?PRETTY_PRINT(pretty_print_v1, weight);
?PRETTY_PRINT(pretty_print_v1, priority);
?PRETTY_PRINT(pretty_print_v1, update_tgpp_access_forwarding_action_information);
?PRETTY_PRINT(pretty_print_v1, update_non_tgpp_access_forwarding_action_information);
?PRETTY_PRINT(pretty_print_v1, ue_ip_address_pool_identity);
?PRETTY_PRINT(pretty_print_v1, alternative_smf_ip_address);
?PRETTY_PRINT(pretty_print_v1, packet_replication_and_detection_carry_on_information);
?PRETTY_PRINT(pretty_print_v1, smf_set_id);
?PRETTY_PRINT(pretty_print_v1, quota_validity_time);
?PRETTY_PRINT(pretty_print_v1, number_of_reports);
?PRETTY_PRINT(pretty_print_v1, pfcp_session_retention_information);
?PRETTY_PRINT(pretty_print_v1, pfcpasrsp_flags);
?PRETTY_PRINT(pretty_print_v1, cp_pfcp_entity_ip_address);
?PRETTY_PRINT(pretty_print_v1, pfcpsereq_flags);
?PRETTY_PRINT(pretty_print_v1, user_plane_path_recovery_report);
?PRETTY_PRINT(pretty_print_v1, ip_multicast_addressing_info);
?PRETTY_PRINT(pretty_print_v1, join_ip_multicast_information);
?PRETTY_PRINT(pretty_print_v1, leave_ip_multicast_information);
?PRETTY_PRINT(pretty_print_v1, ip_multicast_address);
?PRETTY_PRINT(pretty_print_v1, source_ip_address);
?PRETTY_PRINT(pretty_print_v1, packet_rate_status);
?PRETTY_PRINT(pretty_print_v1, create_bridge_info_for_tsc);
?PRETTY_PRINT(pretty_print_v1, created_bridge_info_for_tsc);
?PRETTY_PRINT(pretty_print_v1, ds_tt_port_number);
?PRETTY_PRINT(pretty_print_v1, nw_tt_port_number);
?PRETTY_PRINT(pretty_print_v1, tsn_bridge_id);
?PRETTY_PRINT(pretty_print_v1, port_management_information_for_tsc);
?PRETTY_PRINT(pretty_print_v1, port_management_information_for_tsc_smr);
?PRETTY_PRINT(pretty_print_v1, port_management_information_for_tsc_sdr);
?PRETTY_PRINT(pretty_print_v1, port_management_information_container);
?PRETTY_PRINT(pretty_print_v1, clock_drift_control_information);
?PRETTY_PRINT(pretty_print_v1, requested_clock_drift_information);
?PRETTY_PRINT(pretty_print_v1, clock_drift_report);
?PRETTY_PRINT(pretty_print_v1, tsn_time_domain_number);
?PRETTY_PRINT(pretty_print_v1, time_offset_threshold);
?PRETTY_PRINT(pretty_print_v1, cumulative_rateratio_threshold);
?PRETTY_PRINT(pretty_print_v1, time_offset_measurement);
?PRETTY_PRINT(pretty_print_v1, cumulative_rateratio_measurement);
?PRETTY_PRINT(pretty_print_v1, remove_srr);
?PRETTY_PRINT(pretty_print_v1, create_srr);
?PRETTY_PRINT(pretty_print_v1, update_srr);
?PRETTY_PRINT(pretty_print_v1, session_report);
?PRETTY_PRINT(pretty_print_v1, srr_id);
?PRETTY_PRINT(pretty_print_v1, access_availability_control_information);
?PRETTY_PRINT(pretty_print_v1, requested_access_availability_information);
?PRETTY_PRINT(pretty_print_v1, access_availability_report);
?PRETTY_PRINT(pretty_print_v1, access_availability_information);
?PRETTY_PRINT(pretty_print_v1, provide_atsss_control_information);
?PRETTY_PRINT(pretty_print_v1, atsss_control_parameters);
?PRETTY_PRINT(pretty_print_v1, mptcp_control_information);
?PRETTY_PRINT(pretty_print_v1, atsss_ll_control_information);
?PRETTY_PRINT(pretty_print_v1, pmf_control_information);
?PRETTY_PRINT(pretty_print_v1, mptcp_parameters);
?PRETTY_PRINT(pretty_print_v1, atsss_ll_parameters);
?PRETTY_PRINT(pretty_print_v1, pmf_parameters);
?PRETTY_PRINT(pretty_print_v1, mptcp_address_information);
?PRETTY_PRINT(pretty_print_v1, ue_link_specific_ip_address);
?PRETTY_PRINT(pretty_print_v1, pmf_address_information);
?PRETTY_PRINT(pretty_print_v1, atsss_ll_information);
?PRETTY_PRINT(pretty_print_v1, data_network_access_identifier);
?PRETTY_PRINT(pretty_print_v1, ue_ip_address_pool_information);
?PRETTY_PRINT(pretty_print_v1, average_packet_delay);
?PRETTY_PRINT(pretty_print_v1, minimum_packet_delay);
?PRETTY_PRINT(pretty_print_v1, maximum_packet_delay);
?PRETTY_PRINT(pretty_print_v1, qos_report_trigger);
?PRETTY_PRINT(pretty_print_v1, gtp_u_path_qos_control_information);
?PRETTY_PRINT(pretty_print_v1, gtp_u_path_qos_report);
?PRETTY_PRINT(pretty_print_v1, path_report_qos_information);
?PRETTY_PRINT(pretty_print_v1, gtp_u_path_interface_type);
?PRETTY_PRINT(pretty_print_v1, qos_monitoring_per_qos_flow_control_information);
?PRETTY_PRINT(pretty_print_v1, requested_qos_monitoring);
?PRETTY_PRINT(pretty_print_v1, reporting_frequency);
?PRETTY_PRINT(pretty_print_v1, packet_delay_thresholds);
?PRETTY_PRINT(pretty_print_v1, minimum_wait_time);
?PRETTY_PRINT(pretty_print_v1, qos_monitoring_report);
?PRETTY_PRINT(pretty_print_v1, qos_monitoring_measurement);
?PRETTY_PRINT(pretty_print_v1, mt_edt_control_information);
?PRETTY_PRINT(pretty_print_v1, dl_data_packets_size);
?PRETTY_PRINT(pretty_print_v1, qer_control_indications);
?PRETTY_PRINT(pretty_print_v1, packet_rate_status_report);
?PRETTY_PRINT(pretty_print_v1, nf_instance_id);
?PRETTY_PRINT(pretty_print_v1, ethernet_context_information);
?PRETTY_PRINT(pretty_print_v1, redundant_transmission_parameters);
?PRETTY_PRINT(pretty_print_v1, updated_pdr);
?PRETTY_PRINT(pretty_print_v1, s_nssai);
?PRETTY_PRINT(pretty_print_v1, ip_version);
?PRETTY_PRINT(pretty_print_v1, pfcpasreq_flags);
?PRETTY_PRINT(pretty_print_v1, data_status);
?PRETTY_PRINT(pretty_print_v1, provide_rds_configuration_information);
?PRETTY_PRINT(pretty_print_v1, rds_configuration_information);
?PRETTY_PRINT(pretty_print_v1, query_packet_rate_status_ie_smreq);
?PRETTY_PRINT(pretty_print_v1, packet_rate_status_report_ie_smresp);
?PRETTY_PRINT(pretty_print_v1, mptcp_applicable_indication);
?PRETTY_PRINT(pretty_print_v1, bridge_management_information_container);
?PRETTY_PRINT(pretty_print_v1, ue_ip_address_usage_information);
?PRETTY_PRINT(pretty_print_v1, number_of_ue_ip_addresses);
?PRETTY_PRINT(pretty_print_v1, validity_timer);
?PRETTY_PRINT(pretty_print_v1, redundant_transmission_forwarding);
?PRETTY_PRINT(pretty_print_v1, transport_delay_reporting);
?PRETTY_PRINT(pretty_print_v1, bbf_up_function_features);
?PRETTY_PRINT(pretty_print_v1, logical_port);
?PRETTY_PRINT(pretty_print_v1, bbf_outer_header_creation);
?PRETTY_PRINT(pretty_print_v1, bbf_outer_header_removal);
?PRETTY_PRINT(pretty_print_v1, pppoe_session_id);
?PRETTY_PRINT(pretty_print_v1, ppp_protocol);
?PRETTY_PRINT(pretty_print_v1, verification_timers);
?PRETTY_PRINT(pretty_print_v1, ppp_lcp_magic_number);
?PRETTY_PRINT(pretty_print_v1, mtu);
?PRETTY_PRINT(pretty_print_v1, l2tp_tunnel_endpoint);
?PRETTY_PRINT(pretty_print_v1, l2tp_session_id);
?PRETTY_PRINT(pretty_print_v1, l2tp_type);
?PRETTY_PRINT(pretty_print_v1, ppp_lcp_connectivity);
?PRETTY_PRINT(pretty_print_v1, l2tp_tunnel);
?PRETTY_PRINT(pretty_print_v1, bbf_nat_outside_address);
?PRETTY_PRINT(pretty_print_v1, bbf_apply_action);
?PRETTY_PRINT(pretty_print_v1, bbf_nat_external_port_range);
?PRETTY_PRINT(pretty_print_v1, bbf_nat_port_forward);
?PRETTY_PRINT(pretty_print_v1, bbf_nat_port_block);
?PRETTY_PRINT(pretty_print_v1, bbf_dynamic_port_block_starting_port);
?PRETTY_PRINT(pretty_print_v1, tp_packet_measurement);
?PRETTY_PRINT(pretty_print_v1, tp_build_identifier);
?PRETTY_PRINT(pretty_print_v1, tp_now);
?PRETTY_PRINT(pretty_print_v1, tp_start_time);
?PRETTY_PRINT(pretty_print_v1, tp_stop_time);
?PRETTY_PRINT(pretty_print_v1, tp_error_report);
?PRETTY_PRINT(pretty_print_v1, tp_error_message);
?PRETTY_PRINT(pretty_print_v1, tp_file_name);
?PRETTY_PRINT(pretty_print_v1, tp_line_number);
?PRETTY_PRINT(pretty_print_v1, tp_created_nat_binding);
?PRETTY_PRINT(pretty_print_v1, tp_ipfix_policy);
?PRETTY_PRINT(pretty_print_v1, tp_trace_information);
?PRETTY_PRINT(pretty_print_v1, tp_trace_parent);
?PRETTY_PRINT(pretty_print_v1, tp_trace_state);
pretty_print_v1(_, _) ->
    no.

v1_msg_defs() ->
    #{'N4' =>
	  #{association_release_request =>
		#{node_id => {'M',node_id},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    association_release_response =>
		#{node_id => {'M',node_id},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    association_setup_request =>
		#{alternative_smf_ip_address => {'O',alternative_smf_ip_address},
		  bbf_up_function_features => {'C',bbf_up_function_features},
		  clock_drift_control_information =>
		      {'O',
			  #{cumulative_rateratio_threshold =>
				{'C',cumulative_rateratio_threshold},
			    requested_clock_drift_information =>
				{'M',requested_clock_drift_information},
			    time_offset_threshold => {'C',time_offset_threshold},
			    tsn_time_domain_number => {'C',tsn_time_domain_number}}},
		  cp_function_features => {'C',cp_function_features},
		  gtp_u_path_qos_control_information =>
		      {'C',
			  #{average_packet_delay => {'C',average_packet_delay},
			    gtp_u_path_interface_type => {'C',gtp_u_path_interface_type},
			    maximum_packet_delay => {'C',maximum_packet_delay},
			    measurement_period => {'C',measurement_period},
			    minimum_packet_delay => {'C',minimum_packet_delay},
			    qos_report_trigger => {'M',qos_report_trigger},
			    remote_gtp_u_peer => {'C',remote_gtp_u_peer},
			    timer => {'C',timer},
			    transport_level_marking => {'C',transport_level_marking}}},
		  nf_instance_id => {'O',nf_instance_id},
		  node_id => {'M',node_id},
		  pfcp_session_retention_information =>
		      {'O',#{cp_pfcp_entity_ip_address => {'O',cp_pfcp_entity_ip_address}}},
		  pfcpasreq_flags => {'O',pfcpasreq_flags},
		  recovery_time_stamp => {'M',recovery_time_stamp},
		  smf_set_id => {'C',smf_set_id},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  ue_ip_address_pool_information =>
		      {'O',
			  #{ip_version => {'O',ip_version},
			    network_instance => {'O',network_instance},
			    s_nssai => {'O',s_nssai},
			    ue_ip_address_pool_identity =>
				{'M',ue_ip_address_pool_identity}}},
		  up_function_features => {'C',up_function_features},
		  user_plane_ip_resource_information =>
		      {'O',user_plane_ip_resource_information}},
	    association_setup_response =>
		#{alternative_smf_ip_address => {'O',alternative_smf_ip_address},
		  bbf_up_function_features => {'C',bbf_up_function_features},
		  clock_drift_control_information =>
		      {'C',
			  #{cumulative_rateratio_threshold =>
				{'C',cumulative_rateratio_threshold},
			    requested_clock_drift_information =>
				{'M',requested_clock_drift_information},
			    time_offset_threshold => {'C',time_offset_threshold},
			    tsn_time_domain_number => {'C',tsn_time_domain_number}}},
		  cp_function_features => {'C',cp_function_features},
		  gtp_u_path_qos_control_information =>
		      {'C',
			  #{average_packet_delay => {'C',average_packet_delay},
			    gtp_u_path_interface_type => {'C',gtp_u_path_interface_type},
			    maximum_packet_delay => {'C',maximum_packet_delay},
			    measurement_period => {'C',measurement_period},
			    minimum_packet_delay => {'C',minimum_packet_delay},
			    qos_report_trigger => {'M',qos_report_trigger},
			    remote_gtp_u_peer => {'C',remote_gtp_u_peer},
			    timer => {'C',timer},
			    transport_level_marking => {'C',transport_level_marking}}},
		  nf_instance_id => {'O',nf_instance_id},
		  node_id => {'M',node_id},
		  pfcp_cause => {'M',pfcp_cause},
		  pfcpasrsp_flags => {'O',pfcpasrsp_flags},
		  recovery_time_stamp => {'M',recovery_time_stamp},
		  smf_set_id => {'C',smf_set_id},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  ue_ip_address_pool_information =>
		      {'O',
			  #{ip_version => {'O',ip_version},
			    network_instance => {'O',network_instance},
			    s_nssai => {'O',s_nssai},
			    ue_ip_address_pool_identity =>
				{'M',ue_ip_address_pool_identity}}},
		  up_function_features => {'C',up_function_features},
		  user_plane_ip_resource_information =>
		      {'O',user_plane_ip_resource_information}},
	    association_update_request =>
		#{alternative_smf_ip_address => {'O',alternative_smf_ip_address},
		  bbf_up_function_features => {'C',bbf_up_function_features},
		  clock_drift_control_information =>
		      {'C',
			  #{cumulative_rateratio_threshold =>
				{'C',cumulative_rateratio_threshold},
			    requested_clock_drift_information =>
				{'M',requested_clock_drift_information},
			    time_offset_threshold => {'C',time_offset_threshold},
			    tsn_time_domain_number => {'C',tsn_time_domain_number}}},
		  cp_function_features => {'O',cp_function_features},
		  graceful_release_period => {'C',graceful_release_period},
		  gtp_u_path_qos_information =>
		      {'C',
			  #{average_packet_delay => {'C',average_packet_delay},
			    gtp_u_path_interface_type => {'C',gtp_u_path_interface_type},
			    maximum_packet_delay => {'C',maximum_packet_delay},
			    measurement_period => {'C',measurement_period},
			    minimum_packet_delay => {'C',minimum_packet_delay},
			    qos_report_trigger => {'M',qos_report_trigger},
			    remote_gtp_u_peer => {'C',remote_gtp_u_peer},
			    timer => {'C',timer},
			    transport_level_marking => {'C',transport_level_marking}}},
		  node_id => {'M',node_id},
		  pfcp_association_release_request => {'C',pfcp_association_release_request},
		  pfcpaureq_flags => {'O',pfcpaureq_flags},
		  smf_set_id => {'C',smf_set_id},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  ue_ip_address_pool_information =>
		      {'O',
			  #{ip_version => {'O',ip_version},
			    network_instance => {'O',network_instance},
			    s_nssai => {'O',s_nssai},
			    ue_ip_address_pool_identity =>
				{'M',ue_ip_address_pool_identity}}},
		  ue_ip_address_usage_information =>
		      {'O',
			  #{metric => {'M',metric},
			    network_instance => {'M',network_instance},
			    number_of_ue_ip_addresses => {'M',number_of_ue_ip_addresses},
			    sequence_number => {'M',sequence_number},
			    ue_ip_address_pool_identity => {'O',ue_ip_address_pool_identity},
			    validity_timer => {'M',validity_timer}}},
		  up_function_features => {'O',up_function_features},
		  user_plane_ip_resource_information =>
		      {'O',user_plane_ip_resource_information}},
	    association_update_response =>
		#{bbf_up_function_features => {'C',bbf_up_function_features},
		  cp_function_features => {'O',cp_function_features},
		  node_id => {'M',node_id},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  ue_ip_address_usage_information =>
		      {'O',
			  #{metric => {'M',metric},
			    network_instance => {'M',network_instance},
			    number_of_ue_ip_addresses => {'M',number_of_ue_ip_addresses},
			    sequence_number => {'M',sequence_number},
			    ue_ip_address_pool_identity => {'O',ue_ip_address_pool_identity},
			    validity_timer => {'M',validity_timer}}},
		  up_function_features => {'O',up_function_features}},
	    heartbeat_request =>
		#{recovery_time_stamp => {'M',recovery_time_stamp},
		  source_ip_address => {'O',source_ip_address},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    heartbeat_response =>
		#{recovery_time_stamp => {'M',recovery_time_stamp},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    node_report_request =>
		#{clock_drift_report =>
		      {'C',
			  #{cumulative_rateratio_measurement =>
				{'O',cumulative_rateratio_measurement},
			    time_offset_measurement => {'M',time_offset_measurement},
			    time_stamp => {'O',time_stamp},
			    tsn_time_domain_number => {'C',tsn_time_domain_number}}},
		  gtp_u_path_qos_report =>
		      {'C',
			  #{event_time_stamp => {'M',event_time_stamp},
			    gtp_u_path_interface_type => {'C',gtp_u_path_interface_type},
			    path_report_qos_information =>
				{'M',
				    #{average_packet_delay => {'M',average_packet_delay},
				      maximum_packet_delay => {'C',maximum_packet_delay},
				      minimum_packet_delay => {'C',minimum_packet_delay},
				      transport_level_marking =>
					  {'C',transport_level_marking}}},
			    qos_report_trigger => {'M',qos_report_trigger},
			    remote_gtp_u_peer => {'M',remote_gtp_u_peer},
			    start_time => {'C',start_time}}},
		  node_id => {'M',node_id},
		  node_report_type => {'M',node_report_type},
		  tp_build_identifier => {'O',tp_build_identifier},
		  user_plane_path_failure_report =>
		      {'C',#{remote_gtp_u_peer => {'M',remote_gtp_u_peer}}},
		  user_plane_path_recovery_report =>
		      {'C',#{remote_gtp_u_peer => {'M',remote_gtp_u_peer}}}},
	    node_report_response =>
		#{node_id => {'M',node_id},
		  offending_ie => {'C',offending_ie},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}}},
	    pfd_management_request =>
		#{'application_id\'s_pfds' =>
		      {'M',
			  #{application_id => {'M',application_id},
			    pfd_context => {'C',#{pfd_contents => {'M',pfd_contents}}}}}},
	    pfd_management_response =>
		#{offending_ie => {'C',offending_ie},pfcp_cause => {'M',pfcp_cause}},
	    session_deletion_request =>
		#{tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    session_deletion_response =>
		#{additional_usage_reports_information =>
		      {'C',additional_usage_reports_information},
		  load_control_information => {'O',load_control_information},
		  offending_ie => {'C',offending_ie},
		  overload_control_information => {'O',overload_control_information},
		  packet_rate_status_report =>
		      {'C',
			  #{packet_rate_status => {'M',packet_rate_status},
			    qer_id => {'M',qer_id}}},
		  pfcp_cause => {'M',pfcp_cause},
		  session_report =>
		      {'C',
			  #{access_availability_report =>
				{'C',
				    #{access_availability_information =>
					  {'M',access_availability_information}}},
			    qos_monitoring_report =>
				{'C',
				    #{qfi => {'M',qfi},
				      qos_monitoring_measurement =>
					  {'M',qos_monitoring_measurement},
				      start_time => {'O',start_time},
				      time_stamp => {'M',time_stamp}}},
			    srr_id => {'M',srr_id}}},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  usage_report_sdr =>
		      {'C',
			  #{duration_measurement => {'C',duration_measurement},
			    end_time => {'C',end_time},
			    ethernet_traffic_information =>
				{'C',
				    #{mac_addresses_detected => {'C',mac_addresses_detected},
				      mac_addresses_removed => {'C',mac_addresses_removed}}},
			    start_time => {'C',start_time},
			    time_of_first_packet => {'C',time_of_first_packet},
			    time_of_last_packet => {'C',time_of_last_packet},
			    tp_end_time => {'O',tp_end_time},
			    tp_now => {'O',tp_now},
			    tp_start_time => {'O',tp_start_time},
			    ur_seqn => {'M',ur_seqn},
			    urr_id => {'M',urr_id},
			    usage_information => {'C',usage_information},
			    usage_report_trigger => {'M',usage_report_trigger},
			    volume_measurement => {'C',volume_measurement}}}},
	    session_establishment_request =>
		#{apn_dnn => {'O',apn_dnn},
		  create_bar =>
		      {'O',
			  #{bar_id => {'M',bar_id},
			    suggested_buffering_packets_count =>
				{'C',suggested_buffering_packets_count}}},
		  create_bridge_info_for_tsc => {'C',create_bridge_info_for_tsc},
		  create_far =>
		      {'M',
			  #{apply_action => {'M',apply_action},
			    bar_id => {'O',bar_id},
			    duplicating_parameters =>
				{'C',
				    #{destination_interface => {'M',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      outer_header_creation => {'C',outer_header_creation},
				      transport_level_marking =>
					  {'C',transport_level_marking}}},
			    far_id => {'M',far_id},
			    forwarding_parameters =>
				{'C',
				    #{bbf_apply_action => {'O',bbf_apply_action},
				      bbf_nat_port_block => {'O',bbf_nat_port_block},
				      destination_interface => {'M',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      header_enrichment => {'O',header_enrichment},
				      network_instance => {'O',network_instance},
				      outer_header_creation => {'C',outer_header_creation},
				      proxying => {'C',proxying},
				      redirect_information => {'C',redirect_information},
				      tgpp_interface_type => {'O',tgpp_interface_type},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      transport_level_marking =>
					  {'C',transport_level_marking}}},
			    redundant_transmission_parameters =>
				{'C',
				    #{f_teid => {'M',f_teid},
				      network_instance => {'C',network_instance}}},
			    tp_ipfix_policy => {'O',tp_ipfix_policy}}},
		  create_mar =>
		      {'C',
			  #{mar_id => {'M',mar_id},
			    non_tgpp_access_forwarding_action_information =>
				{'C',
				    #{far_id => {'M',far_id},
				      priority => {'C',priority},
				      urr_id => {'C',urr_id},
				      weight => {'C',weight}}},
			    steering_functionality => {'M',steering_functionality},
			    steering_mode => {'M',steering_mode},
			    tgpp_access_forwarding_action_information =>
				{'C',
				    #{far_id => {'M',far_id},
				      priority => {'C',priority},
				      urr_id => {'C',urr_id},
				      weight => {'C',weight}}}}},
		  create_pdr =>
		      {'M',
			  #{activate_predefined_rules => {'C',activate_predefined_rules},
			    activation_time => {'O',activation_time},
			    deactivation_time => {'O',deactivation_time},
			    far_id => {'C',far_id},
			    ip_multicast_addressing_info =>
				{'O',
				    #{ip_multicast_address => {'M',ip_multicast_address},
				      source_ip_address => {'O',source_ip_address}}},
			    mar_id => {'C',mar_id},
			    mptcp_applicable_indication => {'C',mptcp_applicable_indication},
			    outer_header_removal => {'C',outer_header_removal},
			    packet_replication_and_detection_carry_on_information =>
				{'C',packet_replication_and_detection_carry_on_information},
			    pdi =>
				{'M',
				    #{application_id => {'O',application_id},
				      ethernet_packet_filter =>
					  {'O',
					      #{c_tag => {'O',c_tag},
						ethernet_filter_id =>
						    {'C',ethernet_filter_id},
						ethernet_filter_properties =>
						    {'C',ethernet_filter_properties},
						ethertype => {'O',ethertype},
						mac_address => {'O',mac_address},
						s_tag => {'O',s_tag},
						sdf_filter => {'O',sdf_filter}}},
				      ethernet_pdu_session_information =>
					  {'O',ethernet_pdu_session_information},
				      f_teid => {'O',f_teid},
				      framed_ipv6_route => {'O',framed_ipv6_route},
				      framed_route => {'O',framed_route},
				      framed_routing => {'O',framed_routing},
				      ip_multicast_addressing_info =>
					  {'O',
					      #{ip_multicast_address =>
						    {'M',ip_multicast_address},
						source_ip_address =>
						    {'O',source_ip_address}}},
				      network_instance => {'O',network_instance},
				      qfi => {'O',qfi},
				      redundant_transmission_parameters =>
					  {'O',
					      #{f_teid => {'M',f_teid},
						network_instance => {'O',network_instance}}},
				      sdf_filter => {'O',sdf_filter},
				      source_interface => {'M',source_interface},
				      tgpp_interface_type => {'O',tgpp_interface_type},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      ue_ip_address => {'O',ue_ip_address}}},
			    pdr_id => {'M',pdr_id},
			    precedence => {'M',precedence},
			    qer_id => {'C',qer_id},
			    transport_delay_reporting =>
				{'C',
				    #{remote_gtp_u_peer => {'M',remote_gtp_u_peer},
				      transport_level_marking =>
					  {'O',transport_level_marking}}},
			    ue_ip_address_pool_identity => {'O',ue_ip_address_pool_identity},
			    urr_id => {'C',urr_id}}},
		  create_qer =>
		      {'C',
			  #{averaging_window => {'O',averaging_window},
			    gate_status => {'M',gate_status},
			    gbr => {'C',gbr},
			    mbr => {'C',mbr},
			    packet_rate_status => {'C',packet_rate_status},
			    paging_policy_indicator => {'C',paging_policy_indicator},
			    qer_control_indications => {'C',qer_control_indications},
			    qer_correlation_id => {'C',qer_correlation_id},
			    qer_id => {'M',qer_id},
			    qfi => {'C',qfi},
			    rqi => {'C',rqi}}},
		  create_srr =>
		      {'O',
			  #{access_availability_control_information =>
				{'C',
				    #{requested_access_availability_information =>
					  {'M',requested_access_availability_information}}},
			    qos_monitoring_per_qos_flow_control_information =>
				{'C',
				    #{measurement_period => {'C',measurement_period},
				      minimum_wait_time => {'C',minimum_wait_time},
				      packet_delay_thresholds =>
					  {'C',packet_delay_thresholds},
				      qfi => {'M',qfi},
				      reporting_frequency => {'M',reporting_frequency},
				      requested_qos_monitoring =>
					  {'M',requested_qos_monitoring}}},
			    srr_id => {'M',srr_id}}},
		  create_traffic_endpoint =>
		      {'C',
			  #{ethernet_pdu_session_information =>
				{'O',ethernet_pdu_session_information},
			    f_teid => {'O',f_teid},
			    framed_ipv6_route => {'O',framed_ipv6_route},
			    framed_route => {'O',framed_route},
			    framed_routing => {'O',framed_routing},
			    network_instance => {'O',network_instance},
			    qfi => {'C',qfi},
			    redundant_transmission_parameters =>
				{'O',
				    #{f_teid => {'M',f_teid},
				      network_instance => {'C',network_instance}}},
			    tgpp_interface_type => {'O',tgpp_interface_type},
			    traffic_endpoint_id => {'M',traffic_endpoint_id},
			    ue_ip_address => {'O',ue_ip_address}}},
		  create_urr =>
		      {'C',
			  #{additional_monitoring_time =>
				{'O',
				    #{event_quota => {'O',event_quota},
				      event_threshold => {'O',event_threshold},
				      monitoring_time => {'M',monitoring_time},
				      subsequent_time_quota => {'O',subsequent_time_quota},
				      subsequent_time_threshold =>
					  {'O',subsequent_time_threshold},
				      subsequent_volume_quota =>
					  {'O',subsequent_volume_quota},
				      subsequent_volume_threshold =>
					  {'O',subsequent_volume_threshold}}},
			    dropped_dl_traffic_threshold =>
				{'C',dropped_dl_traffic_threshold},
			    ethernet_inactivity_timer => {'C',ethernet_inactivity_timer},
			    event_quota => {'C',event_quota},
			    event_threshold => {'C',event_threshold},
			    far_id => {'C',far_id},
			    inactivity_detection_time => {'C',inactivity_detection_time},
			    linked_urr_id => {'C',linked_urr_id},
			    measurement_information => {'C',measurement_information},
			    measurement_method => {'M',measurement_method},
			    measurement_period => {'C',measurement_period},
			    monitoring_time => {'O',monitoring_time},
			    number_of_reports => {'O',number_of_reports},
			    quota_holding_time => {'C',quota_holding_time},
			    quota_validity_time => {'C',quota_validity_time},
			    reporting_triggers => {'M',reporting_triggers},
			    subsequent_event_quota => {'O',subsequent_event_quota},
			    subsequent_event_threshold => {'O',subsequent_event_threshold},
			    subsequent_time_quota => {'O',subsequent_time_quota},
			    subsequent_time_threshold => {'O',subsequent_time_threshold},
			    subsequent_volume_quota => {'O',subsequent_volume_quota},
			    subsequent_volume_threshold => {'O',subsequent_volume_threshold},
			    time_quota => {'C',time_quota},
			    time_threshold => {'C',time_threshold},
			    urr_id => {'M',urr_id},
			    volume_quota => {'C',volume_quota},
			    volume_threshold => {'C',volume_threshold}}},
		  f_seid => {'M',f_seid},
		  node_id => {'M',node_id},
		  pdn_type => {'C',pdn_type},
		  pfcpsereq_flags => {'C',pfcpsereq_flags},
		  provide_atsss_control_information =>
		      {'C',
			  #{atsss_ll_control_information =>
				{'C',atsss_ll_control_information},
			    mptcp_control_information => {'C',mptcp_control_information},
			    pmf_control_information => {'C',pmf_control_information}}},
		  provide_rds_configuration_information =>
		      {'O',provide_rds_configuration_information},
		  recovery_time_stamp => {'O',recovery_time_stamp},
		  s_nssai => {'O',s_nssai},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  trace_information => {'O',trace_information},
		  user_id => {'O',user_id},
		  user_plane_inactivity_timer => {'O',user_plane_inactivity_timer}},
	    session_establishment_response =>
		#{atsss_control_parameters =>
		      {'C',
			  #{atsss_ll_parameters =>
				{'C',#{atsss_ll_information => {'M',atsss_ll_information}}},
			    mptcp_parameters =>
				{'C',
				    #{mptcp_address_information =>
					  {'M',mptcp_address_information},
				      ue_link_specific_ip_address =>
					  {'M',ue_link_specific_ip_address}}},
			    pmf_parameters =>
				{'C',
				    #{pmf_address_information =>
					  {'M',pmf_address_information}}}}},
		  created_bridge_info_for_tsc =>
		      {'C',
			  #{ds_tt_port_number => {'C',ds_tt_port_number},
			    nw_tt_port_number => {'C',nw_tt_port_number},
			    tsn_bridge_id => {'C',tsn_bridge_id}}},
		  created_pdr =>
		      {'C',
			  #{f_teid => {'C',f_teid},
			    pdr_id => {'M',pdr_id},
			    ue_ip_address => {'C',ue_ip_address}}},
		  created_traffic_endpoint =>
		      {'C',
			  #{f_teid => {'C',f_teid},
			    traffic_endpoint_id => {'M',traffic_endpoint_id},
			    ue_ip_address => {'C',ue_ip_address}}},
		  f_seid => {'C',f_seid},
		  failed_rule_id => {'C',failed_rule_id},
		  load_control_information =>
		      {'O',
			  #{metric => {'M',metric},sequence_number => {'M',sequence_number}}},
		  node_id => {'M',node_id},
		  offending_ie => {'C',offending_ie},
		  overload_control_information =>
		      {'O',
			  #{metric => {'M',metric},
			    oci_flags => {'C',oci_flags},
			    sequence_number => {'M',sequence_number},
			    timer => {'M',timer}}},
		  pfcp_cause => {'M',pfcp_cause},
		  rds_configuration_information => {'O',rds_configuration_information},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_created_nat_binding =>
		      {'C',
			  #{bbf_nat_outside_address => {'C',bbf_nat_outside_address},
			    bbf_nat_port_block => {'C',bbf_nat_port_block}}},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}}},
	    session_modification_request =>
		#{create_traffic_endpoint =>
		      {'C',
			  #{ethernet_pdu_session_information =>
				{'O',ethernet_pdu_session_information},
			    f_teid => {'O',f_teid},
			    framed_ipv6_route => {'O',framed_ipv6_route},
			    framed_route => {'O',framed_route},
			    framed_routing => {'O',framed_routing},
			    network_instance => {'O',network_instance},
			    qfi => {'C',qfi},
			    redundant_transmission_parameters =>
				{'O',
				    #{f_teid => {'M',f_teid},
				      network_instance => {'C',network_instance}}},
			    traffic_endpoint_id => {'M',traffic_endpoint_id},
			    ue_ip_address => {'O',ue_ip_address}}},
		  create_qer =>
		      {'C',
			  #{averaging_window => {'O',averaging_window},
			    gate_status => {'M',gate_status},
			    gbr => {'C',gbr},
			    mbr => {'C',mbr},
			    packet_rate_status => {'C',packet_rate_status},
			    paging_policy_indicator => {'C',paging_policy_indicator},
			    qer_control_indications => {'C',qer_control_indications},
			    qer_correlation_id => {'C',qer_correlation_id},
			    qer_id => {'M',qer_id},
			    qfi => {'C',qfi},
			    rqi => {'C',rqi}}},
		  create_bar =>
		      {'C',
			  #{bar_id => {'M',bar_id},
			    suggested_buffering_packets_count =>
				{'C',suggested_buffering_packets_count}}},
		  update_mar =>
		      {'C',
			  #{mar_id => {'M',mar_id},
			    non_tgpp_access_forwarding_action_information =>
				{'C',
				    #{far_id => {'M',far_id},
				      priority => {'C',priority},
				      urr_id => {'C',urr_id},
				      weight => {'C',weight}}},
			    steering_functionality => {'C',steering_functionality},
			    steering_mode => {'C',steering_mode},
			    tgpp_access_forwarding_action_information =>
				{'C',
				    #{far_id => {'M',far_id},
				      priority => {'C',priority},
				      urr_id => {'C',urr_id},
				      weight => {'C',weight}}},
			    update_non_tgpp_access_forwarding_action_information =>
				{'C',
				    #{far_id => {'C',far_id},
				      priority => {'C',priority},
				      urr_id => {'C',urr_id},
				      weight => {'C',weight}}},
			    update_tgpp_access_forwarding_action_information =>
				{'C',
				    #{far_id => {'C',far_id},
				      priority => {'C',priority},
				      urr_id => {'C',urr_id},
				      weight => {'C',weight}}}}},
		  create_srr =>
		      {'C',
			  #{access_availability_control_information =>
				{'C',
				    #{requested_access_availability_information =>
					  {'M',requested_access_availability_information}}},
			    qos_monitoring_per_qos_flow_control_information =>
				{'C',
				    #{measurement_period => {'C',measurement_period},
				      minimum_wait_time => {'C',minimum_wait_time},
				      packet_delay_thresholds =>
					  {'C',packet_delay_thresholds},
				      qfi => {'M',qfi},
				      reporting_frequency => {'M',reporting_frequency},
				      requested_qos_monitoring =>
					  {'M',requested_qos_monitoring}}},
			    srr_id => {'M',srr_id}}},
		  remove_bar => {'C',#{bar_id => {'M',bar_id}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  update_urr =>
		      {'C',
			  #{additional_monitoring_time =>
				{'O',
				    #{event_quota => {'O',event_quota},
				      event_threshold => {'O',event_threshold},
				      monitoring_time => {'M',monitoring_time},
				      subsequent_time_quota => {'O',subsequent_time_quota},
				      subsequent_time_threshold =>
					  {'O',subsequent_time_threshold},
				      subsequent_volume_quota =>
					  {'O',subsequent_volume_quota},
				      subsequent_volume_threshold =>
					  {'O',subsequent_volume_threshold}}},
			    dropped_dl_traffic_threshold =>
				{'C',dropped_dl_traffic_threshold},
			    ethernet_inactivity_timer => {'C',ethernet_inactivity_timer},
			    event_quota => {'C',event_quota},
			    event_threshold => {'C',event_threshold},
			    far_id => {'C',far_id},
			    inactivity_detection_time => {'C',inactivity_detection_time},
			    linked_urr_id => {'C',linked_urr_id},
			    measurement_information => {'C',measurement_information},
			    measurement_method => {'C',measurement_method},
			    measurement_period => {'C',measurement_period},
			    monitoring_time => {'C',monitoring_time},
			    number_of_reports => {'O',number_of_reports},
			    quota_holding_time => {'C',quota_holding_time},
			    quota_validity_time => {'C',quota_validity_time},
			    reporting_triggers => {'C',reporting_triggers},
			    subsequent_event_quota => {'O',subsequent_event_quota},
			    subsequent_event_threshold => {'O',subsequent_event_threshold},
			    subsequent_time_quota => {'C',subsequent_time_quota},
			    subsequent_time_threshold => {'C',subsequent_time_threshold},
			    subsequent_volume_quota => {'C',subsequent_volume_quota},
			    subsequent_volume_threshold => {'C',subsequent_volume_threshold},
			    time_quota => {'C',time_quota},
			    time_threshold => {'C',time_threshold},
			    urr_id => {'M',urr_id},
			    volume_quota => {'C',volume_quota},
			    volume_threshold => {'C',volume_threshold}}},
		  user_plane_inactivity_timer => {'C',user_plane_inactivity_timer},
		  create_urr =>
		      {'C',
			  #{additional_monitoring_time =>
				{'O',
				    #{event_quota => {'O',event_quota},
				      event_threshold => {'O',event_threshold},
				      monitoring_time => {'M',monitoring_time},
				      subsequent_time_quota => {'O',subsequent_time_quota},
				      subsequent_time_threshold =>
					  {'O',subsequent_time_threshold},
				      subsequent_volume_quota =>
					  {'O',subsequent_volume_quota},
				      subsequent_volume_threshold =>
					  {'O',subsequent_volume_threshold}}},
			    dropped_dl_traffic_threshold =>
				{'C',dropped_dl_traffic_threshold},
			    ethernet_inactivity_timer => {'C',ethernet_inactivity_timer},
			    event_quota => {'C',event_quota},
			    event_threshold => {'C',event_threshold},
			    far_id => {'C',far_id},
			    inactivity_detection_time => {'C',inactivity_detection_time},
			    linked_urr_id => {'C',linked_urr_id},
			    measurement_information => {'C',measurement_information},
			    measurement_method => {'M',measurement_method},
			    measurement_period => {'C',measurement_period},
			    monitoring_time => {'O',monitoring_time},
			    number_of_reports => {'O',number_of_reports},
			    quota_holding_time => {'C',quota_holding_time},
			    quota_validity_time => {'C',quota_validity_time},
			    reporting_triggers => {'M',reporting_triggers},
			    subsequent_event_quota => {'O',subsequent_event_quota},
			    subsequent_event_threshold => {'O',subsequent_event_threshold},
			    subsequent_time_quota => {'O',subsequent_time_quota},
			    subsequent_time_threshold => {'O',subsequent_time_threshold},
			    subsequent_volume_quota => {'O',subsequent_volume_quota},
			    subsequent_volume_threshold => {'O',subsequent_volume_threshold},
			    time_quota => {'C',time_quota},
			    time_threshold => {'C',time_threshold},
			    urr_id => {'M',urr_id},
			    volume_quota => {'C',volume_quota},
			    volume_threshold => {'C',volume_threshold}}},
		  update_bar =>
		      {'C',
			  #{bar_id => {'M',bar_id},
			    downlink_data_notification_delay =>
				{'C',downlink_data_notification_delay},
			    suggested_buffering_packets_count =>
				{'C',suggested_buffering_packets_count}}},
		  remove_srr => {'C',#{srr_id => {'M',srr_id}}},
		  remove_far => {'C',#{far_id => {'M',far_id}}},
		  query_urr_reference => {'O',query_urr_reference},
		  access_availability_information => {'O',access_availability_information},
		  create_pdr =>
		      {'C',
			  #{activate_predefined_rules => {'C',activate_predefined_rules},
			    activation_time => {'O',activation_time},
			    deactivation_time => {'O',deactivation_time},
			    far_id => {'C',far_id},
			    ip_multicast_addressing_info =>
				{'O',
				    #{ip_multicast_address => {'M',ip_multicast_address},
				      source_ip_address => {'O',source_ip_address}}},
			    mar_id => {'C',mar_id},
			    outer_header_removal => {'C',outer_header_removal},
			    packet_replication_and_detection_carry_on_information =>
				{'C',packet_replication_and_detection_carry_on_information},
			    pdi =>
				{'M',
				    #{application_id => {'O',application_id},
				      ethernet_packet_filter =>
					  {'O',
					      #{c_tag => {'O',c_tag},
						ethernet_filter_id =>
						    {'C',ethernet_filter_id},
						ethernet_filter_properties =>
						    {'C',ethernet_filter_properties},
						ethertype => {'O',ethertype},
						mac_address => {'O',mac_address},
						s_tag => {'O',s_tag},
						sdf_filter => {'O',sdf_filter}}},
				      ethernet_pdu_session_information =>
					  {'O',ethernet_pdu_session_information},
				      f_teid => {'O',f_teid},
				      framed_ipv6_route => {'O',framed_ipv6_route},
				      framed_route => {'O',framed_route},
				      framed_routing => {'O',framed_routing},
				      ip_multicast_addressing_info =>
					  {'O',
					      #{ip_multicast_address =>
						    {'M',ip_multicast_address},
						source_ip_address =>
						    {'O',source_ip_address}}},
				      network_instance => {'O',network_instance},
				      qfi => {'O',qfi},
				      redundant_transmission_parameters =>
					  {'O',
					      #{f_teid => {'M',f_teid},
						network_instance => {'O',network_instance}}},
				      sdf_filter => {'O',sdf_filter},
				      source_interface => {'M',source_interface},
				      tgpp_interface_type => {'O',tgpp_interface_type},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      ue_ip_address => {'O',ue_ip_address}}},
			    pdr_id => {'M',pdr_id},
			    precedence => {'M',precedence},
			    qer_id => {'C',qer_id},
			    ue_ip_address_pool_identity => {'O',ue_ip_address_pool_identity},
			    urr_id => {'C',urr_id}}},
		  update_srr =>
		      {'C',
			  #{access_availability_control_information =>
				{'C',
				    #{requested_access_availability_information =>
					  {'M',requested_access_availability_information}}},
			    qos_monitoring_per_qos_flow_control_information =>
				{'C',
				    #{measurement_period => {'C',measurement_period},
				      minimum_wait_time => {'C',minimum_wait_time},
				      packet_delay_thresholds =>
					  {'C',packet_delay_thresholds},
				      qfi => {'M',qfi},
				      reporting_frequency => {'M',reporting_frequency},
				      requested_qos_monitoring =>
					  {'M',requested_qos_monitoring}}},
			    srr_id => {'M',srr_id}}},
		  trace_information => {'O',trace_information},
		  update_far =>
		      {'C',
			  #{apply_action => {'C',apply_action},
			    bar_id => {'C',bar_id},
			    far_id => {'M',far_id},
			    redundant_transmission_parameters =>
				{'C',
				    #{f_teid => {'M',f_teid},
				      network_instance => {'O',network_instance}}},
			    tp_ipfix_policy => {'O',tp_ipfix_policy},
			    update_duplicating_parameters =>
				{'C',
				    #{destination_interface => {'C',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      outer_header_creation => {'C',outer_header_creation},
				      transport_level_marking =>
					  {'C',transport_level_marking}}},
			    update_forwarding_parameters =>
				{'C',
				    #{bbf_apply_action => {'O',bbf_apply_action},
				      bbf_nat_port_block => {'O',bbf_nat_port_block},
				      destination_interface => {'C',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      header_enrichment => {'C',header_enrichment},
				      network_instance => {'C',network_instance},
				      outer_header_creation => {'C',outer_header_creation},
				      redirect_information => {'C',redirect_information},
				      sxsmreq_flags => {'C',sxsmreq_flags},
				      tgpp_interface_type => {'C',tgpp_interface_type},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      transport_level_marking =>
					  {'C',transport_level_marking}}}}},
		  create_mar =>
		      {'C',
			  #{mar_id => {'M',mar_id},
			    non_tgpp_access_forwarding_action_information =>
				{'C',
				    #{far_id => {'M',far_id},
				      priority => {'C',priority},
				      urr_id => {'C',urr_id},
				      weight => {'C',weight}}},
			    steering_functionality => {'M',steering_functionality},
			    steering_mode => {'M',steering_mode},
			    tgpp_access_forwarding_action_information =>
				{'C',
				    #{far_id => {'M',far_id},
				      priority => {'C',priority},
				      urr_id => {'C',urr_id},
				      weight => {'C',weight}}}}},
		  remove_urr => {'C',#{urr_id => {'M',urr_id}}},
		  f_seid => {'C',f_seid},
		  update_pdr =>
		      {'C',
			  #{activate_predefined_rules => {'C',activate_predefined_rules},
			    activation_time => {'O',activation_time},
			    deactivate_predefined_rules => {'C',deactivate_predefined_rules},
			    deactivation_time => {'O',deactivation_time},
			    far_id => {'C',far_id},
			    ip_multicast_addressing_info =>
				{'O',
				    #{ip_multicast_address => {'M',ip_multicast_address},
				      source_ip_address => {'O',source_ip_address}}},
			    outer_header_removal => {'C',outer_header_removal},
			    pdi =>
				{'C',
				    #{application_id => {'O',application_id},
				      ethernet_packet_filter =>
					  {'O',
					      #{c_tag => {'O',c_tag},
						ethernet_filter_id =>
						    {'C',ethernet_filter_id},
						ethernet_filter_properties =>
						    {'C',ethernet_filter_properties},
						ethertype => {'O',ethertype},
						mac_address => {'O',mac_address},
						s_tag => {'O',s_tag},
						sdf_filter => {'O',sdf_filter}}},
				      ethernet_pdu_session_information =>
					  {'O',ethernet_pdu_session_information},
				      f_teid => {'O',f_teid},
				      framed_ipv6_route => {'O',framed_ipv6_route},
				      framed_route => {'O',framed_route},
				      framed_routing => {'O',framed_routing},
				      network_instance => {'O',network_instance},
				      qfi => {'O',qfi},
				      sdf_filter => {'O',sdf_filter},
				      source_interface => {'M',source_interface},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      ue_ip_address => {'O',ue_ip_address}}},
			    pdr_id => {'M',pdr_id},
			    precedence => {'C',precedence},
			    qer_id => {'C',qer_id},
			    urr_id => {'C',urr_id}}},
		  remove_pdr => {'C',#{pdr_id => {'M',pdr_id}}},
		  remove_traffic_endpoint =>
		      {'C',#{traffic_endpoint_id => {'M',traffic_endpoint_id}}},
		  provide_atsss_control_information =>
		      {'C',
			  #{atsss_ll_control_information =>
				{'C',atsss_ll_control_information},
			    mptcp_control_information => {'C',mptcp_control_information},
			    pmf_control_information => {'C',pmf_control_information}}},
		  remove_mar => {'C',#{mar_id => {'M',mar_id}}},
		  sxsmreq_flags => {'C',sxsmreq_flags},
		  port_management_information_for_tsc =>
		      {'C',
			  #{port_management_information_containerd =>
				{'M',port_management_information_containerd}}},
		  query_packet_rate_status_ie_smreq => {'C',#{qer_id => {'M',qer_id}}},
		  create_far =>
		      {'C',
			  #{apply_action => {'M',apply_action},
			    bar_id => {'O',bar_id},
			    duplicating_parameters =>
				{'C',
				    #{destination_interface => {'M',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      outer_header_creation => {'C',outer_header_creation},
				      transport_level_marking =>
					  {'C',transport_level_marking}}},
			    far_id => {'M',far_id},
			    forwarding_parameters =>
				{'C',
				    #{bbf_apply_action => {'O',bbf_apply_action},
				      bbf_nat_port_block => {'O',bbf_nat_port_block},
				      destination_interface => {'M',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      header_enrichment => {'O',header_enrichment},
				      network_instance => {'O',network_instance},
				      outer_header_creation => {'C',outer_header_creation},
				      proxying => {'C',proxying},
				      redirect_information => {'C',redirect_information},
				      tgpp_interface_type => {'O',tgpp_interface_type},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      transport_level_marking =>
					  {'C',transport_level_marking}}},
			    redundant_transmission_parameters =>
				{'C',
				    #{f_teid => {'M',f_teid},
				      network_instance => {'C',network_instance}}}}},
		  node_id => {'C',node_id},
		  ethernet_context_information =>
		      {'C',#{mac_addressed_detected => {'M',mac_addressed_detected}}},
		  update_traffic_endpoint =>
		      {'C',
			  #{f_teid => {'C',f_teid},
			    framed_ipv6_route => {'C',framed_ipv6_route},
			    framed_route => {'C',framed_route},
			    framed_routing => {'C',framed_routing},
			    network_instance => {'O',network_instance},
			    qfi => {'C',qfi},
			    redundant_transmission_parameters =>
				{'O',
				    #{f_teid => {'M',f_teid},
				      network_instance => {'C',network_instance}}},
			    tgpp_interface_type => {'C',tgpp_interface_type},
			    traffic_endpoint_id => {'M',traffic_endpoint_id},
			    ue_ip_address => {'C',ue_ip_address}}},
		  remove_qer => {'C',#{qer_id => {'M',qer_id}}},
		  update_qer =>
		      {'C',
			  #{averaging_window => {'O',averaging_window},
			    gate_status => {'C',gate_status},
			    gbr => {'C',gbr},
			    mbr => {'C',mbr},
			    paging_policy_indicator => {'C',paging_policy_indicator},
			    qer_control_indications => {'C',qer_control_indications},
			    qer_correlation_id => {'C',qer_correlation_id},
			    qer_id => {'M',qer_id},
			    qfi => {'C',qfi},
			    rqi => {'C',rqi}}},
		  query_urr => {'C',#{urr_id => {'M',urr_id}}}},
	    session_modification_response =>
		#{additional_usage_reports_information =>
		      {'C',additional_usage_reports_information},
		  atsss_control_parameters =>
		      {'C',
			  #{atsss_ll_parameters =>
				{'C',#{atsss_ll_information => {'M',atsss_ll_information}}},
			    mptcp_parameters =>
				{'C',
				    #{mptcp_address_information =>
					  {'M',mptcp_address_information},
				      ue_link_specific_ip_address =>
					  {'M',ue_link_specific_ip_address}}},
			    pmf_parameters =>
				{'C',
				    #{pmf_address_information =>
					  {'M',pmf_address_information}}}}},
		  created_pdr => {'C',created_pdr},
		  created_traffic_endpoint =>
		      {'C',
			  #{f_teid => {'C',f_teid},
			    traffic_endpoint_id => {'M',traffic_endpoint_id},
			    ue_ip_address => {'C',ue_ip_address}}},
		  failed_rule_id => {'C',failed_rule_id},
		  load_control_information => {'O',load_control_information},
		  offending_ie => {'C',offending_ie},
		  overload_control_information => {'O',overload_control_information},
		  packet_rate_status_report_ie_smresp =>
		      {'C',
			  #{packet_rate_status => {'M',packet_rate_status},
			    qer_id => {'M',qer_id}}},
		  pfcp_cause => {'M',pfcp_cause},
		  port_management_information_for_tsc_smr =>
		      {'C',
			  #{port_management_information_container =>
				{'O',port_management_information_container}}},
		  tp_created_nat_binding =>
		      {'C',
			  #{bbf_nat_outside_address => {'C',bbf_nat_outside_address},
			    bbf_nat_port_block => {'C',bbf_nat_port_block}}},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  updated_pdr => {'C',#{f_teid => {'C',f_teid},pdr_id => {'M',pdr_id}}},
		  usage_report_smr =>
		      {'C',
			  #{duration_measurement => {'C',duration_measurement},
			    end_time => {'C',end_time},
			    ethernet_traffic_information =>
				{'C',
				    #{mac_addresses_detected => {'C',mac_addresses_detected},
				      mac_addresses_removed => {'C',mac_addresses_removed}}},
			    query_urr_reference => {'C',query_urr_reference},
			    start_time => {'C',start_time},
			    time_of_first_packet => {'C',time_of_first_packet},
			    time_of_last_packet => {'C',time_of_last_packet},
			    tp_end_time => {'O',tp_end_time},
			    tp_now => {'O',tp_now},
			    tp_start_time => {'O',tp_start_time},
			    ur_seqn => {'M',ur_seqn},
			    urr_id => {'M',urr_id},
			    usage_information => {'C',usage_information},
			    usage_report_trigger => {'M',usage_report_trigger},
			    volume_measurement => {'C',volume_measurement}}}},
	    session_report_request =>
		#{additional_usage_reports_information =>
		      {'C',additional_usage_reports_information},
		  downlink_data_report =>
		      {'C',
			  #{downlink_data_service_information =>
				{'C',downlink_data_service_information},
			    pdr_id => {'M',pdr_id}}},
		  error_indication_report => {'C',#{f_teid => {'M',f_teid}}},
		  f_seid => {'C',f_seid},
		  load_control_information => {'O',load_control_information},
		  overload_control_information => {'O',overload_control_information},
		  packet_rate_status_report =>
		      {'C',
			  #{packet_rate_status => {'M',packet_rate_status},
			    qer_id => {'M',qer_id}}},
		  pfcpsrreq_flags => {'C',pfcpsrreq_flags},
		  port_management_information_for_tsc_sdr =>
		      {'C',
			  #{port_management_information_container =>
				{'O',port_management_information_container}}},
		  report_type => {'M',report_type},
		  session_report =>
		      {'C',
			  #{access_availability_report =>
				{'C',
				    #{access_availability_information =>
					  {'M',access_availability_information}}},
			    qos_monitoring_report =>
				{'C',
				    #{qfi => {'M',qfi},
				      qos_monitoring_measurement =>
					  {'M',qos_monitoring_measurement},
				      start_time => {'O',start_time},
				      time_stamp => {'M',time_stamp}}},
			    srr_id => {'M',srr_id}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  usage_report_srr =>
		      {'C',
			  #{application_detection_information =>
				{'C',
				    #{application_id => {'M',application_id},
				      application_instance_id =>
					  {'C',application_instance_id},
				      flow_information => {'C',flow_information},
				      pdr_id => {'O',pdr_id}}},
			    duration_measurement => {'C',duration_measurement},
			    end_time => {'C',end_time},
			    ethernet_traffic_information =>
				{'C',
				    #{mac_addresses_detected => {'C',mac_addresses_detected},
				      mac_addresses_removed => {'C',mac_addresses_removed}}},
			    event_time_stamp => {'C',event_time_stamp},
			    join_ip_multicast_information =>
				{'C',
				    #{ip_multicast_address => {'M',ip_multicast_address},
				      source_ip_address => {'C',source_ip_address}}},
			    leave_ip_multicast_information =>
				{'C',
				    #{ip_multicast_address => {'M',ip_multicast_address},
				      source_ip_address => {'C',source_ip_address}}},
			    network_instance => {'C',network_instance},
			    query_urr_reference => {'C',query_urr_reference},
			    start_time => {'C',start_time},
			    time_of_first_packet => {'C',time_of_first_packet},
			    time_of_last_packet => {'C',time_of_last_packet},
			    tp_end_time => {'O',tp_end_time},
			    tp_now => {'O',tp_now},
			    tp_start_time => {'O',tp_start_time},
			    ue_ip_address => {'C',ue_ip_address},
			    ur_seqn => {'M',ur_seqn},
			    urr_id => {'M',urr_id},
			    usage_information => {'C',usage_information},
			    usage_report_trigger => {'M',usage_report_trigger},
			    volume_measurement => {'C',volume_measurement}}}},
	    session_report_response =>
		#{alternative_smf_ip_address => {'O',alternative_smf_ip_address},
		  f_seid => {'O',f_seid},
		  f_teid => {'O',f_teid},
		  offending_ie => {'C',offending_ie},
		  pfcp_cause => {'M',pfcp_cause},
		  sxsrrsp_flags => {'C',sxsrrsp_flags},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  update_bar =>
		      {'C',
			  #{bar_id => {'M',bar_id},
			    dl_buffering_duration => {'C',dl_buffering_duration},
			    dl_buffering_suggested_packet_count =>
				{'O',dl_buffering_suggested_packet_count},
			    downlink_data_notification_delay =>
				{'C',downlink_data_notification_delay},
			    suggested_buffering_packets_count =>
				{'C',suggested_buffering_packets_count}}}},
	    version_not_supported_response => #{}},
      'Sxa' =>
	  #{association_release_request =>
		#{node_id => {'M',node_id},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    association_release_response =>
		#{node_id => {'M',node_id},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    association_setup_request =>
		#{alternative_smf_ip_address => {'O',alternative_smf_ip_address},
		  bbf_up_function_features => {'C',bbf_up_function_features},
		  clock_drift_control_information => {'O',#{}},
		  cp_function_features => {'C',cp_function_features},
		  gtp_u_path_qos_control_information => {'C',#{}},
		  nf_instance_id => {'O',nf_instance_id},
		  node_id => {'M',node_id},
		  pfcp_session_retention_information =>
		      {'O',#{cp_pfcp_entity_ip_address => {'O',cp_pfcp_entity_ip_address}}},
		  pfcpasreq_flags => {'O',pfcpasreq_flags},
		  recovery_time_stamp => {'M',recovery_time_stamp},
		  smf_set_id => {'C',smf_set_id},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  ue_ip_address_pool_information => {'O',#{}},
		  up_function_features => {'C',up_function_features},
		  user_plane_ip_resource_information =>
		      {'O',user_plane_ip_resource_information}},
	    association_setup_response =>
		#{alternative_smf_ip_address => {'O',alternative_smf_ip_address},
		  bbf_up_function_features => {'C',bbf_up_function_features},
		  clock_drift_control_information => {'C',#{}},
		  cp_function_features => {'C',cp_function_features},
		  gtp_u_path_qos_control_information => {'C',#{}},
		  nf_instance_id => {'O',nf_instance_id},
		  node_id => {'M',node_id},
		  pfcp_cause => {'M',pfcp_cause},
		  pfcpasrsp_flags => {'O',pfcpasrsp_flags},
		  recovery_time_stamp => {'M',recovery_time_stamp},
		  smf_set_id => {'C',smf_set_id},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  ue_ip_address_pool_information => {'O',#{}},
		  up_function_features => {'C',up_function_features},
		  user_plane_ip_resource_information =>
		      {'O',user_plane_ip_resource_information}},
	    association_update_request =>
		#{alternative_smf_ip_address => {'O',alternative_smf_ip_address},
		  bbf_up_function_features => {'C',bbf_up_function_features},
		  clock_drift_control_information => {'C',#{}},
		  cp_function_features => {'O',cp_function_features},
		  graceful_release_period => {'C',graceful_release_period},
		  gtp_u_path_qos_information => {'C',#{}},
		  node_id => {'M',node_id},
		  pfcp_association_release_request => {'C',pfcp_association_release_request},
		  pfcpaureq_flags => {'O',pfcpaureq_flags},
		  smf_set_id => {'C',smf_set_id},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  ue_ip_address_pool_information => {'O',#{}},
		  ue_ip_address_usage_information => {'O',#{}},
		  up_function_features => {'O',up_function_features},
		  user_plane_ip_resource_information =>
		      {'O',user_plane_ip_resource_information}},
	    association_update_response =>
		#{bbf_up_function_features => {'C',bbf_up_function_features},
		  cp_function_features => {'O',cp_function_features},
		  node_id => {'M',node_id},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  ue_ip_address_usage_information => {'O',#{}},
		  up_function_features => {'O',up_function_features}},
	    heartbeat_request =>
		#{recovery_time_stamp => {'M',recovery_time_stamp},
		  source_ip_address => {'O',source_ip_address},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    heartbeat_response =>
		#{recovery_time_stamp => {'M',recovery_time_stamp},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    node_report_request =>
		#{node_id => {'M',node_id},
		  node_report_type => {'M',node_report_type},
		  tp_build_identifier => {'O',tp_build_identifier},
		  user_plane_path_failure_report =>
		      {'C',#{remote_gtp_u_peer => {'M',remote_gtp_u_peer}}},
		  user_plane_path_recovery_report =>
		      {'C',#{remote_gtp_u_peer => {'M',remote_gtp_u_peer}}}},
	    node_report_response =>
		#{node_id => {'M',node_id},
		  offending_ie => {'C',offending_ie},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}}},
	    session_deletion_request =>
		#{tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    session_deletion_response =>
		#{additional_usage_reports_information =>
		      {'C',additional_usage_reports_information},
		  load_control_information => {'O',load_control_information},
		  offending_ie => {'C',offending_ie},
		  overload_control_information => {'O',overload_control_information},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  usage_report_sdr =>
		      {'C',
			  #{duration_measurement => {'C',duration_measurement},
			    end_time => {'C',end_time},
			    start_time => {'C',start_time},
			    tp_end_time => {'O',tp_end_time},
			    tp_now => {'O',tp_now},
			    tp_start_time => {'O',tp_start_time},
			    ur_seqn => {'M',ur_seqn},
			    urr_id => {'M',urr_id},
			    usage_information => {'C',usage_information},
			    usage_report_trigger => {'M',usage_report_trigger},
			    volume_measurement => {'C',volume_measurement}}}},
	    session_establishment_request =>
		#{apn_dnn => {'O',apn_dnn},
		  create_bar =>
		      {'O',
			  #{bar_id => {'M',bar_id},
			    downlink_data_notification_delay =>
				{'C',downlink_data_notification_delay},
			    mt_edt_control_information => {'O',mt_edt_control_information}}},
		  create_far =>
		      {'M',
			  #{apply_action => {'M',apply_action},
			    bar_id => {'O',bar_id},
			    duplicating_parameters =>
				{'C',
				    #{destination_interface => {'M',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      outer_header_creation => {'C',outer_header_creation},
				      transport_level_marking =>
					  {'C',transport_level_marking}}},
			    far_id => {'M',far_id},
			    forwarding_parameters =>
				{'C',
				    #{destination_interface => {'M',destination_interface},
				      network_instance => {'O',network_instance},
				      outer_header_creation => {'C',outer_header_creation},
				      tgpp_interface_type => {'O',tgpp_interface_type},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      transport_level_marking =>
					  {'C',transport_level_marking}}},
			    tp_ipfix_policy => {'O',tp_ipfix_policy}}},
		  create_pdr =>
		      {'M',
			  #{far_id => {'C',far_id},
			    outer_header_removal => {'C',outer_header_removal},
			    pdi =>
				{'M',
				    #{f_teid => {'O',f_teid},
				      network_instance => {'O',network_instance},
				      source_interface => {'M',source_interface},
				      tgpp_interface_type => {'O',tgpp_interface_type},
				      traffic_endpoint_id => {'C',traffic_endpoint_id}}},
			    pdr_id => {'M',pdr_id},
			    urr_id => {'C',urr_id}}},
		  create_traffic_endpoint =>
		      {'C',
			  #{f_teid => {'O',f_teid},
			    network_instance => {'O',network_instance},
			    tgpp_interface_type => {'O',tgpp_interface_type},
			    traffic_endpoint_id => {'M',traffic_endpoint_id}}},
		  create_urr =>
		      {'C',
			  #{additional_monitoring_time =>
				{'O',
				    #{monitoring_time => {'M',monitoring_time},
				      subsequent_time_threshold =>
					  {'O',subsequent_time_threshold},
				      subsequent_volume_threshold =>
					  {'O',subsequent_volume_threshold}}},
			    dropped_dl_traffic_threshold =>
				{'C',dropped_dl_traffic_threshold},
			    measurement_information => {'C',measurement_information},
			    measurement_method => {'M',measurement_method},
			    measurement_period => {'C',measurement_period},
			    monitoring_time => {'O',monitoring_time},
			    number_of_reports => {'O',number_of_reports},
			    reporting_triggers => {'M',reporting_triggers},
			    subsequent_time_threshold => {'O',subsequent_time_threshold},
			    subsequent_volume_threshold => {'O',subsequent_volume_threshold},
			    time_threshold => {'C',time_threshold},
			    urr_id => {'M',urr_id},
			    volume_threshold => {'C',volume_threshold}}},
		  f_seid => {'M',f_seid},
		  node_id => {'M',node_id},
		  pdn_type => {'C',pdn_type},
		  pfcpsereq_flags => {'C',pfcpsereq_flags},
		  recovery_time_stamp => {'O',recovery_time_stamp},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  trace_information => {'O',trace_information},
		  user_id => {'O',user_id}},
	    session_establishment_response =>
		#{created_pdr => {'C',#{f_teid => {'C',f_teid},pdr_id => {'M',pdr_id}}},
		  created_traffic_endpoint =>
		      {'C',
			  #{f_teid => {'C',f_teid},
			    traffic_endpoint_id => {'M',traffic_endpoint_id}}},
		  f_seid => {'C',f_seid},
		  failed_rule_id => {'C',failed_rule_id},
		  fq_csid => {'C',fq_csid},
		  load_control_information =>
		      {'O',
			  #{metric => {'M',metric},sequence_number => {'M',sequence_number}}},
		  node_id => {'M',node_id},
		  offending_ie => {'C',offending_ie},
		  overload_control_information =>
		      {'O',
			  #{metric => {'M',metric},
			    oci_flags => {'C',oci_flags},
			    sequence_number => {'M',sequence_number},
			    timer => {'M',timer}}},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}}},
	    session_modification_request =>
		#{create_bar =>
		      {'C',
			  #{bar_id => {'M',bar_id},
			    downlink_data_notification_delay =>
				{'C',downlink_data_notification_delay},
			    mt_edt_control_information => {'O',mt_edt_control_information}}},
		  create_far =>
		      {'C',
			  #{apply_action => {'M',apply_action},
			    bar_id => {'O',bar_id},
			    duplicating_parameters =>
				{'C',
				    #{destination_interface => {'M',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      outer_header_creation => {'C',outer_header_creation},
				      transport_level_marking =>
					  {'C',transport_level_marking}}},
			    far_id => {'M',far_id},
			    forwarding_parameters =>
				{'C',
				    #{destination_interface => {'M',destination_interface},
				      network_instance => {'O',network_instance},
				      outer_header_creation => {'C',outer_header_creation},
				      tgpp_interface_type => {'O',tgpp_interface_type},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      transport_level_marking =>
					  {'C',transport_level_marking}}}}},
		  create_pdr =>
		      {'C',
			  #{far_id => {'C',far_id},
			    outer_header_removal => {'C',outer_header_removal},
			    pdi =>
				{'M',
				    #{f_teid => {'O',f_teid},
				      network_instance => {'O',network_instance},
				      source_interface => {'M',source_interface},
				      tgpp_interface_type => {'O',tgpp_interface_type},
				      traffic_endpoint_id => {'C',traffic_endpoint_id}}},
			    pdr_id => {'M',pdr_id},
			    urr_id => {'C',urr_id}}},
		  create_traffic_endpoint =>
		      {'C',
			  #{f_teid => {'O',f_teid},
			    network_instance => {'O',network_instance},
			    traffic_endpoint_id => {'M',traffic_endpoint_id}}},
		  create_urr =>
		      {'C',
			  #{additional_monitoring_time =>
				{'O',
				    #{monitoring_time => {'M',monitoring_time},
				      subsequent_time_threshold =>
					  {'O',subsequent_time_threshold},
				      subsequent_volume_threshold =>
					  {'O',subsequent_volume_threshold}}},
			    dropped_dl_traffic_threshold =>
				{'C',dropped_dl_traffic_threshold},
			    measurement_information => {'C',measurement_information},
			    measurement_method => {'M',measurement_method},
			    measurement_period => {'C',measurement_period},
			    monitoring_time => {'O',monitoring_time},
			    number_of_reports => {'O',number_of_reports},
			    reporting_triggers => {'M',reporting_triggers},
			    subsequent_time_threshold => {'O',subsequent_time_threshold},
			    subsequent_volume_threshold => {'O',subsequent_volume_threshold},
			    time_threshold => {'C',time_threshold},
			    urr_id => {'M',urr_id},
			    volume_threshold => {'C',volume_threshold}}},
		  f_seid => {'C',f_seid},
		  fq_csid => {'C',fq_csid},
		  query_urr => {'C',#{urr_id => {'M',urr_id}}},
		  query_urr_reference => {'O',query_urr_reference},
		  remove_bar => {'C',#{bar_id => {'M',bar_id}}},
		  remove_far => {'C',#{far_id => {'M',far_id}}},
		  remove_pdr => {'C',#{pdr_id => {'M',pdr_id}}},
		  remove_traffic_endpoint =>
		      {'C',#{traffic_endpoint_id => {'M',traffic_endpoint_id}}},
		  remove_urr => {'C',#{urr_id => {'M',urr_id}}},
		  sxsmreq_flags => {'C',sxsmreq_flags},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  trace_information => {'O',trace_information},
		  update_bar =>
		      {'C',
			  #{bar_id => {'M',bar_id},
			    downlink_data_notification_delay =>
				{'C',downlink_data_notification_delay},
			    mt_edt_control_information => {'C',mt_edt_control_information}}},
		  update_far =>
		      {'C',
			  #{apply_action => {'C',apply_action},
			    bar_id => {'C',bar_id},
			    far_id => {'M',far_id},
			    tp_ipfix_policy => {'O',tp_ipfix_policy},
			    update_duplicating_parameters =>
				{'C',
				    #{destination_interface => {'C',destination_interface},
				      outer_header_creation => {'C',outer_header_creation},
				      transport_level_marking =>
					  {'C',transport_level_marking}}},
			    update_forwarding_parameters =>
				{'C',
				    #{destination_interface => {'C',destination_interface},
				      network_instance => {'C',network_instance},
				      outer_header_creation => {'C',outer_header_creation},
				      sxsmreq_flags => {'C',sxsmreq_flags},
				      tgpp_interface_type => {'C',tgpp_interface_type},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      transport_level_marking =>
					  {'C',transport_level_marking}}}}},
		  update_pdr =>
		      {'C',
			  #{far_id => {'C',far_id},
			    outer_header_removal => {'C',outer_header_removal},
			    pdi =>
				{'C',
				    #{f_teid => {'O',f_teid},
				      network_instance => {'O',network_instance},
				      source_interface => {'M',source_interface},
				      traffic_endpoint_id => {'C',traffic_endpoint_id}}},
			    pdr_id => {'M',pdr_id},
			    urr_id => {'C',urr_id}}},
		  update_traffic_endpoint =>
		      {'C',
			  #{f_teid => {'C',f_teid},
			    network_instance => {'O',network_instance},
			    tgpp_interface_type => {'C',tgpp_interface_type},
			    traffic_endpoint_id => {'M',traffic_endpoint_id}}},
		  update_urr =>
		      {'C',
			  #{additional_monitoring_time =>
				{'O',
				    #{monitoring_time => {'M',monitoring_time},
				      subsequent_time_threshold =>
					  {'O',subsequent_time_threshold},
				      subsequent_volume_threshold =>
					  {'O',subsequent_volume_threshold}}},
			    dropped_dl_traffic_threshold =>
				{'C',dropped_dl_traffic_threshold},
			    measurement_method => {'C',measurement_method},
			    measurement_period => {'C',measurement_period},
			    monitoring_time => {'C',monitoring_time},
			    number_of_reports => {'O',number_of_reports},
			    reporting_triggers => {'C',reporting_triggers},
			    subsequent_time_threshold => {'C',subsequent_time_threshold},
			    subsequent_volume_threshold => {'C',subsequent_volume_threshold},
			    time_threshold => {'C',time_threshold},
			    urr_id => {'M',urr_id},
			    volume_threshold => {'C',volume_threshold}}}},
	    session_modification_response =>
		#{additional_usage_reports_information =>
		      {'C',additional_usage_reports_information},
		  created_pdr => {'C',created_pdr},
		  created_traffic_endpoint =>
		      {'C',
			  #{f_teid => {'C',f_teid},
			    traffic_endpoint_id => {'M',traffic_endpoint_id}}},
		  failed_rule_id => {'C',failed_rule_id},
		  load_control_information => {'O',load_control_information},
		  offending_ie => {'C',offending_ie},
		  overload_control_information => {'O',overload_control_information},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  usage_report_smr =>
		      {'C',
			  #{duration_measurement => {'C',duration_measurement},
			    end_time => {'C',end_time},
			    query_urr_reference => {'C',query_urr_reference},
			    start_time => {'C',start_time},
			    tp_end_time => {'O',tp_end_time},
			    tp_now => {'O',tp_now},
			    tp_start_time => {'O',tp_start_time},
			    ur_seqn => {'M',ur_seqn},
			    urr_id => {'M',urr_id},
			    usage_information => {'C',usage_information},
			    usage_report_trigger => {'M',usage_report_trigger},
			    volume_measurement => {'C',volume_measurement}}}},
	    session_report_request =>
		#{additional_usage_reports_information =>
		      {'C',additional_usage_reports_information},
		  downlink_data_report =>
		      {'C',
			  #{dl_data_packets_size => {'C',dl_data_packets_size},
			    downlink_data_service_information =>
				{'C',downlink_data_service_information},
			    pdr_id => {'M',pdr_id}}},
		  error_indication_report => {'C',#{f_teid => {'M',f_teid}}},
		  load_control_information => {'O',load_control_information},
		  overload_control_information => {'O',overload_control_information},
		  pfcpsrreq_flags => {'C',pfcpsrreq_flags},
		  report_type => {'M',report_type},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  usage_report_srr =>
		      {'C',
			  #{duration_measurement => {'C',duration_measurement},
			    end_time => {'C',end_time},
			    query_urr_reference => {'C',query_urr_reference},
			    start_time => {'C',start_time},
			    tp_end_time => {'O',tp_end_time},
			    tp_now => {'O',tp_now},
			    tp_start_time => {'O',tp_start_time},
			    ur_seqn => {'M',ur_seqn},
			    urr_id => {'M',urr_id},
			    usage_information => {'C',usage_information},
			    usage_report_trigger => {'M',usage_report_trigger},
			    volume_measurement => {'C',volume_measurement}}}},
	    session_report_response =>
		#{offending_ie => {'C',offending_ie},
		  pfcp_cause => {'M',pfcp_cause},
		  sxsrrsp_flags => {'C',sxsrrsp_flags},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  update_bar =>
		      {'C',
			  #{bar_id => {'M',bar_id},
			    dl_buffering_duration => {'C',dl_buffering_duration},
			    dl_buffering_suggested_packet_count =>
				{'O',dl_buffering_suggested_packet_count},
			    downlink_data_notification_delay =>
				{'C',downlink_data_notification_delay}}}},
	    session_set_deletion_request =>
		#{fq_csid => {'C',fq_csid},
		  node_id => {'M',node_id},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}}},
	    session_set_deletion_response =>
		#{node_id => {'M',node_id},
		  offending_ie => {'C',offending_ie},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}}},
	    version_not_supported_response => #{}},
      'Sxb' =>
	  #{association_release_request =>
		#{node_id => {'M',node_id},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    association_release_response =>
		#{node_id => {'M',node_id},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    association_setup_request =>
		#{alternative_smf_ip_address => {'O',alternative_smf_ip_address},
		  bbf_up_function_features => {'C',bbf_up_function_features},
		  clock_drift_control_information => {'O',#{}},
		  cp_function_features => {'C',cp_function_features},
		  gtp_u_path_qos_control_information => {'C',#{}},
		  nf_instance_id => {'O',nf_instance_id},
		  node_id => {'M',node_id},
		  pfcp_session_retention_information =>
		      {'O',#{cp_pfcp_entity_ip_address => {'O',cp_pfcp_entity_ip_address}}},
		  pfcpasreq_flags => {'O',pfcpasreq_flags},
		  recovery_time_stamp => {'M',recovery_time_stamp},
		  smf_set_id => {'C',smf_set_id},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  ue_ip_address_pool_information =>
		      {'O',
			  #{network_instance => {'O',network_instance},
			    ue_ip_address_pool_identity =>
				{'M',ue_ip_address_pool_identity}}},
		  up_function_features => {'C',up_function_features},
		  user_plane_ip_resource_information =>
		      {'O',user_plane_ip_resource_information}},
	    association_setup_response =>
		#{alternative_smf_ip_address => {'O',alternative_smf_ip_address},
		  bbf_up_function_features => {'C',bbf_up_function_features},
		  clock_drift_control_information => {'C',#{}},
		  cp_function_features => {'C',cp_function_features},
		  gtp_u_path_qos_control_information => {'C',#{}},
		  nf_instance_id => {'O',nf_instance_id},
		  node_id => {'M',node_id},
		  pfcp_cause => {'M',pfcp_cause},
		  pfcpasrsp_flags => {'O',pfcpasrsp_flags},
		  recovery_time_stamp => {'M',recovery_time_stamp},
		  smf_set_id => {'C',smf_set_id},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  ue_ip_address_pool_information =>
		      {'O',
			  #{network_instance => {'O',network_instance},
			    ue_ip_address_pool_identity =>
				{'M',ue_ip_address_pool_identity}}},
		  up_function_features => {'C',up_function_features},
		  user_plane_ip_resource_information =>
		      {'O',user_plane_ip_resource_information}},
	    association_update_request =>
		#{alternative_smf_ip_address => {'O',alternative_smf_ip_address},
		  bbf_up_function_features => {'C',bbf_up_function_features},
		  clock_drift_control_information => {'C',#{}},
		  cp_function_features => {'O',cp_function_features},
		  graceful_release_period => {'C',graceful_release_period},
		  gtp_u_path_qos_information => {'C',#{}},
		  node_id => {'M',node_id},
		  pfcp_association_release_request => {'C',pfcp_association_release_request},
		  pfcpaureq_flags => {'O',pfcpaureq_flags},
		  smf_set_id => {'C',smf_set_id},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  ue_ip_address_pool_information =>
		      {'O',
			  #{network_instance => {'O',network_instance},
			    ue_ip_address_pool_identity =>
				{'M',ue_ip_address_pool_identity}}},
		  ue_ip_address_usage_information =>
		      {'O',
			  #{metric => {'M',metric},
			    network_instance => {'M',network_instance},
			    number_of_ue_ip_addresses => {'M',number_of_ue_ip_addresses},
			    sequence_number => {'M',sequence_number},
			    ue_ip_address_pool_identity => {'O',ue_ip_address_pool_identity},
			    validity_timer => {'M',validity_timer}}},
		  up_function_features => {'O',up_function_features},
		  user_plane_ip_resource_information =>
		      {'O',user_plane_ip_resource_information}},
	    association_update_response =>
		#{bbf_up_function_features => {'C',bbf_up_function_features},
		  cp_function_features => {'O',cp_function_features},
		  node_id => {'M',node_id},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  ue_ip_address_usage_information =>
		      {'O',
			  #{metric => {'M',metric},
			    network_instance => {'M',network_instance},
			    number_of_ue_ip_addresses => {'M',number_of_ue_ip_addresses},
			    sequence_number => {'M',sequence_number},
			    ue_ip_address_pool_identity => {'O',ue_ip_address_pool_identity},
			    validity_timer => {'M',validity_timer}}},
		  up_function_features => {'O',up_function_features}},
	    heartbeat_request =>
		#{recovery_time_stamp => {'M',recovery_time_stamp},
		  source_ip_address => {'O',source_ip_address},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    heartbeat_response =>
		#{recovery_time_stamp => {'M',recovery_time_stamp},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    node_report_request =>
		#{node_id => {'M',node_id},
		  node_report_type => {'M',node_report_type},
		  tp_build_identifier => {'O',tp_build_identifier},
		  user_plane_path_failure_report =>
		      {'C',#{remote_gtp_u_peer => {'M',remote_gtp_u_peer}}},
		  user_plane_path_recovery_report =>
		      {'C',#{remote_gtp_u_peer => {'M',remote_gtp_u_peer}}}},
	    node_report_response =>
		#{node_id => {'M',node_id},
		  offending_ie => {'C',offending_ie},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}}},
	    pfd_management_request =>
		#{'application_id\'s_pfds' =>
		      {'M',
			  #{application_id => {'M',application_id},
			    pfd_context => {'C',#{pfd_contents => {'M',pfd_contents}}}}}},
	    pfd_management_response =>
		#{offending_ie => {'C',offending_ie},pfcp_cause => {'M',pfcp_cause}},
	    session_deletion_request =>
		#{tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    session_deletion_response =>
		#{additional_usage_reports_information =>
		      {'C',additional_usage_reports_information},
		  load_control_information => {'O',load_control_information},
		  offending_ie => {'C',offending_ie},
		  overload_control_information => {'O',overload_control_information},
		  packet_rate_status_report =>
		      {'C',
			  #{packet_rate_status => {'M',packet_rate_status},
			    qer_id => {'M',qer_id}}},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  usage_report_sdr =>
		      {'C',
			  #{duration_measurement => {'C',duration_measurement},
			    end_time => {'C',end_time},
			    start_time => {'C',start_time},
			    time_of_first_packet => {'C',time_of_first_packet},
			    time_of_last_packet => {'C',time_of_last_packet},
			    tp_end_time => {'O',tp_end_time},
			    tp_now => {'O',tp_now},
			    tp_start_time => {'O',tp_start_time},
			    ur_seqn => {'M',ur_seqn},
			    urr_id => {'M',urr_id},
			    usage_information => {'C',usage_information},
			    usage_report_trigger => {'M',usage_report_trigger},
			    volume_measurement => {'C',volume_measurement}}}},
	    session_establishment_request =>
		#{apn_dnn => {'O',apn_dnn},
		  create_far =>
		      {'M',
			  #{apply_action => {'M',apply_action},
			    duplicating_parameters =>
				{'C',
				    #{destination_interface => {'M',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      outer_header_creation => {'C',outer_header_creation},
				      transport_level_marking =>
					  {'C',transport_level_marking}}},
			    far_id => {'M',far_id},
			    forwarding_parameters =>
				{'C',
				    #{bbf_apply_action => {'O',bbf_apply_action},
				      bbf_nat_port_block => {'O',bbf_nat_port_block},
				      destination_interface => {'M',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      header_enrichment => {'O',header_enrichment},
				      network_instance => {'O',network_instance},
				      outer_header_creation => {'C',outer_header_creation},
				      redirect_information => {'C',redirect_information},
				      tgpp_interface_type => {'O',tgpp_interface_type},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      transport_level_marking =>
					  {'C',transport_level_marking}}},
			    tp_ipfix_policy => {'O',tp_ipfix_policy}}},
		  create_pdr =>
		      {'M',
			  #{activate_predefined_rules => {'C',activate_predefined_rules},
			    activation_time => {'O',activation_time},
			    deactivation_time => {'O',deactivation_time},
			    far_id => {'C',far_id},
			    outer_header_removal => {'C',outer_header_removal},
			    pdi =>
				{'M',
				    #{application_id => {'O',application_id},
				      f_teid => {'O',f_teid},
				      framed_ipv6_route => {'O',framed_ipv6_route},
				      framed_route => {'O',framed_route},
				      framed_routing => {'O',framed_routing},
				      network_instance => {'O',network_instance},
				      sdf_filter => {'O',sdf_filter},
				      source_interface => {'M',source_interface},
				      tgpp_interface_type => {'O',tgpp_interface_type},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      ue_ip_address => {'O',ue_ip_address}}},
			    pdr_id => {'M',pdr_id},
			    precedence => {'M',precedence},
			    qer_id => {'C',qer_id},
			    ue_ip_address_pool_identity => {'O',ue_ip_address_pool_identity},
			    urr_id => {'C',urr_id}}},
		  create_qer =>
		      {'C',
			  #{dl_flow_level_marking => {'C',dl_flow_level_marking},
			    gate_status => {'M',gate_status},
			    gbr => {'C',gbr},
			    mbr => {'C',mbr},
			    packet_rate => {'C',packet_rate},
			    packet_rate_status => {'C',packet_rate_status},
			    qer_control_indications => {'C',qer_control_indications},
			    qer_correlation_id => {'C',qer_correlation_id},
			    qer_id => {'M',qer_id}}},
		  create_traffic_endpoint =>
		      {'C',
			  #{f_teid => {'O',f_teid},
			    framed_ipv6_route => {'O',framed_ipv6_route},
			    framed_route => {'O',framed_route},
			    framed_routing => {'O',framed_routing},
			    network_instance => {'O',network_instance},
			    tgpp_interface_type => {'O',tgpp_interface_type},
			    traffic_endpoint_id => {'M',traffic_endpoint_id},
			    ue_ip_address => {'O',ue_ip_address}}},
		  create_urr =>
		      {'C',
			  #{additional_monitoring_time =>
				{'O',
				    #{event_quota => {'O',event_quota},
				      event_threshold => {'O',event_threshold},
				      monitoring_time => {'M',monitoring_time},
				      subsequent_time_quota => {'O',subsequent_time_quota},
				      subsequent_time_threshold =>
					  {'O',subsequent_time_threshold},
				      subsequent_volume_quota =>
					  {'O',subsequent_volume_quota},
				      subsequent_volume_threshold =>
					  {'O',subsequent_volume_threshold}}},
			    aggregated_urrs =>
				{'C',
				    #{aggregated_urr_id => {'M',aggregated_urr_id},
				      multiplier => {'M',multiplier}}},
			    event_quota => {'C',event_quota},
			    event_threshold => {'C',event_threshold},
			    far_id => {'C',far_id},
			    inactivity_detection_time => {'C',inactivity_detection_time},
			    linked_urr_id => {'C',linked_urr_id},
			    measurement_information => {'C',measurement_information},
			    measurement_method => {'M',measurement_method},
			    measurement_period => {'C',measurement_period},
			    monitoring_time => {'O',monitoring_time},
			    number_of_reports => {'O',number_of_reports},
			    quota_holding_time => {'C',quota_holding_time},
			    quota_validity_time => {'C',quota_validity_time},
			    reporting_triggers => {'M',reporting_triggers},
			    subsequent_event_quota => {'O',subsequent_event_quota},
			    subsequent_event_threshold => {'O',subsequent_event_threshold},
			    subsequent_time_quota => {'O',subsequent_time_quota},
			    subsequent_time_threshold => {'O',subsequent_time_threshold},
			    subsequent_volume_quota => {'O',subsequent_volume_quota},
			    subsequent_volume_threshold => {'O',subsequent_volume_threshold},
			    time_quota => {'C',time_quota},
			    time_quota_mechanism => {'C',time_quota_mechanism},
			    time_threshold => {'C',time_threshold},
			    urr_id => {'M',urr_id},
			    volume_quota => {'C',volume_quota},
			    volume_threshold => {'C',volume_threshold}}},
		  f_seid => {'M',f_seid},
		  fq_csid => {'C',fq_csid},
		  node_id => {'M',node_id},
		  pdn_type => {'C',pdn_type},
		  pfcpsereq_flags => {'C',pfcpsereq_flags},
		  provide_rds_configuration_information =>
		      {'O',provide_rds_configuration_information},
		  recovery_time_stamp => {'O',recovery_time_stamp},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  trace_information => {'O',trace_information},
		  user_id => {'O',user_id},
		  user_plane_inactivity_timer => {'O',user_plane_inactivity_timer}},
	    session_establishment_response =>
		#{created_pdr =>
		      {'C',
			  #{f_teid => {'C',f_teid},
			    pdr_id => {'M',pdr_id},
			    ue_ip_address => {'C',ue_ip_address}}},
		  created_traffic_endpoint =>
		      {'C',
			  #{f_teid => {'C',f_teid},
			    traffic_endpoint_id => {'M',traffic_endpoint_id},
			    ue_ip_address => {'C',ue_ip_address}}},
		  f_seid => {'C',f_seid},
		  failed_rule_id => {'C',failed_rule_id},
		  fq_csid => {'C',fq_csid},
		  load_control_information =>
		      {'O',
			  #{metric => {'M',metric},sequence_number => {'M',sequence_number}}},
		  node_id => {'M',node_id},
		  offending_ie => {'C',offending_ie},
		  overload_control_information =>
		      {'O',
			  #{metric => {'M',metric},
			    oci_flags => {'C',oci_flags},
			    sequence_number => {'M',sequence_number},
			    timer => {'M',timer}}},
		  pfcp_cause => {'M',pfcp_cause},
		  rds_configuration_information => {'O',rds_configuration_information},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_created_nat_binding =>
		      {'C',
			  #{bbf_nat_outside_address => {'C',bbf_nat_outside_address},
			    bbf_nat_port_block => {'C',bbf_nat_port_block}}},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}}},
	    session_modification_request =>
		#{create_far =>
		      {'C',
			  #{apply_action => {'M',apply_action},
			    duplicating_parameters =>
				{'C',
				    #{destination_interface => {'M',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      outer_header_creation => {'C',outer_header_creation},
				      transport_level_marking =>
					  {'C',transport_level_marking}}},
			    far_id => {'M',far_id},
			    forwarding_parameters =>
				{'C',
				    #{bbf_apply_action => {'O',bbf_apply_action},
				      bbf_nat_port_block => {'O',bbf_nat_port_block},
				      destination_interface => {'M',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      header_enrichment => {'O',header_enrichment},
				      network_instance => {'O',network_instance},
				      outer_header_creation => {'C',outer_header_creation},
				      redirect_information => {'C',redirect_information},
				      tgpp_interface_type => {'O',tgpp_interface_type},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      transport_level_marking =>
					  {'C',transport_level_marking}}}}},
		  create_pdr =>
		      {'C',
			  #{activate_predefined_rules => {'C',activate_predefined_rules},
			    activation_time => {'O',activation_time},
			    deactivation_time => {'O',deactivation_time},
			    far_id => {'C',far_id},
			    outer_header_removal => {'C',outer_header_removal},
			    pdi =>
				{'M',
				    #{application_id => {'O',application_id},
				      f_teid => {'O',f_teid},
				      framed_ipv6_route => {'O',framed_ipv6_route},
				      framed_route => {'O',framed_route},
				      framed_routing => {'O',framed_routing},
				      network_instance => {'O',network_instance},
				      sdf_filter => {'O',sdf_filter},
				      source_interface => {'M',source_interface},
				      tgpp_interface_type => {'O',tgpp_interface_type},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      ue_ip_address => {'O',ue_ip_address}}},
			    pdr_id => {'M',pdr_id},
			    precedence => {'M',precedence},
			    qer_id => {'C',qer_id},
			    ue_ip_address_pool_identity => {'O',ue_ip_address_pool_identity},
			    urr_id => {'C',urr_id}}},
		  create_qer =>
		      {'C',
			  #{dl_flow_level_marking => {'C',dl_flow_level_marking},
			    gate_status => {'M',gate_status},
			    gbr => {'C',gbr},
			    mbr => {'C',mbr},
			    packet_rate => {'C',packet_rate},
			    packet_rate_status => {'C',packet_rate_status},
			    qer_control_indications => {'C',qer_control_indications},
			    qer_correlation_id => {'C',qer_correlation_id},
			    qer_id => {'M',qer_id}}},
		  create_traffic_endpoint =>
		      {'C',
			  #{f_teid => {'O',f_teid},
			    framed_ipv6_route => {'O',framed_ipv6_route},
			    framed_route => {'O',framed_route},
			    framed_routing => {'O',framed_routing},
			    network_instance => {'O',network_instance},
			    traffic_endpoint_id => {'M',traffic_endpoint_id},
			    ue_ip_address => {'O',ue_ip_address}}},
		  create_urr =>
		      {'C',
			  #{additional_monitoring_time =>
				{'O',
				    #{event_quota => {'O',event_quota},
				      event_threshold => {'O',event_threshold},
				      monitoring_time => {'M',monitoring_time},
				      subsequent_time_quota => {'O',subsequent_time_quota},
				      subsequent_time_threshold =>
					  {'O',subsequent_time_threshold},
				      subsequent_volume_quota =>
					  {'O',subsequent_volume_quota},
				      subsequent_volume_threshold =>
					  {'O',subsequent_volume_threshold}}},
			    aggregated_urrs =>
				{'C',
				    #{aggregated_urr_id => {'M',aggregated_urr_id},
				      multiplier => {'M',multiplier}}},
			    event_quota => {'C',event_quota},
			    event_threshold => {'C',event_threshold},
			    far_id => {'C',far_id},
			    inactivity_detection_time => {'C',inactivity_detection_time},
			    linked_urr_id => {'C',linked_urr_id},
			    measurement_information => {'C',measurement_information},
			    measurement_method => {'M',measurement_method},
			    measurement_period => {'C',measurement_period},
			    monitoring_time => {'O',monitoring_time},
			    number_of_reports => {'O',number_of_reports},
			    quota_holding_time => {'C',quota_holding_time},
			    quota_validity_time => {'C',quota_validity_time},
			    reporting_triggers => {'M',reporting_triggers},
			    subsequent_event_quota => {'O',subsequent_event_quota},
			    subsequent_event_threshold => {'O',subsequent_event_threshold},
			    subsequent_time_quota => {'O',subsequent_time_quota},
			    subsequent_time_threshold => {'O',subsequent_time_threshold},
			    subsequent_volume_quota => {'O',subsequent_volume_quota},
			    subsequent_volume_threshold => {'O',subsequent_volume_threshold},
			    time_quota => {'C',time_quota},
			    time_quota_mechanism => {'C',time_quota_mechanism},
			    time_threshold => {'C',time_threshold},
			    urr_id => {'M',urr_id},
			    volume_quota => {'C',volume_quota},
			    volume_threshold => {'C',volume_threshold}}},
		  f_seid => {'C',f_seid},
		  fq_csid => {'C',fq_csid},
		  query_packet_rate_status_ie_smreq => {'C',#{qer_id => {'M',qer_id}}},
		  query_urr => {'C',#{urr_id => {'M',urr_id}}},
		  query_urr_reference => {'O',query_urr_reference},
		  remove_far => {'C',#{far_id => {'M',far_id}}},
		  remove_pdr => {'C',#{pdr_id => {'M',pdr_id}}},
		  remove_qer => {'C',#{qer_id => {'M',qer_id}}},
		  remove_traffic_endpoint =>
		      {'C',#{traffic_endpoint_id => {'M',traffic_endpoint_id}}},
		  remove_urr => {'C',#{urr_id => {'M',urr_id}}},
		  sxsmreq_flags => {'C',sxsmreq_flags},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  trace_information => {'O',trace_information},
		  update_far =>
		      {'C',
			  #{apply_action => {'C',apply_action},
			    far_id => {'M',far_id},
			    tp_ipfix_policy => {'O',tp_ipfix_policy},
			    update_duplicating_parameters =>
				{'C',
				    #{destination_interface => {'C',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      outer_header_creation => {'C',outer_header_creation},
				      transport_level_marking =>
					  {'C',transport_level_marking}}},
			    update_forwarding_parameters =>
				{'C',
				    #{bbf_apply_action => {'O',bbf_apply_action},
				      bbf_nat_port_block => {'O',bbf_nat_port_block},
				      destination_interface => {'C',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      header_enrichment => {'C',header_enrichment},
				      network_instance => {'C',network_instance},
				      outer_header_creation => {'C',outer_header_creation},
				      redirect_information => {'C',redirect_information},
				      sxsmreq_flags => {'C',sxsmreq_flags},
				      tgpp_interface_type => {'C',tgpp_interface_type},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      transport_level_marking =>
					  {'C',transport_level_marking}}}}},
		  update_pdr =>
		      {'C',
			  #{activate_predefined_rules => {'C',activate_predefined_rules},
			    activation_time => {'O',activation_time},
			    deactivate_predefined_rules => {'C',deactivate_predefined_rules},
			    deactivation_time => {'O',deactivation_time},
			    far_id => {'C',far_id},
			    outer_header_removal => {'C',outer_header_removal},
			    pdi =>
				{'C',
				    #{application_id => {'O',application_id},
				      f_teid => {'O',f_teid},
				      framed_ipv6_route => {'O',framed_ipv6_route},
				      framed_route => {'O',framed_route},
				      framed_routing => {'O',framed_routing},
				      network_instance => {'O',network_instance},
				      sdf_filter => {'O',sdf_filter},
				      source_interface => {'M',source_interface},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      ue_ip_address => {'O',ue_ip_address}}},
			    pdr_id => {'M',pdr_id},
			    precedence => {'C',precedence},
			    qer_id => {'C',qer_id},
			    urr_id => {'C',urr_id}}},
		  update_qer =>
		      {'C',
			  #{dl_flow_level_marking => {'C',dl_flow_level_marking},
			    gate_status => {'C',gate_status},
			    gbr => {'C',gbr},
			    mbr => {'C',mbr},
			    packet_rate => {'C',packet_rate},
			    qer_control_indications => {'C',qer_control_indications},
			    qer_correlation_id => {'C',qer_correlation_id},
			    qer_id => {'M',qer_id}}},
		  update_traffic_endpoint =>
		      {'C',
			  #{framed_ipv6_route => {'C',framed_ipv6_route},
			    framed_route => {'C',framed_route},
			    framed_routing => {'C',framed_routing},
			    network_instance => {'O',network_instance},
			    tgpp_interface_type => {'C',tgpp_interface_type},
			    traffic_endpoint_id => {'M',traffic_endpoint_id},
			    ue_ip_address => {'C',ue_ip_address}}},
		  update_urr =>
		      {'C',
			  #{additional_monitoring_time =>
				{'O',
				    #{event_quota => {'O',event_quota},
				      event_threshold => {'O',event_threshold},
				      monitoring_time => {'M',monitoring_time},
				      subsequent_time_quota => {'O',subsequent_time_quota},
				      subsequent_time_threshold =>
					  {'O',subsequent_time_threshold},
				      subsequent_volume_quota =>
					  {'O',subsequent_volume_quota},
				      subsequent_volume_threshold =>
					  {'O',subsequent_volume_threshold}}},
			    aggregated_urrs => {'C',aggregated_urrs},
			    event_quota => {'C',event_quota},
			    event_threshold => {'C',event_threshold},
			    far_id => {'C',far_id},
			    inactivity_detection_time => {'C',inactivity_detection_time},
			    linked_urr_id => {'C',linked_urr_id},
			    measurement_information => {'C',measurement_information},
			    measurement_method => {'C',measurement_method},
			    measurement_period => {'C',measurement_period},
			    monitoring_time => {'C',monitoring_time},
			    number_of_reports => {'O',number_of_reports},
			    quota_holding_time => {'C',quota_holding_time},
			    quota_validity_time => {'C',quota_validity_time},
			    reporting_triggers => {'C',reporting_triggers},
			    subsequent_event_quota => {'O',subsequent_event_quota},
			    subsequent_event_threshold => {'O',subsequent_event_threshold},
			    subsequent_time_quota => {'C',subsequent_time_quota},
			    subsequent_time_threshold => {'C',subsequent_time_threshold},
			    subsequent_volume_quota => {'C',subsequent_volume_quota},
			    subsequent_volume_threshold => {'C',subsequent_volume_threshold},
			    time_quota => {'C',time_quota},
			    time_quota_mechanism => {'C',time_quota_mechanism},
			    time_threshold => {'C',time_threshold},
			    urr_id => {'M',urr_id},
			    volume_quota => {'C',volume_quota},
			    volume_threshold => {'C',volume_threshold}}},
		  user_plane_inactivity_timer => {'C',user_plane_inactivity_timer}},
	    session_modification_response =>
		#{additional_usage_reports_information =>
		      {'C',additional_usage_reports_information},
		  created_pdr => {'C',created_pdr},
		  created_traffic_endpoint =>
		      {'C',
			  #{f_teid => {'C',f_teid},
			    traffic_endpoint_id => {'M',traffic_endpoint_id},
			    ue_ip_address => {'C',ue_ip_address}}},
		  failed_rule_id => {'C',failed_rule_id},
		  load_control_information => {'O',load_control_information},
		  offending_ie => {'C',offending_ie},
		  overload_control_information => {'O',overload_control_information},
		  packet_rate_status_report_ie_smresp =>
		      {'C',
			  #{packet_rate_status => {'M',packet_rate_status},
			    qer_id => {'M',qer_id}}},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_created_nat_binding =>
		      {'C',
			  #{bbf_nat_outside_address => {'C',bbf_nat_outside_address},
			    bbf_nat_port_block => {'C',bbf_nat_port_block}}},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  usage_report_smr =>
		      {'C',
			  #{duration_measurement => {'C',duration_measurement},
			    end_time => {'C',end_time},
			    query_urr_reference => {'C',query_urr_reference},
			    start_time => {'C',start_time},
			    time_of_first_packet => {'C',time_of_first_packet},
			    time_of_last_packet => {'C',time_of_last_packet},
			    tp_end_time => {'O',tp_end_time},
			    tp_now => {'O',tp_now},
			    tp_start_time => {'O',tp_start_time},
			    ur_seqn => {'M',ur_seqn},
			    urr_id => {'M',urr_id},
			    usage_information => {'C',usage_information},
			    usage_report_trigger => {'M',usage_report_trigger},
			    volume_measurement => {'C',volume_measurement}}}},
	    session_report_request =>
		#{additional_usage_reports_information =>
		      {'C',additional_usage_reports_information},
		  error_indication_report => {'C',#{f_teid => {'M',f_teid}}},
		  load_control_information => {'O',load_control_information},
		  overload_control_information => {'O',overload_control_information},
		  packet_rate_status_report =>
		      {'C',
			  #{packet_rate_status => {'M',packet_rate_status},
			    qer_id => {'M',qer_id}}},
		  pfcpsrreq_flags => {'C',pfcpsrreq_flags},
		  report_type => {'M',report_type},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  usage_report_srr =>
		      {'C',
			  #{application_detection_information =>
				{'C',
				    #{application_id => {'M',application_id},
				      application_instance_id =>
					  {'C',application_instance_id},
				      flow_information => {'C',flow_information},
				      pdr_id => {'O',pdr_id}}},
			    duration_measurement => {'C',duration_measurement},
			    end_time => {'C',end_time},
			    event_time_stamp => {'C',event_time_stamp},
			    query_urr_reference => {'C',query_urr_reference},
			    start_time => {'C',start_time},
			    time_of_first_packet => {'C',time_of_first_packet},
			    time_of_last_packet => {'C',time_of_last_packet},
			    tp_end_time => {'O',tp_end_time},
			    tp_now => {'O',tp_now},
			    tp_start_time => {'O',tp_start_time},
			    ur_seqn => {'M',ur_seqn},
			    urr_id => {'M',urr_id},
			    usage_information => {'C',usage_information},
			    usage_report_trigger => {'M',usage_report_trigger},
			    volume_measurement => {'C',volume_measurement}}}},
	    session_report_response =>
		#{offending_ie => {'C',offending_ie},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}}},
	    session_set_deletion_request =>
		#{fq_csid => {'C',fq_csid},
		  node_id => {'M',node_id},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}}},
	    session_set_deletion_response =>
		#{node_id => {'M',node_id},
		  offending_ie => {'C',offending_ie},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}}},
	    version_not_supported_response => #{}},
      'Sxc' =>
	  #{association_release_request =>
		#{node_id => {'M',node_id},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    association_release_response =>
		#{node_id => {'M',node_id},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    association_setup_request =>
		#{alternative_smf_ip_address => {'O',alternative_smf_ip_address},
		  bbf_up_function_features => {'C',bbf_up_function_features},
		  clock_drift_control_information => {'O',#{}},
		  cp_function_features => {'C',cp_function_features},
		  gtp_u_path_qos_control_information => {'C',#{}},
		  nf_instance_id => {'O',nf_instance_id},
		  node_id => {'M',node_id},
		  pfcp_session_retention_information =>
		      {'O',#{cp_pfcp_entity_ip_address => {'O',cp_pfcp_entity_ip_address}}},
		  pfcpasreq_flags => {'O',pfcpasreq_flags},
		  recovery_time_stamp => {'M',recovery_time_stamp},
		  smf_set_id => {'C',smf_set_id},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  ue_ip_address_pool_information => {'O',#{}},
		  up_function_features => {'C',up_function_features},
		  user_plane_ip_resource_information =>
		      {'O',user_plane_ip_resource_information}},
	    association_setup_response =>
		#{alternative_smf_ip_address => {'O',alternative_smf_ip_address},
		  bbf_up_function_features => {'C',bbf_up_function_features},
		  clock_drift_control_information => {'C',#{}},
		  cp_function_features => {'C',cp_function_features},
		  gtp_u_path_qos_control_information => {'C',#{}},
		  nf_instance_id => {'O',nf_instance_id},
		  node_id => {'M',node_id},
		  pfcp_cause => {'M',pfcp_cause},
		  pfcpasrsp_flags => {'O',pfcpasrsp_flags},
		  recovery_time_stamp => {'M',recovery_time_stamp},
		  smf_set_id => {'C',smf_set_id},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  ue_ip_address_pool_information => {'O',#{}},
		  up_function_features => {'C',up_function_features},
		  user_plane_ip_resource_information =>
		      {'O',user_plane_ip_resource_information}},
	    association_update_request =>
		#{alternative_smf_ip_address => {'O',alternative_smf_ip_address},
		  bbf_up_function_features => {'C',bbf_up_function_features},
		  clock_drift_control_information => {'C',#{}},
		  cp_function_features => {'O',cp_function_features},
		  graceful_release_period => {'C',graceful_release_period},
		  gtp_u_path_qos_information => {'C',#{}},
		  node_id => {'M',node_id},
		  pfcp_association_release_request => {'C',pfcp_association_release_request},
		  pfcpaureq_flags => {'O',pfcpaureq_flags},
		  smf_set_id => {'C',smf_set_id},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  ue_ip_address_pool_information => {'O',#{}},
		  ue_ip_address_usage_information => {'O',#{}},
		  up_function_features => {'O',up_function_features},
		  user_plane_ip_resource_information =>
		      {'O',user_plane_ip_resource_information}},
	    association_update_response =>
		#{bbf_up_function_features => {'C',bbf_up_function_features},
		  cp_function_features => {'O',cp_function_features},
		  node_id => {'M',node_id},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  ue_ip_address_usage_information => {'O',#{}},
		  up_function_features => {'O',up_function_features}},
	    heartbeat_request =>
		#{recovery_time_stamp => {'M',recovery_time_stamp},
		  source_ip_address => {'O',source_ip_address},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    heartbeat_response =>
		#{recovery_time_stamp => {'M',recovery_time_stamp},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    node_report_request =>
		#{node_id => {'M',node_id},
		  node_report_type => {'M',node_report_type},
		  tp_build_identifier => {'O',tp_build_identifier}},
	    node_report_response =>
		#{node_id => {'M',node_id},
		  offending_ie => {'C',offending_ie},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}}},
	    pfd_management_request =>
		#{'application_id\'s_pfds' =>
		      {'M',
			  #{application_id => {'M',application_id},
			    pfd_context => {'C',#{pfd_contents => {'M',pfd_contents}}}}}},
	    pfd_management_response =>
		#{offending_ie => {'C',offending_ie},pfcp_cause => {'M',pfcp_cause}},
	    session_deletion_request =>
		#{tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}}},
	    session_deletion_response =>
		#{additional_usage_reports_information =>
		      {'C',additional_usage_reports_information},
		  load_control_information => {'O',load_control_information},
		  offending_ie => {'C',offending_ie},
		  overload_control_information => {'O',overload_control_information},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  usage_report_sdr =>
		      {'C',
			  #{duration_measurement => {'C',duration_measurement},
			    end_time => {'C',end_time},
			    start_time => {'C',start_time},
			    time_of_first_packet => {'C',time_of_first_packet},
			    time_of_last_packet => {'C',time_of_last_packet},
			    tp_end_time => {'O',tp_end_time},
			    tp_now => {'O',tp_now},
			    tp_start_time => {'O',tp_start_time},
			    ur_seqn => {'M',ur_seqn},
			    urr_id => {'M',urr_id},
			    usage_information => {'C',usage_information},
			    usage_report_trigger => {'M',usage_report_trigger},
			    volume_measurement => {'C',volume_measurement}}}},
	    session_establishment_request =>
		#{create_far =>
		      {'M',
			  #{apply_action => {'M',apply_action},
			    far_id => {'M',far_id},
			    forwarding_parameters =>
				{'C',
				    #{destination_interface => {'M',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      header_enrichment => {'O',header_enrichment},
				      network_instance => {'O',network_instance},
				      redirect_information => {'C',redirect_information}}},
			    tp_ipfix_policy => {'O',tp_ipfix_policy}}},
		  create_pdr =>
		      {'M',
			  #{activate_predefined_rules => {'C',activate_predefined_rules},
			    activation_time => {'O',activation_time},
			    deactivation_time => {'O',deactivation_time},
			    far_id => {'C',far_id},
			    pdi =>
				{'M',
				    #{application_id => {'O',application_id},
				      network_instance => {'O',network_instance},
				      sdf_filter => {'O',sdf_filter},
				      source_interface => {'M',source_interface},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      ue_ip_address => {'O',ue_ip_address}}},
			    pdr_id => {'M',pdr_id},
			    precedence => {'M',precedence},
			    qer_id => {'C',qer_id},
			    urr_id => {'C',urr_id}}},
		  create_qer =>
		      {'C',
			  #{dl_flow_level_marking => {'C',dl_flow_level_marking},
			    gate_status => {'M',gate_status},
			    gbr => {'C',gbr},
			    mbr => {'C',mbr},
			    qer_id => {'M',qer_id}}},
		  create_traffic_endpoint =>
		      {'C',
			  #{network_instance => {'O',network_instance},
			    traffic_endpoint_id => {'M',traffic_endpoint_id},
			    ue_ip_address => {'O',ue_ip_address}}},
		  create_urr =>
		      {'C',
			  #{additional_monitoring_time =>
				{'O',
				    #{event_quota => {'O',event_quota},
				      event_threshold => {'O',event_threshold},
				      monitoring_time => {'M',monitoring_time},
				      subsequent_time_quota => {'O',subsequent_time_quota},
				      subsequent_time_threshold =>
					  {'O',subsequent_time_threshold},
				      subsequent_volume_quota =>
					  {'O',subsequent_volume_quota},
				      subsequent_volume_threshold =>
					  {'O',subsequent_volume_threshold}}},
			    event_quota => {'C',event_quota},
			    event_threshold => {'C',event_threshold},
			    far_id => {'C',far_id},
			    inactivity_detection_time => {'C',inactivity_detection_time},
			    linked_urr_id => {'C',linked_urr_id},
			    measurement_information => {'C',measurement_information},
			    measurement_method => {'M',measurement_method},
			    measurement_period => {'C',measurement_period},
			    monitoring_time => {'O',monitoring_time},
			    number_of_reports => {'O',number_of_reports},
			    quota_holding_time => {'C',quota_holding_time},
			    reporting_triggers => {'M',reporting_triggers},
			    subsequent_event_quota => {'O',subsequent_event_quota},
			    subsequent_event_threshold => {'O',subsequent_event_threshold},
			    subsequent_time_quota => {'O',subsequent_time_quota},
			    subsequent_time_threshold => {'O',subsequent_time_threshold},
			    subsequent_volume_quota => {'O',subsequent_volume_quota},
			    subsequent_volume_threshold => {'O',subsequent_volume_threshold},
			    time_quota => {'C',time_quota},
			    time_threshold => {'C',time_threshold},
			    urr_id => {'M',urr_id},
			    volume_quota => {'C',volume_quota},
			    volume_threshold => {'C',volume_threshold}}},
		  f_seid => {'M',f_seid},
		  node_id => {'M',node_id},
		  recovery_time_stamp => {'O',recovery_time_stamp},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  trace_information => {'O',trace_information},
		  user_id => {'O',user_id},
		  user_plane_inactivity_timer => {'O',user_plane_inactivity_timer}},
	    session_establishment_response =>
		#{f_seid => {'C',f_seid},
		  failed_rule_id => {'C',failed_rule_id},
		  load_control_information =>
		      {'O',
			  #{metric => {'M',metric},sequence_number => {'M',sequence_number}}},
		  node_id => {'M',node_id},
		  offending_ie => {'C',offending_ie},
		  overload_control_information =>
		      {'O',
			  #{metric => {'M',metric},
			    oci_flags => {'C',oci_flags},
			    sequence_number => {'M',sequence_number},
			    timer => {'M',timer}}},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_build_identifier => {'O',tp_build_identifier},
		  tp_created_nat_binding =>
		      {'C',
			  #{bbf_nat_outside_address => {'C',bbf_nat_outside_address},
			    bbf_nat_port_block => {'C',bbf_nat_port_block}}},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}}},
	    session_modification_request =>
		#{create_far =>
		      {'C',
			  #{apply_action => {'M',apply_action},
			    far_id => {'M',far_id},
			    forwarding_parameters =>
				{'C',
				    #{destination_interface => {'M',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      header_enrichment => {'O',header_enrichment},
				      network_instance => {'O',network_instance},
				      redirect_information => {'C',redirect_information}}}}},
		  create_pdr =>
		      {'C',
			  #{activate_predefined_rules => {'C',activate_predefined_rules},
			    activation_time => {'O',activation_time},
			    deactivation_time => {'O',deactivation_time},
			    far_id => {'C',far_id},
			    pdi =>
				{'M',
				    #{application_id => {'O',application_id},
				      network_instance => {'O',network_instance},
				      sdf_filter => {'O',sdf_filter},
				      source_interface => {'M',source_interface},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      ue_ip_address => {'O',ue_ip_address}}},
			    pdr_id => {'M',pdr_id},
			    precedence => {'M',precedence},
			    qer_id => {'C',qer_id},
			    urr_id => {'C',urr_id}}},
		  create_qer =>
		      {'C',
			  #{dl_flow_level_marking => {'C',dl_flow_level_marking},
			    gate_status => {'M',gate_status},
			    gbr => {'C',gbr},
			    mbr => {'C',mbr},
			    qer_id => {'M',qer_id}}},
		  create_traffic_endpoint =>
		      {'C',
			  #{network_instance => {'O',network_instance},
			    traffic_endpoint_id => {'M',traffic_endpoint_id},
			    ue_ip_address => {'O',ue_ip_address}}},
		  create_urr =>
		      {'C',
			  #{additional_monitoring_time =>
				{'O',
				    #{event_quota => {'O',event_quota},
				      event_threshold => {'O',event_threshold},
				      monitoring_time => {'M',monitoring_time},
				      subsequent_time_quota => {'O',subsequent_time_quota},
				      subsequent_time_threshold =>
					  {'O',subsequent_time_threshold},
				      subsequent_volume_quota =>
					  {'O',subsequent_volume_quota},
				      subsequent_volume_threshold =>
					  {'O',subsequent_volume_threshold}}},
			    event_quota => {'C',event_quota},
			    event_threshold => {'C',event_threshold},
			    far_id => {'C',far_id},
			    inactivity_detection_time => {'C',inactivity_detection_time},
			    linked_urr_id => {'C',linked_urr_id},
			    measurement_information => {'C',measurement_information},
			    measurement_method => {'M',measurement_method},
			    measurement_period => {'C',measurement_period},
			    monitoring_time => {'O',monitoring_time},
			    number_of_reports => {'O',number_of_reports},
			    quota_holding_time => {'C',quota_holding_time},
			    reporting_triggers => {'M',reporting_triggers},
			    subsequent_event_quota => {'O',subsequent_event_quota},
			    subsequent_event_threshold => {'O',subsequent_event_threshold},
			    subsequent_time_quota => {'O',subsequent_time_quota},
			    subsequent_time_threshold => {'O',subsequent_time_threshold},
			    subsequent_volume_quota => {'O',subsequent_volume_quota},
			    subsequent_volume_threshold => {'O',subsequent_volume_threshold},
			    time_quota => {'C',time_quota},
			    time_threshold => {'C',time_threshold},
			    urr_id => {'M',urr_id},
			    volume_quota => {'C',volume_quota},
			    volume_threshold => {'C',volume_threshold}}},
		  f_seid => {'C',f_seid},
		  query_urr => {'C',#{urr_id => {'M',urr_id}}},
		  query_urr_reference => {'O',query_urr_reference},
		  remove_far => {'C',#{far_id => {'M',far_id}}},
		  remove_pdr => {'C',#{pdr_id => {'M',pdr_id}}},
		  remove_qer => {'C',#{qer_id => {'M',qer_id}}},
		  remove_traffic_endpoint =>
		      {'C',#{traffic_endpoint_id => {'M',traffic_endpoint_id}}},
		  remove_urr => {'C',#{urr_id => {'M',urr_id}}},
		  sxsmreq_flags => {'C',sxsmreq_flags},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  trace_information => {'O',trace_information},
		  update_far =>
		      {'C',
			  #{apply_action => {'C',apply_action},
			    far_id => {'M',far_id},
			    tp_ipfix_policy => {'O',tp_ipfix_policy},
			    update_forwarding_parameters =>
				{'C',
				    #{destination_interface => {'C',destination_interface},
				      forwarding_policy => {'C',forwarding_policy},
				      header_enrichment => {'C',header_enrichment},
				      network_instance => {'C',network_instance},
				      redirect_information => {'C',redirect_information}}}}},
		  update_pdr =>
		      {'C',
			  #{activate_predefined_rules => {'C',activate_predefined_rules},
			    activation_time => {'O',activation_time},
			    deactivate_predefined_rules => {'C',deactivate_predefined_rules},
			    deactivation_time => {'O',deactivation_time},
			    far_id => {'C',far_id},
			    pdi =>
				{'C',
				    #{application_id => {'O',application_id},
				      network_instance => {'O',network_instance},
				      sdf_filter => {'O',sdf_filter},
				      source_interface => {'M',source_interface},
				      traffic_endpoint_id => {'C',traffic_endpoint_id},
				      ue_ip_address => {'O',ue_ip_address}}},
			    pdr_id => {'M',pdr_id},
			    precedence => {'C',precedence},
			    qer_id => {'C',qer_id},
			    urr_id => {'C',urr_id}}},
		  update_qer =>
		      {'C',
			  #{dl_flow_level_marking => {'C',dl_flow_level_marking},
			    gate_status => {'C',gate_status},
			    gbr => {'C',gbr},
			    mbr => {'C',mbr},
			    qer_id => {'M',qer_id}}},
		  update_traffic_endpoint =>
		      {'C',
			  #{network_instance => {'O',network_instance},
			    traffic_endpoint_id => {'M',traffic_endpoint_id},
			    ue_ip_address => {'C',ue_ip_address}}},
		  update_urr =>
		      {'C',
			  #{additional_monitoring_time =>
				{'O',
				    #{event_quota => {'O',event_quota},
				      event_threshold => {'O',event_threshold},
				      monitoring_time => {'M',monitoring_time},
				      subsequent_time_quota => {'O',subsequent_time_quota},
				      subsequent_time_threshold =>
					  {'O',subsequent_time_threshold},
				      subsequent_volume_quota =>
					  {'O',subsequent_volume_quota},
				      subsequent_volume_threshold =>
					  {'O',subsequent_volume_threshold}}},
			    event_quota => {'C',event_quota},
			    event_threshold => {'C',event_threshold},
			    far_id => {'C',far_id},
			    inactivity_detection_time => {'C',inactivity_detection_time},
			    linked_urr_id => {'C',linked_urr_id},
			    measurement_method => {'C',measurement_method},
			    measurement_period => {'C',measurement_period},
			    monitoring_time => {'C',monitoring_time},
			    number_of_reports => {'O',number_of_reports},
			    quota_holding_time => {'C',quota_holding_time},
			    reporting_triggers => {'C',reporting_triggers},
			    subsequent_event_quota => {'O',subsequent_event_quota},
			    subsequent_event_threshold => {'O',subsequent_event_threshold},
			    subsequent_time_quota => {'C',subsequent_time_quota},
			    subsequent_time_threshold => {'C',subsequent_time_threshold},
			    subsequent_volume_quota => {'C',subsequent_volume_quota},
			    subsequent_volume_threshold => {'C',subsequent_volume_threshold},
			    time_quota => {'C',time_quota},
			    time_threshold => {'C',time_threshold},
			    urr_id => {'M',urr_id},
			    volume_quota => {'C',volume_quota},
			    volume_threshold => {'C',volume_threshold}}},
		  user_plane_inactivity_timer => {'C',user_plane_inactivity_timer}},
	    session_modification_response =>
		#{additional_usage_reports_information =>
		      {'C',additional_usage_reports_information},
		  failed_rule_id => {'C',failed_rule_id},
		  load_control_information => {'O',load_control_information},
		  offending_ie => {'C',offending_ie},
		  overload_control_information => {'O',overload_control_information},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_created_nat_binding =>
		      {'C',
			  #{bbf_nat_outside_address => {'C',bbf_nat_outside_address},
			    bbf_nat_port_block => {'C',bbf_nat_port_block}}},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}},
		  usage_report_smr =>
		      {'C',
			  #{duration_measurement => {'C',duration_measurement},
			    end_time => {'C',end_time},
			    query_urr_reference => {'C',query_urr_reference},
			    start_time => {'C',start_time},
			    time_of_first_packet => {'C',time_of_first_packet},
			    time_of_last_packet => {'C',time_of_last_packet},
			    tp_end_time => {'O',tp_end_time},
			    tp_now => {'O',tp_now},
			    tp_start_time => {'O',tp_start_time},
			    ur_seqn => {'M',ur_seqn},
			    urr_id => {'M',urr_id},
			    usage_information => {'C',usage_information},
			    usage_report_trigger => {'M',usage_report_trigger},
			    volume_measurement => {'C',volume_measurement}}}},
	    session_report_request =>
		#{additional_usage_reports_information =>
		      {'C',additional_usage_reports_information},
		  load_control_information => {'O',load_control_information},
		  overload_control_information => {'O',overload_control_information},
		  pfcpsrreq_flags => {'C',pfcpsrreq_flags},
		  report_type => {'M',report_type},
		  tp_trace_information =>
		      {'O',
			  #{tp_trace_parent => {'O',tp_trace_parent},
			    tp_trace_state => {'O',tp_trace_state}}},
		  usage_report_srr =>
		      {'C',
			  #{application_detection_information =>
				{'C',
				    #{application_id => {'M',application_id},
				      application_instance_id =>
					  {'C',application_instance_id},
				      flow_information => {'C',flow_information},
				      pdr_id => {'O',pdr_id}}},
			    duration_measurement => {'C',duration_measurement},
			    end_time => {'C',end_time},
			    event_time_stamp => {'C',event_time_stamp},
			    network_instance => {'C',network_instance},
			    query_urr_reference => {'C',query_urr_reference},
			    start_time => {'C',start_time},
			    time_of_first_packet => {'C',time_of_first_packet},
			    time_of_last_packet => {'C',time_of_last_packet},
			    tp_end_time => {'O',tp_end_time},
			    tp_now => {'O',tp_now},
			    tp_start_time => {'O',tp_start_time},
			    ue_ip_address => {'C',ue_ip_address},
			    ur_seqn => {'M',ur_seqn},
			    urr_id => {'M',urr_id},
			    usage_information => {'C',usage_information},
			    usage_report_trigger => {'M',usage_report_trigger},
			    volume_measurement => {'C',volume_measurement}}}},
	    session_report_response =>
		#{offending_ie => {'C',offending_ie},
		  pfcp_cause => {'M',pfcp_cause},
		  tp_error_report =>
		      {'O',
			  #{tp_error_message => {'M',tp_error_message},
			    tp_file_name => {'O',tp_file_name},
			    tp_line_number => {'O',tp_line_number}}}},
	    version_not_supported_response => #{}}}.
