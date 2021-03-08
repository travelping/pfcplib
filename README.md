pfcplib
=======
[![Hex.pm Version][hexpm version]][hexpm]
[![Hex.pm Downloads][hexpm downloads]][hexpm]
[![Build Status][gh badge]][gh]
[![Coverage Status][coveralls badge]][coveralls]
[![Erlang Versions][erlang version badge]][gh]

Erlang library for encoding and decoding Packet Forwarding Control Protocol (PFCP) frames.

BUILDING
--------

Using rebar:

    # rebar3 compile

Build a PCAP file with random PFCP Messages
-------------------------------------------

This procedure will generate a a file called pfcp.pcap that is filled
with randomly generated PFCP packets. The overall structure of the
information elements in the PFCP will match the specification, however
the structure of grouped IEs, and requirements for mandatory IEs will
not be meet.

    # rebar3 as pcap do compile, shell
    > c("test/property_test/pfcplib_prop.erl").
    > pfcplib_prop:gen_pcap(2000).
    > q().

<!-- Badges -->
[hexpm]: https://hex.pm/packages/pfcplib
[hexpm version]: https://img.shields.io/hexpm/v/pfcplib.svg?style=flat-square
[hexpm downloads]: https://img.shields.io/hexpm/dt/pfcplib.svg?style=flat-square
[gh]: https://github.com/travelping/pfcplib/actions/workflows/main.yml
[gh badge]: https://img.shields.io/github/workflow/status/travelping/pfcplib/CI?style=flat-square
[coveralls]: https://coveralls.io/github/travelping/pfcplib
[coveralls badge]: https://img.shields.io/coveralls/travelping/pfcplib/master.svg?style=flat-square
[erlang version badge]: https://img.shields.io/badge/erlang-20.1%20to%2023.2-blue.svg?style=flat-square
