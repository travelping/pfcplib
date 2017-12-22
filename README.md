pfcplib
=======
[![Build Status][travis badge]][travis]
[![Coverage Status][coveralls badge]][coveralls]
[![Erlang Versions][erlang version badge]][travis]

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
[travis]: https://travis-ci.org/travelping/pfcplib
[travis badge]: https://img.shields.io/travis/travelping/pfcplib/master.svg?style=flat-square
[coveralls]: https://coveralls.io/github/travelping/pfcplib
[coveralls badge]: https://img.shields.io/coveralls/travelping/pfcplib/master.svg?style=flat-square
[erlang version badge]: https://img.shields.io/badge/erlang-R20.0%20to%2020.1-blue.svg?style=flat-square
