pfcplib
=======

Erlang library for encoding and decoding Packet Forwarding Control Protocol (PFCP) frames.

Version 2.3.0 - 26 Sep 2022
---------------------------

**Features** :rocket:
* [#32](https://github.com/travelping/pfcplib/pull/32) add Travelping VSAs to transport tracing information

**[Compare 2.2.0...2.3.0](https://github.com/travelping/pfcplib/compare/2.2.0...2.3.0)**

Version 2.2.0 - 5 Apr 2022
--------------------------

**Features** :rocket:
* [#31](https://github.com/travelping/pfcplib/pull/31) Adding TP IPFIX Policy IE

**[Compare 2.1.2...2.2.0](https://github.com/travelping/pfcplib/compare/2.1.2...2.2.0)**

Version 2.1.2 - 10 November 2021
---------------------------

**Refactorings** :fire:
* [#29](https://github.com/travelping/pfcplib/pull/29) Remove all `dialyzer` warning
____
**Special thanks to our contributors**

* [@jbdamiano](https://github.com/jbdamiano) [#29](https://github.com/travelping/pfcplib/pull/29) Remove all `dialyzer` warning

**[Compare 2.1.1...2.1.2](https://github.com/travelping/pfcplib/compare/2.1.1...2.1.2)**

Version 2.1.1 - 24 June 2021
---------------------------

**Bugfixes** :bug:
* [#27](https://github.com/travelping/pfcplib/pull/27) fix encoding of User ID

**[Compare 2.1.0...2.1.1](https://github.com/travelping/pfcplib/compare/2.1.0...2.1.1)**

Version 2.1.0 - 3 June 2021
---------------------------

**Features** :rocket:
* [#24](https://github.com/travelping/pfcplib/pull/24) Normalize `FQDNs` by lowercasing them in all `IEs`

**[Compare 2.0.1...2.1.0](https://github.com/travelping/pfcplib/compare/2.0.1...2.1.0)**

Version 2.0.1 - 19 May 2021
---------------------------

**Features** :rocket:
* [#22](https://github.com/travelping/pfcplib/pull/22) `BBF TR 459`

**[Compare 2.0.0...2.0.1](https://github.com/travelping/pfcplib/compare/2.0.0...2.0.1)**

Version 2.0.0 - 6 Mar 2021
---------------------------

**Dependencies** :gear:
* [#2](https://github.com/travelping/pfcplib/pull/3) upgrade dependencies and drop old rebar compatibility stuff and add PFCP message validator

**Improvements** :bulb:
* [32f764a](https://github.com/travelping/pfcplib/commit/32f764a91d52724ff4d2ff52e91688cc28c63770) add all information elemens from Rel. `15.2`
* [99ee214](https://github.com/travelping/pfcplib/commit/99ee214506f6dd35bdda4eec911d17836ad3c99b) add helper to format IEs for lager
* [312ebca](https://github.com/travelping/pfcplib/commit/312ebca66835dc28f2821585cdd8cacc8914e29e) add `io_lib` pretty print helper
* [14a0c73](https://github.com/travelping/pfcplib/commit/14a0c734a320bee8c55764b07adef3445d709394) export `ies_to_map/1`

**Features** :rocket:
* [#18](https://github.com/travelping/pfcplib/pull/18) Replace `erlando` to `cut` `1.0.3`
* [#16](https://github.com/travelping/pfcplib/pull/16) Add `hex` to GH action
* [#15](https://github.com/travelping/pfcplib/pull/15) Start use `SemVer`
* [#14](https://github.com/travelping/pfcplib/pull/14) Update GH actions
* [#13](https://github.com/travelping/pfcplib/pull/13) update to rel. `16.6.0`
* [#12](https://github.com/travelping/pfcplib/pull/12) Add `.github`
* [#10](https://github.com/travelping/pfcplib/pull/10) update to rel. `16.3.1`

**Bugfixes** :bug:
* [#9](https://github.com/travelping/pfcplib/pull/9) fix en/decode for DL Buffering Suggested Packet Count
* [#7](https://github.com/travelping/pfcplib/pull/7) fix information loss in property test
* [#6](https://github.com/travelping/pfcplib/pull/6) Fix PFD Contents and Query URR Reference IEs
* [ec9d724](https://github.com/travelping/pfcplib/commit/ec9d7242dd4a180486b5ec12269e242b3489d1fd) fix specification for Travis-CI builds

**[Compare 1.0.0...2.0.0](https://github.com/travelping/pfcplib/compare/1.0.0...2.0.0)**

Version 1.0.0 - 01 Aug 2018
---------------------------

* Initial release
