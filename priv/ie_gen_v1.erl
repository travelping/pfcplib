#!/usr/bin/env escript
%% -*- erlang -*-
%%! -smp enable

-mode(compile).

raw_ies() ->
    [
     {1, "Create PDR",
      [{"Group", 0, {type, v1_grouped}}]},
     {2, "PDI",
      [{"Group", 0, {type, v1_grouped}}]},
     {3, "Create FAR",
      [{"Group", 0, {type, v1_grouped}}]},
     {4, "Forwarding Parameters",
      [{"Group", 0, {type, v1_grouped}}]},
     {5, "Duplicating Parameters",
      [{"Group", 0, {type, v1_grouped}}]},
     {6, "Create URR",
      [{"Group", 0, {type, v1_grouped}}]},
     {7, "Create QER",
      [{"Group", 0, {type, v1_grouped}}]},
     {8, "Created PDR",
      [{"Group", 0, {type, v1_grouped}}]},
     {9, "Update PDR",
      [{"Group", 0, {type, v1_grouped}}]},
     {10, "Update FAR",
      [{"Group", 0, {type, v1_grouped}}]},
     {11, "Update Forwarding Parameters",
      [{"Group", 0, {type, v1_grouped}}]},
     {12, "Update BAR Response",
      [{"Group", 0, {type, v1_grouped}}]},
     {13, "Update URR",
      [{"Group", 0, {type, v1_grouped}}]},
     {14, "Update QER",
      [{"Group", 0, {type, v1_grouped}}]},
     {15, "Remove PDR",
      [{"Group", 0, {type, v1_grouped}}]},
     {16, "Remove FAR",
      [{"Group", 0, {type, v1_grouped}}]},
     {17, "Remove URR",
      [{"Group", 0, {type, v1_grouped}}]},
     {18, "Remove QER",
      [{"Group", 0, {type, v1_grouped}}]},
     {19, "PFCP Cause",
      [{"Cause", 8, {enum, [{0 , "Reserved"},
			    {1,  "Request accepted"},
			    {64, "Request rejected"},
			    {65, "Session context not found"},
			    {66, "Mandatory IE missing"},
			    {67, "Conditional IE missing"},
			    {68, "Invalid length"},
			    {69, "Mandatory IE incorrect"},
			    {70, "Invalid Forwarding Policy"},
			    {71, "Invalid F-TEID allocation option"},
			    {72, "No established Sx Association"},
			    {73, "Rule creation/modification Failure"},
			    {74, "PFCP entity in congestion"},
			    {75, "No resources available"},
			    {76, "Service not supported"},
			    {77, "System failure"}]}}]},
     {20, "Source Interface",
      [{'_', 4},
       {"Interface", 4, {enum, [{0, "Access"},
				{1, "Core"},
				{2, "SGi-LAN"},
				{3, "CP-function"}]}},
       {'_', 0}]},
     {21, "F-TEID", f_teid},
     {22, "Network Instance",
      [{"Instance", 0, binary}]},
     {23, "SDF Filter", sdf_filter},
     {24, "Application ID",
      [{"Id", 0, binary}]},
     {25, "Gate Status",
      [{'_', 4},
       {"UL", 2, {enum, [{0, "OPEN"},
			 {1, "CLOSED"}]}},
       {"DL", 2, {enum, [{0, "OPEN"},
			 {1, "CLOSED"}]}},
       {'_', 0}]},
     {26, "MBR",
      [{"UL", 40, integer},
       {"DL", 40, integer},
       {'_', 0}]},
     {27, "GBR",
      [{"UL", 40, integer},
       {"DL", 40, integer},
       {'_', 0}]},
     {28, "QER Correlation ID",
      [{"Id", 32, integer},
       {'_', 0}]},
     {29, "Precedence",
      [{"Precedence", 32, integer},
       {'_', 0}]},
     {30, "Transport Level Marking",
      [{"TOS", 16, integer},
       {'_', 0}]},
     {31, "Volume Threshold", volume_threshold},
     {32, "Time Threshold",
      [{"Threshold", 32, integer},
       {'_', 0}]},
     {33, "Monitoring Time",
      [{"Time", 32, integer},
       {'_', 0}]},
     {34, "Subsequent Volume Threshold", volume_threshold},
     {35, "Subsequent Time Threshold",
      [{"Threshold", 32, integer},
       {'_', 0}]},
     {36, "Inactivity Detection Time",
      [{"Time", 32, integer},
       {'_', 0}]},
     {37, "Reporting Triggers",
      [{"Linked Usage Reporting", 1, integer},
       {"Dropped DL Traffic Threshold", 1, integer},
       {"Stop of Traffic", 1, integer},
       {"Start of Traffic", 1, integer},
       {"Quota Holding Time", 1, integer},
       {"Time Threshold", 1, integer},
       {"Volume Threshold", 1, integer},
       {"Periodic Reporting", 1, integer},
       {'_', 4},
       {"MAC Addresses Reporting", 1, integer},
       {"Envelope Closure", 1, integer},
       {"Time Quota", 1, integer},
       {"Volume Quota", 1, integer},
       {'_', 0}]},
     {38, "Redirect Information",
      [{'_', 4},
       {"Type", 4, {enum, [{0, "IPv4"},
			   {1, "IPv6"},
			   {2, "URL"},
			   {3, "SIP URI"}]}},
       {"Address", 16, length_binary},
       {'_', 0}]},
     {39, "Report Type",
      [{'_', 4},
       {"UPIR", 1, integer},
       {"ERIR", 1, integer},
       {"USAR", 1, integer},
       {"DLDR", 1, integer},
       {'_', 0}]},
     {40, "Offending IE",
      [{"Type", 16, integer}]},
     {41, "Forwarding Policy",
      [{"Policy Identifier", 8, length_binary},
       {'_', 0}]},
     {42, "Destination Interface",
      [{'_', 4},
       {"Interface", 4, {enum, [{0, "Access"},
				{1, "Core"},
				{2, "SGi-LAN"},
				{3, "CP-function"},
				{4, "LI-function"}]}},
       {'_', 0}]},
     {43, "UP Function Features",
      [{"TREU", 1, integer},
       {"HEEU", 1, integer},
       {"PFDM", 1, integer},
       {"FTUP", 1, integer},
       {"TRST", 1, integer},
       {"DLBD", 1, integer},
       {"DDND", 1, integer},
       {"BUCP", 1, integer},
       {'_', 4},
       {"QUOAC", 1, integer},
       {"UDBC", 1, integer},
       {"PDIU", 1, integer},
       {"EMPU", 1, integer},
       {'_', 0}]},
     {44, "Apply Action",
      [{'_', 3},
       {"DUPL", 1, integer},
       {"NOCP", 1, integer},
       {"BUFF", 1, integer},
       {"FORW", 1, integer},
       {"DROP", 1, integer},
       {'_', 0}]},
     {45, "Downlink Data Service Information", paging_policy_indication},
     {46, "Downlink Data Notification Delay",
      [{"Delay", 8, integer},
       {'_', 0}]},
     {47, "DL Buffering Duration",
      [{"DL Buffer Unit", 3,  {enum, [{0 , "2 seconds"},
				      {1 , "1 minute"},
				      {2 , "10 minutes"},
				      {3 , "1 hour"},
				      {4 , "10 hours"},
				      {7 , "infinite"}]}},
       {"DL Buffer Value", 5, integer},
       {'_', 0}]},
     {48, "DL Buffering Suggested Packet Count", dl_buffering_suggested_packet_count},
     {49, "SxSMReq-Flags",
      [{'_', 5},
       {"QAURR", 1, integer},
       {"SNDEM", 1, integer},
       {"DROBU", 1, integer},
       {'_', 0}]},
     {50, "SxSRRsp-Flags",
      [{'_', 7},
       {"DROBU", 1, integer},
       {'_', 0}]},
     {51, "Load Control Information",
      [{"Group", 0, {type, v1_grouped}}]},
     {52, "Sequence Number",
      [{"Number", 32, integer}]},
     {53, "Metric",
      [{"Metric", 8, integer}]},
     {54, "Overload Control Information",
      [{"Group", 0, {type, v1_grouped}}]},
     {55, "Timer",
      [{"Timer Unit", 3,  {enum, [{0 , "2 seconds"},
				  {1 , "1 minute"},
				  {2 , "10 minutes"},
				  {3 , "1 hour"},
				  {4 , "10 hours"},
				  {7 , "infinite"}]}},
       {"Timer Value", 5, integer},
       {'_', 0}]},
      {56, "PDR ID",
       [{"Id", 16, integer},
	{'_', 0}]},
     {57, "F-SEID", f_seid},
     {58, "Application ID PFDs",
      [{"Group", 0, {type, v1_grouped}}]},
     {59, "PFD context",
      [{"Group", 0, {type, v1_grouped}}]},
     {60, "Node ID", node_id},
     {61, "PFD contents", pfd_contents},
     {62, "Measurement Method",
      [{'_', 5},
       {"EVENT", 1, integer},
       {"VOLUM", 1, integer},
       {"DURAT", 1, integer},
       {'_', 0}]},
     {63, "Usage Report Trigger",
      [{"IMMER", 1, integer},
       {"DROTH", 1, integer},
       {"STOPT", 1, integer},
       {"START", 1, integer},
       {"QUHTI", 1, integer},
       {"TIMTH", 1, integer},
       {"VOLTH", 1, integer},
       {"PERIO", 1, integer},
       {'_', 1},
       {"MACAR", 1, integer},
       {"ENVCL", 1, integer},
       {"MONIT", 1, integer},
       {"TERMR", 1, integer},
       {"LIUSA", 1, integer},
       {"TIMQU", 1, integer},
       {"VOLQU", 1, integer},
       {'_', 0}]},
     {64, "Measurement Period",
      [{"Period", 32, integer},
       {'_', 0}]},
     {65, "FQ-CSID", fq_csid},
     {66, "Volume Measurement", volume_threshold},
     {67, "Duration Measurement",
      [{"Duration", 32, integer},
       {'_', 0}]},
     {68, "Application Detection Information",
      [{"Group", 0, {type, v1_grouped}}]},
     {69, "Time of First Packet",
      [{"Time", 32, integer},
       {'_', 0}]},
     {70, "Time of Last Packet",
      [{"Time", 32, integer},
       {'_', 0}]},
     {71, "Quota Holding Time",
      [{"Time", 32, integer},
       {'_', 0}]},
     {72, "Dropped DL Traffic Threshold", dropped_dl_traffic_threshold},
     {73, "Volume Quota", volume_threshold},
     {74, "Time Quota",
      [{"Quota", 32, integer},
       {'_', 0}]},
     {75, "Start Time",
      [{"Time", 32, integer},
       {'_', 0}]},
     {76, "End Time",
      [{"Time", 32, integer},
       {'_', 0}]},
     {77, "Query URR",
      [{"Group", 0, {type, v1_grouped}}]},
     {78, "Usage Report SMR",
      [{"Group", 0, {type, v1_grouped}}]},
     {79, "Usage Report SDR",
      [{"Group", 0, {type, v1_grouped}}]},
     {80, "Usage Report SRR",
      [{"Group", 0, {type, v1_grouped}}]},
     {81, "URR ID",
      [{"Id", 32, integer},
       {'_', 0}]},
     {82, "Linked URR ID",
      [{"Id", 32, integer},
       {'_', 0}]},
     {83, "Downlink Data Report",
      [{"Group", 0, {type, v1_grouped}}]},
     {84, "Outer Header Creation", outer_header_creation},
     {85, "Create BAR",
      [{"Group", 0, {type, v1_grouped}}]},
     {86, "Update BAR Request",
      [{"Group", 0, {type, v1_grouped}}]},
     {87, "Remove BAR",
      [{"Group", 0, {type, v1_grouped}}]},
     {88, "BAR ID",
      [{"Id", 8, integer},
       {'_', 0}]},
     {89, "CP Function Features",
      [{'_', 6},
       {"OVRL", 1, integer},
       {"LOAD", 1, integer},
       {'_', 0}]},
     {90, "Usage Information",
      [{'_', 4},
       {"UBE", 1, integer},
       {"UAE", 1, integer},
       {"AFT", 1, integer},
       {"BEF", 1, integer},
       {'_', 0}]},
     {91, "Application Instance ID",
      [{"Id", 0, binary}]},
     {92, "Flow Information",
      [{'_', 4},
       {"Direction", 4,  {enum, [{0, "Unspecified"},
				 {1, "Downlink"},
				 {2, "Uplink"},
				 {3, "Bidirectional"}]}},
       {"Flow", 16, length_binary},
       {'_', 0}]},
     {93, "UE IP Address", ue_ip_address},
     {94, "Packet Rate", packet_rate},
     {95, "Outer Header Removal",
      [{"Header", 8, {enum, [{0, "GTP-U/UDP/IPv4"},
			     {1, "GTP-U/UDP/IPv6"},
			     {2, "UDP/IPv4"},
			     {3, "UDP/IPv6"}]}},
       {'_', 0}]},
     {96, "Recovery Time Stamp",
      [{"Time", 32, integer},
       {'_', 0}]},
     {97, "DL Flow Level Marking", dl_flow_level_marking},
     {98, "Header Enrichment",
      [{'_', 4},
       {"Header Type", 4,  {enum, [{0, "HTTP"}]}},
       {"Name", 8, length_binary},
       {"Value", 8, length_binary},
       {'_', 0}]},
     {99, "Error Indication Report",
      [{"Group", 0, {type, v1_grouped}}]},
     {100, "Measurement Information",
      [{'_', 5},
       {"RADI", 1, integer},
       {"INAM", 1, integer},
       {"MBQE", 1, integer},
       {'_', 0}]},
     {101, "Node Report Type",
      [{'_', 7},
       {"UPFR", 1, integer},
       {'_', 0}]},
     {102, "User Plane Path Failure Report",
      [{"Group", 0, {type, v1_grouped}}]},
     {103, "Remote GTP-U Peer", remote_peer},
     {104, "UR-SEQN",
      [{"NUmber", 32, integer}]},
     {105, "Update Duplicating Parameters",
      [{"Group", 0, {type, v1_grouped}}]},
     {106, "Activate Predefined Rules",
      [{"Name", 0, binary}]},
     {107, "Deactivate Predefined Rules",
      [{"Name", 0, binary}]},
     {108, "FAR ID",
      [{"Id", 32, integer},
       {'_', 0}]},
     {109, "QER ID",
      [{"Id", 32, integer},
       {'_', 0}]},
     {110, "OCI Flags",
      [{'_', 7},
       {"AOCI", 1, integer},
       {'_', 0}]},
     {111, "Sx Association Release Request",
      [{'_', 7},
       {"SARR", 1, integer},
       {'_', 0}]},
     {112, "Graceful Release Period",
      [{"Release Timer Unit", 3,  {enum, [{0 , "2 seconds"},
					  {1 , "1 minute"},
					  {2 , "10 minutes"},
					  {3 , "1 hour"},
					  {4 , "10 hours"},
					  {7 , "infinite"}]}},
       {"Release Timer Value", 5, integer},
       {'_', 0}]},
     {113, "PDN Type",
      [{'_', 5},
       {"PDN Type", 3,  {enum, [{1, "IPv4"},
				{2, "IPv6"},
				{3, "IPv4v6"},
				{4, "Non-IP"}]}},
       {'_', 0}]},
     {114, "Failed Rule ID", failed_rule_id},
     {115, "Time Quota Mechanism",
      [{'_', 6},
       {"Base Time Interval Type", 2,  {enum, [{0 , "CTP"},
					       {1 , "DTP"}]}},
       {"Interval", 32, integer},
       {'_', 0}]},
     {116, "User Plane IP Resource Information", user_plane_ip_resource_information},
     {117, "User Plane Inactivity Timer",
      [{"Timer", 32, integer},
       {'_', 0}]},
     {118, "Aggregated URRs",
      [{"Group", 0, {type, v1_grouped}}]},
     {119, "Multiplier",
      [{"Digits", 64, 'signed-integer'},
       {"Exponent", 32, 'signed-integer'}]},
     {120, "Aggregated URR ID",
      [{"Id", 32, integer}]},
     {121, "Subsequent Volume Quota", volume_threshold},
     {122, "Subsequent Time Quota",
      [{"Quota", 32, integer},
       {'_', 0}]},
     {123, "RQI",
      [{'_', 7},
       {"RQI", 1, integer},
       {'_', 0}]},
     {124, "QFI",
      [{"QFI", 8, integer},
       {'_', 0}]},
     {125, "Query URR Reference",
      [{"Reference", 32, integer},
       {'_', 0}]},
     {126, "Additional Usage Reports Information",
      [{"AURI", 1, integer},
       {"Reports", 15, integer},
       {'_', 0}]},
     {127, "Create Traffic Endpoint",
      [{"Group", 0, {type, v1_grouped}}]},
     {128, "Created Traffic Endpoint",
      [{"Group", 0, {type, v1_grouped}}]},
     {129, "Update Traffic Endpoint",
      [{"Group", 0, {type, v1_grouped}}]},
     {130, "Remove Traffic Endpoint",
      [{"Group", 0, {type, v1_grouped}}]},
     {131, "Traffic Endpoint ID",
      [{"Id", 8, integer},
       {'_', 0}]},
     {132, "Ethernet Packet Filter",
      [{"Group", 0, {type, v1_grouped}}]},
     {133, "MAC address", mac_address},
     {134, "C-TAG", vlan_tag},
     {135, "S-TAG", vlan_tag},
     {136, "Ethertype",
      [{"Type", 16, integer},
       {'_', 0}]},
     {137, "Proxying",
      [{'_', 6},
       {"INS", 1, integer},
       {"ARP", 1, integer},
       {'_', 0}]},
     {138, "Ethernet Filter ID",
      [{"Id", 32, integer},
       {'_', 0}]},
     {139, "Ethernet Filter Properties",
      [{'_', 7},
       {"BIDE", 1, integer},
       {'_', 0}]},
     {140, "Suggested Buffering Packets Count",
      [{"Count", 8, integer},
       {'_', 0}]},
     {141, "User ID", user_id},
     {142, "Ethernet PDU Session Information",
      [{'_', 7},
       {"ETHI", 1, integer},
       {'_', 0}]},
     {143, "Ethernet Traffic Information",
      [{"Group", 0, {type, v1_grouped}}]},
     {144, "MAC Addresses Detected",
      [{"MACs", 8, {array, 6}}]},
     {145, "MAC Addresses Removed",
      [{"MACs", 8, {array, 6}}]},
     {146, "Ethernet Inactivity Timer",
      [{"Timer", 32, integer},
       {'_', 0}]},
     {{18681, 1}, "TP Packet Measurement", volume_threshold},
     {{18681, 2}, "TP Build Identifier",
      [{"Id", 0, binary}]},
     {{18681, 3}, "TP Now",
      [{"Now", 64, float},
       {'_', 0}]},
     {{18681, 4}, "TP Start Time",
      [{"Start", 64, float},
       {'_', 0}]},
     {{18681, 5}, "TP Stop Time",
      [{"Stop", 64, float},
       {'_', 0}]}
    ].

msgs() ->
    [{1, "Heartbeat Request",				{'X', 'X', 'X', 'X'},
      [{"Recovery Time Stamp",			   'M', {'X', 'X', 'X', 'X'}}]},
     {2, "Heartbeat Response",				{'X', 'X', 'X', 'X'},
      [{"Recovery Time Stamp",			   'M', {'X', 'X', 'X', 'X'}}]},
     {3, "PFD Management Request",			{'-', 'X', 'X', 'X'},
      [{"Application ID's PFDs",		   'M', {'-', 'X', 'X', 'X'},
	[{"Application ID",			   'M', {'-', 'X', 'X', 'X'}},
	 {"PFD context",			   'M', {'-', 'X', 'X', 'X'},
	  [{"PFD Contents",			   'M', {'-', 'X', 'X', 'X'}}]}
	]}
      ]},
     {4, "PFD Management Response",			{'-', 'X', 'X', 'X'},
      [{"PFCP Cause",				   'M', {'-', 'X', 'X', 'X'}},
       {"Offending IE",				   'M', {'-', 'X', 'X', 'X'}}]},
     {5, "Association Setup Request",			{'X', 'X', 'X', 'X'},
      [{"Node ID",				   'M', {'X', 'X', 'X', 'X'}},
       {"Recovery Time Stamp",			   'M', {'X', 'X', 'X', 'X'}},
       {"UP Function Features",			   'C', {'X', 'X', 'X', 'X'}},
       {"CP Function Features",			   'C', {'X', 'X', 'X', 'X'}},
       {"User Plane IP Resource Information",	   'O', {'X', 'X', 'X', 'X'}},
       {"TP Build Identifier",			   'O', {'X', 'X', 'X', 'X'}}]},
     {6, "Association Setup Response",			{'X', 'X', 'X', 'X'},
      [{"Node ID",				   'M', {'X', 'X', 'X', 'X'}},
       {"PFCP Cause",				   'M', {'X', 'X', 'X', 'X'}},
       {"Recovery Time Stamp",			   'M', {'X', 'X', 'X', 'X'}},
       {"UP Function Features",			   'C', {'X', 'X', 'X', 'X'}},
       {"CP Function Features",			   'C', {'X', 'X', 'X', 'X'}},
       {"User Plane IP Resource Information",	   'O', {'X', 'X', 'X', 'X'}},
       {"TP Build Identifier",			   'O', {'X', 'X', 'X', 'X'}}]},
     {7, "Association Update Request",			{'X', 'X', 'X', 'X'},
      [{"Node ID",				   'M', {'X', 'X', 'X', 'X'}},
       {"UP Function Features",			   'O', {'X', 'X', 'X', 'X'}},
       {"CP Function Features",			   'O', {'X', 'X', 'X', 'X'}},
       {"PFCP Association Release Request",	   'O', {'X', 'X', 'X', 'X'}},
       {"Graceful Release Period",		   'O', {'X', 'X', 'X', 'X'}},
       {"User Plane IP Resource Information",	   'O', {'X', 'X', 'X', 'X'}}]},
     {8, "Association Update Response",			{'X', 'X', 'X', 'X'},
      [{"Node ID",				   'M', {'X', 'X', 'X', 'X'}},
       {"PFCP Cause",				   'M', {'X', 'X', 'X', 'X'}},
       {"UP Function Features",			   'O', {'X', 'X', 'X', 'X'}},
       {"CP Function Features",			   'O', {'X', 'X', 'X', 'X'}},
       {"TP Build Identifier",			   'O', {'X', 'X', 'X', 'X'}}]},
     {9, "Association Release Request",			{'X', 'X', 'X', 'X'},
      [{"Node ID",				   'M', {'X', 'X', 'X', 'X'}},
       {"TP Build Identifier",			   'O', {'X', 'X', 'X', 'X'}}]},
     {10, "Association Release Response",		{'X', 'X', 'X', 'X'},
      [{"Node ID",				   'M', {'X', 'X', 'X', 'X'}},
       {"PFCP Cause",				   'M', {'X', 'X', 'X', 'X'}},
       {"TP Build Identifier",			   'O', {'X', 'X', 'X', 'X'}}]},
     {11, "Version Not Supported Response",		{'X', 'X', 'X', 'X'},
      []},
     {12, "Node Report Request",			{'X', 'X', 'X', 'X'},
      [{"Node ID",				   'M', {'X', 'X', 'X', 'X'}},
       {"Node Report Type",			   'M', {'X', 'X', 'X', 'X'}},
       {"User Plane Path Failure Report",	   'C', {'X', 'X', '-', 'X'},
	[{"Remote GTP-U Peer",			   'M', {'X', 'X', '-', 'X'}}]},
       {"TP Build Identifier",			   'O', {'X', 'X', 'X', 'X'}}]},
     {13, "Node Report Response",			{'X', 'X', 'X', 'X'},
      [{"Node ID",				   'M', {'X', 'X', 'X', 'X'}},
       {"PFCP Cause",				   'M', {'X', 'X', 'X', 'X'}},
       {"Offending IE",				   'C', {'X', 'X', 'X', 'X'}},
       {"TP Build Identifier",			   'O', {'X', 'X', 'X', 'X'}}]},
     {14, "Session Set Deletion Request",		{'X', 'X', '-', ' '},
      [{"Node ID",				   'M', {'X', 'X', '-', ' '}},
       {"FQ-CSID",				   'C', {'X', 'X', '-', ' '}},
       {"TP Build Identifier",			   'O', {'X', 'X', 'X', 'X'}}]},
     {15, "Session Set Deletion Response",		{'X', 'X', '-', ' '},
      [{"Node ID",				   'M', {'X', 'X', '-', ' '}},
       {"PFCP Cause",				   'M', {'X', 'X', '-', ' '}},
       {"Offending IE",				   'C', {'X', 'X', '-', ' '}},
       {"TP Build Identifier",			   'O', {'X', 'X', 'X', 'X'}}]},
     {50, "Session Establishment Request",		{'X', 'X', 'X', 'X'},
      [{"Node ID",				   'M', {'X', 'X', 'X', 'X'}},
       {"F-SEID",				   'M', {'X', 'X', 'X', 'X'}},
       {"Create PDR",				   'M', {'X', 'X', 'X', 'X'},
	[{"PDR ID",				   'M', {'X', 'X', 'X', 'X'}},
	 {"Precedence",				   'M', {'-', 'X', 'X', 'X'}},
	 {"PDI",				   'M', {'X', 'X', 'X', 'X'},
	  [{"Source Interface",			   'M', {'X', 'X', 'X', 'X'}},
	   {"F-TEID",				   'O', {'X', 'X', '-', 'X'}},
	   {"Network Instance",			   'O', {'X', 'X', 'X', 'X'}},
	   {"UE IP address",			   'O', {'-', 'X', 'X', 'X'}},
	   {"Traffic Endpoint ID",		   'C', {'X', 'X', 'X', 'X'}},
	   {"SDF Filter",			   'O', {'-', 'X', 'X', 'X'}},
	   {"Application ID",			   'O', {'-', 'X', 'X', 'X'}},
	   {"Ethernet PDU Session Information",	   'O', {'-', '-', '-', 'X'}},
	   {"Ethernet Packet Filter",		   'O', {'-', '-', '-', 'X'},
	    [{"Ethernet Filter ID",		   'C', {'-', '-', '-', 'X'}},
	     {"Ethernet Filter Properties",	   'C', {'-', '-', '-', 'X'}},
	     {"MAC address",			   'O', {'-', '-', '-', 'X'}},
	     {"Ethertype",			   'O', {'-', '-', '-', 'X'}},
	     {"C-TAG",				   'O', {'-', '-', '-', 'X'}},
	     {"S-TAG",				   'O', {'-', '-', '-', 'X'}},
	     {"SDF Filter",			   'O', {'-', '-', '-', 'X'}}]},
	   {"QFI",				   'O', {'-', '-', '-', 'X'}},
	   {"Framed-Route",			   'O', {'-', 'X', '-', 'X'}},
	   {"Framed-Routing",			   'O', {'-', 'X', '-', 'X'}},
	   {"Framed-IPv6-Route",		   'O', {'-', 'X', '-', 'X'}}]},
	 {"Outer Header Removal",		   'C', {'X', 'X', '-', 'X'}},
	 {"FAR ID",				   'C', {'X', 'X', 'X', 'X'}},
	 {"URR ID",				   'C', {'X', 'X', 'X', 'X'}},
	 {"QER ID",				   'C', {'-', 'X', 'X', 'X'}},
	 {"Activate Predefined Rules",		   'C', {'-', 'X', 'X', 'X'}}]},
       {"Create FAR",				   'M', {'X', 'X', 'X', 'X'},
	[{"FAR ID",				   'M', {'X', 'X', 'X', 'X'}},
	 {"Apply Action",			   'M', {'X', 'X', 'X', 'X'}},
	 {"Forwarding Parameters",		   'C', {'X', 'X', 'X', 'X'},
	  [{"Destination Interface",		   'M', {'X', 'X', 'X', 'X'}},
	   {"Network Instance",			   'O', {'X', 'X', 'X', 'X'}},
	   {"Redirect Information",		   'C', {'-', 'X', 'X', 'X'}},
	   {"Outer Header Creation",		   'C', {'X', 'X', '-', 'X'}},
	   {"Transport Level Marking",		   'C', {'X', 'X', '-', 'X'}},
	   {"Forwarding Policy",		   'C', {'-', 'X', 'X', 'X'}},
	   {"Header Enrichment",		   'O', {'-', 'X', 'X', 'X'}},
	   {"Traffic Endpoint ID",		   'C', {'X', 'X', '-', 'X'}},
	   {"Proxying",				   'C', {'-', '-', '-', 'X'}}]},
	 {"Duplicating Parameters",		   'C', {'X', 'X', '-', 'X'},
	  [{"Destination Interface",		   'M', {'X', 'X', '-', 'X'}},
	   {"Outer Header Creation",		   'C', {'X', 'X', '-', 'X'}},
	   {"Transport Level Marking",		   'C', {'X', 'X', '-', 'X'}},
	   {"Forwarding Policy",		   'C', {'X', 'X', '-', 'X'}}]},
	 {"BAR ID",				   'O', {'X', '-', '-', 'X'}}]},
       {"Create URR",				   'C', {'X', 'X', 'X', 'X'},
	[{"URR ID",				   'M', {'X', 'X', 'X', 'X'}},
	 {"Measurement Method",			   'M', {'X', 'X', 'X', 'X'}},
	 {"Reporting Triggers",			   'M', {'X', 'X', 'X', 'X'}},
	 {"Measurement Period",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Volume Threshold",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Volume Quota",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Event Threshold",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Event Quota",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Time Threshold",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Time Quota",				   'C', {'-', 'X', 'X', 'X'}},
	 {"Quota Holding Time",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Dropped DL Traffic Threshold",	   'C', {'X', '-', '-', 'X'}},
	 {"Monitoring Time",			   'O', {'X', 'X', 'X', 'X'}},
	 {"Subsequent Volume Threshold",	   'O', {'X', 'X', 'X', 'X'}},
	 {"Subsequent Time Threshold",		   'O', {'X', 'X', 'X', 'X'}},
	 {"Subsequent Volume Quota",		   'O', {'-', 'X', 'X', 'X'}},
	 {"Subsequent Time Quota",		   'O', {'-', 'X', 'X', 'X'}},
	 {"Subsequent Event Threshold",		   'O', {'-', 'X', 'X', 'X'}},
	 {"Subsequent Event Quota",		   'O', {'-', 'X', 'X', 'X'}},
	 {"Inactivity Detection Time",		   'C', {'-', 'X', 'X', 'X'}},
	 {"Linked URR ID",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Measurement Information",		   'C', {'-', 'X', 'X', 'X'}},
	 {"Time Quota Mechanism",		   'C', {'-', 'X', '-', '-'}},
	 {"Aggregated URRs",			   'C', {'-', 'X', '-', ' '},
	  [{"Aggregated URR ID",		   'M', {'-', 'X', '-', '-'}},
	   {"Multiplier",			   'M', {'-', 'X', '-', '-'}}]},
	 {"FAR ID",				   'C', {'-', 'X', 'X', 'X'}},
	 {"Ethernet Inactivity Timer",		   'C', {'-', '-', '-', 'X'}},
	 {"Additional Monitoring Time",		   'O', {'X', 'X', 'X', 'X'},
	  [{"Monitoring Time",			   'M', {'X', 'X', 'X', 'X'}},
	   {"Subsequent Volume Threshold",	   'O', {'X', 'X', 'X', 'X'}},
	   {"Subsequent Time Threshold",	   'O', {'X', 'X', 'X', 'X'}},
	   {"Subsequent Volume Quota",		   'O', {'-', 'X', 'X', 'X'}},
	   {"Subsequent Time Quota",		   'O', {'-', 'X', 'X', 'X'}},
	   {"Event Threshold",			   'O', {'-', 'X', 'X', 'X'}},
	   {"Event Quota",			   'O', {'-', 'X', 'X', 'X'}}]}
	]},
       {"Create QER",				   'C', {'-', 'X', 'X', 'X'},
	[{"QER ID",				   'M', {'-', 'X', 'X', 'X'}},
	 {"QER Correlation ID",			   'C', {'-', 'X', '-', 'X'}},
	 {"Gate Status",			   'M', {'-', 'X', 'X', 'X'}},
	 {"MBR",				   'C', {'-', 'X', 'X', 'X'}},
	 {"GBR",				   'C', {'-', 'X', 'X', 'X'}},
	 {"Packet Rate",			   'C', {'-', 'X', '-', ' '}},
	 {"DL Flow Level Marking",		   'C', {'-', 'X', 'X', '-'}},
	 {"QFI",				   'C', {'-', '-', '-', 'X'}},
	 {"RQI",				   'C', {'-', '-', '-', 'X'}},
	 {"Paging Policy Indicator",		   'C', {'-', '-', '-', 'X'}},
	 {"Averaging Window",			   'O', {'-', '-', '-', 'X'}}]},
       {"Create BAR",				   'O', {'X', '-', '-', 'X'},
	[{"BAR ID",				   'M', {'X', '-', '-', 'X'}},
	 {"Downlink Data Notification Delay",	   'C', {'X', '-', '-', '-'}},
	 {"Suggested Buffering Packets Count",	   'C', {' ', 'X', 'X', 'X'}}]},
       {"Create Traffic Endpoint",		   'C', {'X', 'X', 'X', 'X'},
	[{"Traffic Endpoint ID",		   'M', {'X', 'X', 'X', 'X'}},
	 {"F-TEID",				   'O', {'X', 'X', '-', 'X'}},
	 {"Network Instance",			   'O', {'X', 'X', 'X', 'X'}},
	 {"UE IP address",			   'O', {'-', 'X', 'X', 'X'}},
	 {"Ethernet PDU Session Information",	   'O', {'-', '-', '-', 'X'}},
	 {"Framed-Route",			   'O', {'-', 'X', '-', 'X'}},
	 {"Framed-Routing",			   'O', {'-', 'X', '-', 'X'}},
	 {"Framed-IPv6-Route",			   'O', {'-', 'X', '-', 'X'}}]},
       {"PDN Type",				   'C', {'X', 'X', '-', 'X'}},
       {"FQ-CSID",				   'C', {'-', 'X', '-', '-'}},
       {"User Plane Inactivity Timer",		   'O', {'-', 'X', 'X', 'X'}},
       {"User ID",				   'O', {'X', 'X', 'X', 'X'}},
       {"Trace Information",			   'O', {'X', 'X', 'X', 'X'}},
       {"TP Build Identifier",			   'O', {'X', 'X', 'X', 'X'}}]},
     {51, "Session Establishment Response",		{'X', 'X', 'X', 'X'},
      [{"Node ID",				   'M', {'X', 'X', 'X', 'X'}},
       {"PFCP Cause",				   'M', {'X', 'X', 'X', 'X'}},
       {"Offending IE",				   'C', {'X', 'X', 'X', 'X'}},
       {"F-SEID",				   'C', {'X', 'X', 'X', 'X'}},
       {"Created PDR",				   'C', {'X', 'X', '-', 'X'},
	[{"PDR ID",				   'M', {'X', 'X', '-', 'X'}},
	 {"F-TEID",				   'C', {'X', 'X', '-', 'X'}}]},
       {"Load Control Information",		   'O', {'X', 'X', 'X', 'X'},
	[{"Sequence Number",			   'M', {'X', 'X', 'X', 'X'}},
	 {"Metric",				   'M', {'X', 'X', 'X', 'X'}}]},
       {"Overload Control Information",		   'O', {'X', 'X', 'X', 'X'},
	[{"Sequence Number",			   'M', {'X', 'X', 'X', 'X'}},
	 {"Metric",				   'M', {'X', 'X', 'X', 'X'}},
	 {"Timer",				   'M', {'X', 'X', 'X', 'X'}},
	 {"OCI Flags",				   'C', {'X', 'X', 'X', 'X'}}]},
       {"FQ-CSID",				   'C', {'X', '-', '-', '-'}},
       {"FQ-CSID",				   'C', {'-', 'X', '-', '-'}},
       {"Failed Rule ID",			   'C', {'X', 'X', 'X', 'X'}},
       {"Created Traffic Endpoint",		   'C', {'X', 'X', '-', 'X'},
	[{"Traffic Endpoint ID",		   'M', {'X', 'X', '-', 'X'}},
	 {"F-TEID",				   'C', {'X', 'X', '-', 'X'}}]},
       {"TP Build Identifier",			   'O', {'X', 'X', 'X', 'X'}}]},
     {52, "Session Modification Request",		{'X', 'X', 'X', 'X'},
      [{"F-SEID",				   'C', {'X', 'X', 'X', 'X'}},
       {"Remove PDR",				   'C', {'X', 'X', 'X', 'X'},
	[{"PDR ID",				   'M', {'X', 'X', 'X', 'X'}}]},
       {"Remove FAR",				   'C', {'X', 'X', 'X', 'X'},
	[{"FAR ID",				   'M', {'X', 'X', 'X', 'X'}}]},
       {"Remove URR",				   'C', {'X', 'X', 'X', 'X'},
	[{"URR ID",				   'M', {'X', 'X', 'X', 'X'}}]},
       {"Remove QER",				   'C', {'-', 'X', 'X', 'X'},
	[{"QER ID",				   'M', {'X', 'X', 'X', 'X'}}]},
       {"Remove BAR",				   'C', {'X', '-', '-', 'X'},
	[{"BAR ID",				   'M', {'X', 'X', 'X', 'X'}}]},
       {"Remove Traffic Endpoint",		   'C', {'X', 'X', 'X', 'X'},
	[{"Traffic Endpoint ID",		   'M', {'X', 'X', 'X', 'X'}}]},
       {"Create PDR",				   'C', {'X', 'X', 'X', 'X'},
	[{"PDR ID",				   'M', {'X', 'X', 'X', 'X'}},
	 {"Precedence",				   'M', {'-', 'X', 'X', 'X'}},
	 {"PDI",				   'M', {'X', 'X', 'X', 'X'},
	  [{"Source Interface",			   'M', {'X', 'X', 'X', 'X'}},
	   {"F-TEID",				   'O', {'X', 'X', '-', 'X'}},
	   {"Network Instance",			   'O', {'X', 'X', 'X', 'X'}},
	   {"UE IP address",			   'O', {'-', 'X', 'X', 'X'}},
	   {"Traffic Endpoint ID",		   'C', {'X', 'X', 'X', 'X'}},
	   {"SDF Filter",			   'O', {'-', 'X', 'X', 'X'}},
	   {"Application ID",			   'O', {'-', 'X', 'X', 'X'}},
	   {"Ethernet PDU Session Information",	   'O', {'-', '-', '-', 'X'}},
	   {"Ethernet Packet Filter",		   'O', {'-', '-', '-', 'X'},
	    [{"Ethernet Filter ID",		   'C', {'-', '-', '-', 'X'}},
	     {"Ethernet Filter Properties",	   'C', {'-', '-', '-', 'X'}},
	     {"MAC address",			   'O', {'-', '-', '-', 'X'}},
	     {"Ethertype",			   'O', {'-', '-', '-', 'X'}},
	     {"C-TAG",				   'O', {'-', '-', '-', 'X'}},
	     {"S-TAG",				   'O', {'-', '-', '-', 'X'}},
	     {"SDF Filter",			   'O', {'-', '-', '-', 'X'}}]},
	   {"QFI",				   'O', {'-', '-', '-', 'X'}},
	   {"Framed-Route",			   'O', {'-', 'X', '-', 'X'}},
	   {"Framed-Routing",			   'O', {'-', 'X', '-', 'X'}},
	   {"Framed-IPv6-Route",		   'O', {'-', 'X', '-', 'X'}}]},
	 {"Outer Header Removal",		   'C', {'X', 'X', '-', 'X'}},
	 {"FAR ID",				   'C', {'X', 'X', 'X', 'X'}},
	 {"URR ID",				   'C', {'X', 'X', 'X', 'X'}},
	 {"QER ID",				   'C', {'-', 'X', 'X', 'X'}},
	 {"Activate Predefined Rules",		   'C', {'-', 'X', 'X', 'X'}}]},
       {"Create FAR",				   'C', {'X', 'X', 'X', 'X'},
	[{"FAR ID",				   'M', {'X', 'X', 'X', 'X'}},
	 {"Apply Action",			   'M', {'X', 'X', 'X', 'X'}},
	 {"Forwarding Parameters",		   'C', {'X', 'X', 'X', 'X'},
	  [{"Destination Interface",		   'M', {'X', 'X', 'X', 'X'}},
	   {"Network Instance",			   'O', {'X', 'X', 'X', 'X'}},
	   {"Redirect Information",		   'C', {'-', 'X', 'X', 'X'}},
	   {"Outer Header Creation",		   'C', {'X', 'X', '-', 'X'}},
	   {"Transport Level Marking",		   'C', {'X', 'X', '-', 'X'}},
	   {"Forwarding Policy",		   'C', {'-', 'X', 'X', 'X'}},
	   {"Header Enrichment",		   'O', {'-', 'X', 'X', 'X'}},
	   {"Traffic Endpoint ID",		   'C', {'X', 'X', '-', 'X'}},
	   {"Proxying",				   'C', {'-', '-', '-', 'X'}}]},
	 {"Duplicating Parameters",		   'C', {'X', 'X', '-', 'X'},
	  [{"Destination Interface",		   'M', {'X', 'X', '-', 'X'}},
	   {"Outer Header Creation",		   'C', {'X', 'X', '-', 'X'}},
	   {"Transport Level Marking",		   'C', {'X', 'X', '-', 'X'}},
	   {"Forwarding Policy",		   'C', {'X', 'X', '-', 'X'}}]},
	 {"BAR ID",				   'O', {'X', '-', '-', 'X'}}]},
       {"Create URR",				   'C', {'X', 'X', 'X', 'X'},
	[{"URR ID",				   'M', {'X', 'X', 'X', 'X'}},
	 {"Measurement Method",			   'M', {'X', 'X', 'X', 'X'}},
	 {"Reporting Triggers",			   'M', {'X', 'X', 'X', 'X'}},
	 {"Measurement Period",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Volume Threshold",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Volume Quota",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Event Threshold",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Event Quota",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Time Threshold",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Time Quota",				   'C', {'-', 'X', 'X', 'X'}},
	 {"Quota Holding Time",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Dropped DL Traffic Threshold",	   'C', {'X', '-', '-', 'X'}},
	 {"Monitoring Time",			   'O', {'X', 'X', 'X', 'X'}},
	 {"Subsequent Volume Threshold",	   'O', {'X', 'X', 'X', 'X'}},
	 {"Subsequent Time Threshold",		   'O', {'X', 'X', 'X', 'X'}},
	 {"Subsequent Volume Quota",		   'O', {'-', 'X', 'X', 'X'}},
	 {"Subsequent Time Quota",		   'O', {'-', 'X', 'X', 'X'}},
	 {"Subsequent Event Threshold",		   'O', {'-', 'X', 'X', 'X'}},
	 {"Subsequent Event Quota",		   'O', {'-', 'X', 'X', 'X'}},
	 {"Inactivity Detection Time",		   'C', {'-', 'X', 'X', 'X'}},
	 {"Linked URR ID",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Measurement Information",		   'C', {'-', 'X', 'X', 'X'}},
	 {"Time Quota Mechanism",		   'C', {'-', 'X', '-', '-'}},
	 {"Aggregated URRs",			   'C', {'-', 'X', '-', ' '},
	  [{"Aggregated URR ID",		   'M', {'-', 'X', '-', '-'}},
	   {"Multiplier",			   'M', {'-', 'X', '-', '-'}}]},
	 {"FAR ID",				   'C', {'-', 'X', 'X', 'X'}},
	 {"Ethernet Inactivity Timer",		   'C', {'-', '-', '-', 'X'}},
	 {"Additional Monitoring Time",		   'O', {'X', 'X', 'X', 'X'},
	  [{"Monitoring Time",			   'M', {'X', 'X', 'X', 'X'}},
	   {"Subsequent Volume Threshold",	   'O', {'X', 'X', 'X', 'X'}},
	   {"Subsequent Time Threshold",	   'O', {'X', 'X', 'X', 'X'}},
	   {"Subsequent Volume Quota",		   'O', {'-', 'X', 'X', 'X'}},
	   {"Subsequent Time Quota",		   'O', {'-', 'X', 'X', 'X'}},
	   {"Event Threshold",			   'O', {'-', 'X', 'X', 'X'}},
	   {"Event Quota",			   'O', {'-', 'X', 'X', 'X'}}]}
	]},
       {"Create QER",				   'C', {'-', 'X', 'X', 'X'},
	[{"QER ID",				   'M', {'-', 'X', 'X', 'X'}},
	 {"QER Correlation ID",			   'C', {'-', 'X', '-', 'X'}},
	 {"Gate Status",			   'M', {'-', 'X', 'X', 'X'}},
	 {"MBR",				   'C', {'-', 'X', 'X', 'X'}},
	 {"GBR",				   'C', {'-', 'X', 'X', 'X'}},
	 {"Packet Rate",			   'C', {'-', 'X', '-', ' '}},
	 {"DL Flow Level Marking",		   'C', {'-', 'X', 'X', '-'}},
	 {"QFI",				   'C', {'-', '-', '-', 'X'}},
	 {"RQI",				   'C', {'-', '-', '-', 'X'}},
	 {"Paging Policy Indicator",		   'C', {'-', '-', '-', 'X'}},
	 {"Averaging Window",			   'O', {'-', '-', '-', 'X'}}]},
       {"Create BAR",				   'O', {'X', '-', '-', 'X'},
	[{"BAR ID",				   'M', {'X', '-', '-', 'X'}},
	 {"Downlink Data Notification Delay",	   'C', {'X', '-', '-', '-'}},
	 {"Suggested Buffering Packets Count",	   'C', {' ', 'X', 'X', 'X'}}]},
       {"Create Traffic Endpoint",		   'C', {'X', 'X', 'X', 'X'},
	[{"Traffic Endpoint ID",		   'M', {'X', 'X', 'X', 'X'}},
	 {"F-TEID",				   'O', {'X', 'X', '-', 'X'}},
	 {"Network Instance",			   'O', {'X', 'X', 'X', 'X'}},
	 {"UE IP address",			   'O', {'-', 'X', 'X', 'X'}},
	 {"Ethernet PDU Session Information",	   'O', {'-', '-', '-', 'X'}},
	 {"Framed-Route",			   'O', {'-', 'X', '-', 'X'}},
	 {"Framed-Routing",			   'O', {'-', 'X', '-', 'X'}},
	 {"Framed-IPv6-Route",			   'O', {'-', 'X', '-', 'X'}}]},
       {"Update PDR",				   'C', {'X', 'X', 'X', 'X'},
	[{"PDR ID",				   'M', {'X', 'X', 'X', 'X'}},
	 {"Outer Header Removal",		   'C', {'X', 'X', '-', 'X'}},
	 {"Precedence",				   'C', {'-', 'X', 'X', 'X'}},
	 {"PDI",				   'C', {'X', 'X', 'X', 'X'},
	  [{"Source Interface",			   'M', {'X', 'X', 'X', 'X'}},
	   {"F-TEID",				   'O', {'X', 'X', '-', 'X'}},
	   {"Network Instance",			   'O', {'X', 'X', 'X', 'X'}},
	   {"UE IP address",			   'O', {'-', 'X', 'X', 'X'}},
	   {"Traffic Endpoint ID",		   'C', {'X', 'X', 'X', 'X'}},
	   {"SDF Filter",			   'O', {'-', 'X', 'X', 'X'}},
	   {"Application ID",			   'O', {'-', 'X', 'X', 'X'}},
	   {"Ethernet PDU Session Information",	   'O', {'-', '-', '-', 'X'}},
	   {"Ethernet Packet Filter",		   'O', {'-', '-', '-', 'X'},
	    [{"Ethernet Filter ID",		   'C', {'-', '-', '-', 'X'}},
	     {"Ethernet Filter Properties",	   'C', {'-', '-', '-', 'X'}},
	     {"MAC address",			   'O', {'-', '-', '-', 'X'}},
	     {"Ethertype",			   'O', {'-', '-', '-', 'X'}},
	     {"C-TAG",				   'O', {'-', '-', '-', 'X'}},
	     {"S-TAG",				   'O', {'-', '-', '-', 'X'}},
	     {"SDF Filter",			   'O', {'-', '-', '-', 'X'}}]},
	   {"QFI",				   'O', {'-', '-', '-', 'X'}},
	   {"Framed-Route",			   'O', {'-', 'X', '-', 'X'}},
	   {"Framed-Routing",			   'O', {'-', 'X', '-', 'X'}},
	   {"Framed-IPv6-Route",		   'O', {'-', 'X', '-', 'X'}}]},
	 {"FAR ID",				   'C', {'X', 'X', 'X', 'X'}},
	 {"URR ID",				   'C', {'X', 'X', 'X', 'X'}},
	 {"QER ID",				   'C', {'-', 'X', 'X', 'X'}},
	 {"Activate Predefined Rules",		   'C', {'-', 'X', 'X', 'X'}},
	 {"Deactivate Predefined Rules",	   'C', {'-', 'X', 'X', 'X'}}]},
       {"Update FAR",				   'C', {'X', 'X', 'X', 'X'},
	[{"FAR ID",				   'M', {'X', 'X', 'X', 'X'}},
	 {"Apply Action",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Update Forwarding Parameters",	   'C', {'X', 'X', 'X', 'X'},
	  [{"Destination Interface",		   'C', {'X', 'X', 'X', 'X'}},
	   {"Network Instance",			   'C', {'X', 'X', 'X', 'X'}},
	   {"Redirect Information",		   'C', {'-', 'X', 'X', 'X'}},
	   {"Outer Header Creation",		   'C', {'X', 'X', '-', 'X'}},
	   {"Transport Level Marking",		   'C', {'X', 'X', '-', 'X'}},
	   {"Forwarding Policy",		   'C', {'-', 'X', 'X', 'X'}},
	   {"Header Enrichment",		   'C', {'-', 'X', 'X', 'X'}},
	   {"SxSMReq-Flags",			   'C', {'X', 'X', '-', 'X'}},
	   {"Traffic Endpoint ID",		   'C', {'X', 'X', '-', 'X'}}]},
	 {"Update Duplicating Parameters",	   'C', {'X', 'X', '-', 'X'},
	  [{"Destination Interface",		   'C', {'X', 'X', '-', 'X'}},
	   {"Outer Header Creation",		   'C', {'X', 'X', '-', 'X'}},
	   {"Transport Level Marking",		   'C', {'X', 'X', '-', 'X'}},
	   {"Forwarding Policy",		   'C', {'-', 'X', '-', 'X'}}]},
	 {"BAR ID",				   'C', {'X', '-', '-', 'X'}}]},
       {"Update URR",				   'C', {'X', 'X', 'X', 'X'},
	[{"URR ID",				   'M', {'X', 'X', 'X', 'X'}},
	 {"Measurement Method",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Reporting Triggers",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Measurement Period",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Volume Threshold",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Volume Quota",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Time Threshold",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Time Quota",				   'C', {'-', 'X', 'X', 'X'}},
	 {"Event Threshold",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Event Quota",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Quota Holding Time",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Dropped DL Traffic Threshold",	   'C', {'X', '-', '-', 'X'}},
	 {"Monitoring Time",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Subsequent Volume Threshold",	   'C', {'X', 'X', 'X', 'X'}},
	 {"Subsequent Time Threshold",		   'C', {'X', 'X', 'X', 'X'}},
	 {"Subsequent Volume Quota",		   'C', {'-', 'X', 'X', 'X'}},
	 {"Subsequent Time Quota",		   'C', {'-', 'X', 'X', 'X'}},
	 {"Subsequent Event Threshold",		   'O', {'-', 'X', 'X', 'X'}},
	 {"Subsequent Event Quota",		   'O', {'-', 'X', 'X', 'X'}},
	 {"Inactivity Detection Time",		   'C', {'-', 'X', 'X', 'X'}},
	 {"Linked URR ID",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Measurement Information",		   'C', {'-', 'X', '-', 'X'}},
	 {"Time Quota Mechanism",		   'C', {'-', 'X', '-', '-'}},
	 {"Aggregated URRs",			   'C', {'-', 'X', '-', ' '}},
	 {"FAR ID",				   'C', {'-', 'X', 'X', 'X'}},
	 {"Ethernet Inactivity Timer",		   'C', {'-', '-', '-', 'X'}},
	 {"Additional Monitoring Time",		   'O', {'X', 'X', 'X', 'X'}}]},
       {"Update QER",				   'C', {'-', 'X', 'X', 'X'},
	[{"QER ID",				   'M', {'-', 'X', 'X', 'X'}},
	 {"QER Correlation ID",			   'C', {'-', 'X', '-', 'X'}},
	 {"Gate Status",			   'C', {'-', 'X', 'X', 'X'}},
	 {"MBR",				   'C', {'-', 'X', 'X', 'X'}},
	 {"GBR",				   'C', {'-', 'X', 'X', 'X'}},
	 {"Packet Rate",			   'C', {'-', 'X', '-', ' '}},
	 {"DL Flow Level Marking",		   'C', {'-', 'X', 'X', '-'}},
	 {"QFI",				   'C', {'-', '-', '-', 'X'}},
	 {"RQI",				   'C', {'-', '-', '-', 'X'}},
	 {"Paging Policy Indicator",		   'C', {'-', '-', '-', 'X'}},
	 {"Averaging Window",			   'O', {'-', '-', '-', 'X'}}]},
       {"Update BAR",				   'C', {'X', '-', '-', 'X'},
	[{"BAR ID",				   'M', {'X', '-', '-', 'X'}},
	 {"Downlink Data Notification Delay",	   'C', {'X', '-', '-', 'X'}},
	 {"Suggested Buffering Packets Count",	   'C', {' ', 'X', 'X', 'X'}}]},
       {"Update Traffic Endpoint",		   'C', {'X', 'X', 'X', 'X'},
	[{"Traffic Endpoint ID",		   'M', {'X', 'X', 'X', 'X'}},
	 {"F-TEID",				   'C', {'X', '-', '-', 'X'}},
	 {"Network Instance",			   'O', {'X', 'X', 'X', 'X'}},
	 {"UE IP address",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Framed-Route",			   'C', {'-', 'X', '-', 'X'}},
	 {"Framed-Routing",			   'C', {'-', 'X', '-', 'X'}},
	 {"Framed-IPv6-Route",			   'C', {'-', 'X', '-', 'X'}}]},
       {"SxSMReq-Flags",			   'C', {'X', 'X', 'X', 'X'}},
       {"Query URR",				   'C', {'X', 'X', 'X', 'X'},
	[{"URR ID",				   'M', {'X', 'X', 'X', 'X'}}]},
       {"FQ-CSID",				   'C', {'X', 'X', '-', '-'}},
       {"User Plane Inactivity Timer",		   'C', {'-', 'X', 'X', 'X'}},
       {"Query URR Reference",			   'O', {'X', 'X', 'X', 'X'}},
       {"Trace Information",			   'O', {'X', 'X', 'X', 'X'}}]},
     {53, "Session Modification Response",		{'X', 'X', 'X', 'X'},
      [{"PFCP Cause",				   'M', {'X', 'X', 'X', 'X'}},
       {"Offending IE",				   'C', {'X', 'X', 'X', 'X'}},
       {"Created PDR",				   'C', {'X', 'X', '-', 'X'}},
       {"Load Control Information",		   'O', {'X', 'X', 'X', 'X'}},
       {"Overload Control Information",		   'O', {'X', 'X', 'X', 'X'}},
       {"Usage Report SMR",			   'C', {'X', 'X', 'X', 'X'},
	[{"URR ID",				   'M', {'X', 'X', 'X', 'X'}},
	 {"UR-SEQN",				   'M', {'X', 'X', 'X', 'X'}},
	 {"Usage Report Trigger",		   'M', {'X', 'X', 'X', 'X'}},
	 {"Start Time",				   'C', {'X', 'X', 'X', 'X'}},
	 {"End Time",				   'C', {'X', 'X', 'X', 'X'}},
	 {"Volume Measurement",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Duration Measurement",		   'C', {'X', 'X', 'X', 'X'}},
	 {"Time of First Packet",		   'C', {'-', 'X', 'X', 'X'}},
	 {"Time of Last Packet",		   'C', {'-', 'X', 'X', 'X'}},
	 {"Usage Information",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Query URR Reference",		   'C', {'X', 'X', 'X', 'X'}},
	 {"Ethernet Traffic Information",	   'C', {'-', '-', '-', 'X'}},
	 {"TP Now",				   'O', {'X', 'X', 'X', 'X'}},
	 {"TP Start Time",			   'O', {'X', 'X', 'X', 'X'}},
	 {"TP End Time",			   'O', {'X', 'X', 'X', 'X'}}]},
       {"Failed Rule ID",			   'C', {'X', 'X', 'X', 'X'}},
       {"Additional Usage Reports Information",	   'C', {'X', 'X', 'X', 'X'}},
       {"Created Traffic Endpoint",		   'C', {'X', 'X', '-', 'X'}}]},
     {54, "Session Deletion Request",			{'X', 'X', 'X', 'X'},
      []},
     {55, "Session Deletion Response",			{'X', 'X', 'X', 'X'},
      [{"PFCP Cause",				   'M', {'X', 'X', 'X', 'X'}},
       {"Offending IE",				   'C', {'X', 'X', 'X', 'X'}},
       {"Load Control Information",		   'O', {'X', 'X', 'X', 'X'}},
       {"Overload Control Information",		   'O', {'X', 'X', 'X', 'X'}},
       {"Usage Report SDR",			   'C', {'X', 'X', 'X', 'X'},
	[{"URR ID",				   'M', {'X', 'X', 'X', 'X'}},
	 {"UR-SEQN",				   'M', {'X', 'X', 'X', 'X'}},
	 {"Usage Report Trigger",		   'M', {'X', 'X', 'X', 'X'}},
	 {"Start Time",				   'C', {'X', 'X', 'X', 'X'}},
	 {"End Time",				   'C', {'X', 'X', 'X', 'X'}},
	 {"Volume Measurement",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Duration Measurement",		   'C', {'X', 'X', 'X', 'X'}},
	 {"Time of First Packet",		   'C', {'-', 'X', 'X', 'X'}},
	 {"Time of Last Packet",		   'C', {'-', 'X', 'X', 'X'}},
	 {"Usage Information",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Ethernet Traffic Information",	   'C', {'-', '-', '-', 'X'}},
	 {"TP Now",				   'O', {'X', 'X', 'X', 'X'}},
	 {"TP Start Time",			   'O', {'X', 'X', 'X', 'X'}},
	 {"TP End Time",			   'O', {'X', 'X', 'X', 'X'}}]}
      ]},
     {56, "Session Report Request",			{'X', 'X', 'X', 'X'},
      [{"Report Type",				   'M', {'X', 'X', 'X', 'X'}},
       {"Downlink Data Report",			   'C', {'X', '-', '-', 'X'},
	[{"PDR ID",				   'M', {'X', '-', '-', 'X'}},
	 {"Downlink Data Service Information",	   'C', {'X', '-', '-', 'X'}}]},
       {"Usage Report SRR",			   'C', {'X', 'X', 'X', 'X'},
	[{"URR ID",				   'M', {'X', 'X', 'X', 'X'}},
	 {"UR-SEQN",				   'M', {'X', 'X', 'X', 'X'}},
	 {"Usage Report Trigger",		   'M', {'X', 'X', 'X', 'X'}},
	 {"Start Time",				   'C', {'X', 'X', 'X', 'X'}},
	 {"End Time",				   'C', {'X', 'X', 'X', 'X'}},
	 {"Volume Measurement",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Duration Measurement",		   'C', {'X', 'X', 'X', 'X'}},
	 {"Application Detection Information",	   'C', {'-', 'X', 'X', 'X'},
	  [{"Application ID",			   'M', {'-', 'X', 'X', 'X'}},
	   {"Application Instance ID",		   'C', {'-', 'X', 'X', 'X'}},
	   {"Flow Information",			   'C', {'-', 'X', 'X', 'X'}}]},
	 {"UE IP address",			   'C', {'-', '-', 'X', 'X'}},
	 {"Network Instance",			   'C', {'-', '-', 'X', 'X'}},
	 {"Time of First Packet",		   'C', {'-', 'X', 'X', 'X'}},
	 {"Time of Last Packet",		   'C', {'-', 'X', 'X', 'X'}},
	 {"Usage Information",			   'C', {'X', 'X', 'X', 'X'}},
	 {"Query URR Reference",		   'C', {'X', 'X', 'X', 'X'}},
	 {"Event Time Stamp",			   'C', {'-', 'X', 'X', 'X'}},
	 {"Ethernet Traffic Information",	   'C', {'-', '-', '-', 'X'},
	  [{"MAC Addresses Detected",		   'C', {'-', '-', '-', 'X'}},
	   {"MAC Addresses Removed",		   'C', {'-', '-', '-', 'X'}}]},
	 {"TP Now",				   'O', {'X', 'X', 'X', 'X'}},
	 {"TP Start Time",			   'O', {'X', 'X', 'X', 'X'}},
	 {"TP End Time",			   'O', {'X', 'X', 'X', 'X'}}]},
       {"Error Indication Report",		   'C', {'X', 'X', '-', 'X'},
	[{"F-TEID",				   'M', {'X', 'X', '-', 'X'}}]},
       {"Load Control Information",		   'O', {'X', 'X', 'X', 'X'}},
       {"Overload Control Information",		   'O', {'X', 'X', 'X', 'X'}},
       {"Additional Usage Reports Information",	   'C', {'X', 'X', 'X', 'X'}}]},
     {57, "Session Report Response",			{'X', 'X', 'X', 'X'},
      [{"PFCP Cause",				   'M', {'X', 'X', 'X', 'X'}},
       {"Offending IE",				   'C', {'X', 'X', 'X', 'X'}},
       {"Update BAR",				   'C', {'X', '-', '-', 'X'},
	[{"BAR ID",				   'M', {'X', '-', '-', 'X'}},
	 {"Downlink Data Notification Delay",	   'C', {'X', '-', '-', 'X'}},
	 {"DL Buffering Duration",		   'C', {'X', '-', '-', 'X'}},
	 {"DL Buffering Suggested Packet Count",   'O', {'X', '-', '-', 'X'}},
	 {"Suggested Buffering Packets Count",	   'C', {' ', 'X', 'X', 'X'}}]},
       {"SxSRRsp-Flags",			   'C', {'X', '-', '-', 'X'}}]}].

-type flag() :: any().
-type enum() :: any().
-type array_def() :: any().
-type field_type() ::
    {flags, [flag()]} |
    {enum, [enum()]} |
    boolean |
    integer |
    bits |
    bytes |
    binary |
    length_binary |
    {array, array_def()} |
    tuple().

-record(ie, {id, name, type, min_field_count, fields}).
-record(field, {rec, name, len, optional, type, spec}).

-define('WildCard', #field{type = '_', len = 0}).
-define('DecoderFunName', "decode_v1_element").
-define('EncoderFunName', "encode_v1_element").

ies() ->
    TypeFF = fun(Type,          F) when is_atom(Type) -> F#field{type = Type};
		({type,  Type}, F) when is_atom(Type) -> F#field{type = helper, spec = Type};
		({array, Size}, F) when is_integer(Size) -> F#field{type = array, spec = {Size, bytes}};
		({Type,  Spec}, F) when is_atom(Type) -> F#field{type = Type, spec = Spec}
	     end,
    FieldF = fun(Rec, {Name, Len, Type}, Optional, F) when is_integer(Len) ->
		     [TypeFF(Type, #field{rec = Rec, name = s2a(Name), len = Len,
					  optional = Optional}) | F];
		(Rec, {Name, Type}, Optional, F) when is_list(Name), is_atom(Type) ->
		     [#field{rec = Rec, name = s2a(Name), len = 0, optional = Optional,
			     type = helper, spec = Type} | F];
		(Rec, {'_', Len}, Optional, F) when is_integer(Len) ->
		     [#field{rec = Rec, len = Len, optional = Optional, type = '_'} | F]
	     end,
    SpecF = fun(Fields, #ie{name = Rec, min_field_count = MinLen} = IE) when is_list(Fields) ->
		    {FieldDef, _} =
			lists:foldl(
			  fun(Field, {F, Cnt}) ->
				  {FieldF(Rec, Field, Cnt >= MinLen, F), Cnt + 1} end,
			  {[], 0}, Fields),
		    IE#ie{fields = lists:reverse(FieldDef)};
	      (Helper, IE) when is_atom(Helper) ->
		    IE#ie{type = Helper}
	   end,
    lists:map(
      fun ({Id, Name, Spec}) ->
	      SpecF(Spec, #ie{id = Id, name = s2a(Name)});
	  ({Id, Name, MinLen, Spec}) ->
	      SpecF(Spec, #ie{id = Id, name = s2a(Name), min_field_count = MinLen})
      end, raw_ies()).


gen_record_def(#field{type = '_'}) ->
    [];
gen_record_def(#field{spec = mccmnc}) ->
    ["mcc = <<\"001\">>", "mnc = <<\"001\">>"];
gen_record_def(#field{name = Name, optional = true}) ->
    [to_string(Name)];
gen_record_def(#field{name = Name, type = flags}) ->
    [io_lib:format("~s = []", [Name])];
gen_record_def(#field{name = Name, type = enum, spec = [{_,H}|_]}) ->
    [io_lib:format("~s = ~w", [Name, s2e(H)])];
gen_record_def(#field{name = Name, type = enum, spec = [H|_]}) ->
    [io_lib:format("~s = ~w", [Name, s2e(H)])];
gen_record_def(#field{name = Name, type = boolean}) ->
    [io_lib:format("~s = false", [Name])];
gen_record_def(#field{name = Name, type = Type})
  when Type =:= integer; Type =:= 'signed-integer' ->
    [io_lib:format("~s = 0", [Name])];
gen_record_def(#field{name = Name, type = float}) ->
    [io_lib:format("~s = 0.0", [s2a(Name)])];
gen_record_def(#field{name = Name, len = Size, type = bits}) ->
    [io_lib:format("~s = ~w", [Name, <<0:Size>>])];
gen_record_def(#field{name = Name, len = Size, type = bytes}) ->
    [io_lib:format("~s = ~w", [Name, <<0:(Size * 8)>>])];
gen_record_def(#field{name = Name, type = Type})
  when Type =:= binary; Type =:= length_binary ->
    [io_lib:format("~s = <<>>", [Name])];
gen_record_def(#field{name = Name, type = array}) ->
    [io_lib:format("~s = []", [Name])];
gen_record_def(#field{name = Name}) ->
    [to_string(Name)].


gen_decoder_header_match(#field{type = '_', len = 0}) ->
    ["_/binary"];
gen_decoder_header_match(#field{type = '_', len = Size}) ->
    [io_lib:format("_:~w", [Size])];
%% gen_decoder_header_match(#field{Value, Size}) when is_integer(Value); is_atom(Value) ->
%%     [io_lib:format("~w:~w", [Value, Size])];
gen_decoder_header_match(#field{name = Name, spec = mccmnc}) ->
    [io_lib:format("M_~s:3/bytes", [Name])];
%% gen_decoder_header_match(#field{name = Name, type = flags}) ->
%%     [io_lib:format("M_~s/binary", [Name])];
gen_decoder_header_match({Name, {flags, Flags}}) ->
    [io_lib:format("M_~s_~s:1", [Name, Flag]) || Flag <- Flags];
gen_decoder_header_match(#field{name = Name, len = Size, type = enum}) ->
    [io_lib:format("M_~s:~w/integer", [Name, Size])];
gen_decoder_header_match(#field{name = Name, type = array, spec = Multi})
  when is_list(Multi) ->
    {stop, [io_lib:format("M_~s_Rest/binary", [Name])]};
gen_decoder_header_match(#field{name = Name, len = Len, type = array}) ->
    {stop, [io_lib:format("M_~s_len:~w/integer, M_~s_Rest/binary", [Name, Len, Name])]};
gen_decoder_header_match(#field{name = Name, len = Len, type = length_binary}) ->
    [io_lib:format("M_~s_len:~w/integer, M_~s:M_~s_len/bytes", [Name, Len, Name, Name])];
gen_decoder_header_match(#field{name = Name, len = 0, type = helper}) ->
    [io_lib:format("M_~s/binary", [Name])];
gen_decoder_header_match(#field{name = Name, len = Size, type = helper}) ->
    [io_lib:format("M_~s:~w/bits", [Name, Size])];
gen_decoder_header_match(#field{name = Name, len = Size, type = boolean}) ->
    [io_lib:format("M_~s:~w/integer", [Name, Size])];
gen_decoder_header_match(#field{name = Name, len = 0, type = Type}) ->
    [io_lib:format("M_~s/~w", [Name, Type])];
gen_decoder_header_match(#field{name = Name, len = Size, type = Type}) ->
    [io_lib:format("M_~s:~w/~s", [Name, Size, Type])].


gen_decoder_record_assign(#field{type = '_'}) ->
    [];
gen_decoder_record_assign(#field{name = Name, spec = mccmnc}) ->
    [io_lib:format("mcc = decode_mcc(M_~s)", [Name]),
     io_lib:format("mnc = decode_mnc(M_~s)", [Name])];
%% gen_decoder_record_assign(#field{name = Name, type = flags, spec = Flags}) ->
%%     [io_lib:format("~s = decode_flags(M_~s, ~p)",
%% 		   [Name, Name, Flags])];
gen_decoder_record_assign(#field{name = Name, type = flags, spec = Flags}) ->
    F = [io_lib:format("[ '~s' || M_~s_~s =/= 0 ]", [X, Name, X]) || X <- Flags],
    [io_lib:format("~s = ~s", [Name, string:join(F, " ++ ")])];
gen_decoder_record_assign(#field{rec = Rec, name = Name, type = enum}) ->
    [io_lib:format("~s = enum_v1_~s_~s(M_~s)", [Name, Rec, Name, Name])];
gen_decoder_record_assign(#field{name = Name, len = Size, type = array, spec = Multi})
  when is_list(Multi) ->
    [io_lib:format("~s = [X || <<X:~w/bytes>> <= M_~s]", [Name, Size, Name])];
gen_decoder_record_assign(#field{name = Name, type = array, spec = {Size, Type}}) ->
    [io_lib:format("~s = [X || <<X:~w/~s>> <= M_~s]", [Name, Size, Type, Name])];
gen_decoder_record_assign(#field{name = Name, type = helper, spec = TypeName}) ->
    [io_lib:format("~s = decode_~s(M_~s)", [Name, TypeName, Name])];
gen_decoder_record_assign(#field{name = Name, type = boolean}) ->
    [io_lib:format("~s = int2bool(M_~s)", [Name, Name])];
gen_decoder_record_assign(#field{name = Name}) ->
    [io_lib:format("~s = M_~s", [Name, Name])].


gen_encoder_record_assign(#field{type = '_'}) ->
    [];
gen_encoder_record_assign(#field{spec = mccmnc}) ->
    ["mcc = M_mcc", "mnc = M_mnc"];
gen_encoder_record_assign(#field{name = Name, type = undefined}) ->
    [io_lib:format("~s = undefined", [Name])];
gen_encoder_record_assign(#field{name = Name}) ->
    [io_lib:format("~s = M_~s", [Name, Name])].

%% gen_encoder_bin({Name, Size, float}) ->
%%     [io_lib:format("M_~s:~w/float", [s2a(Name), Size])];
%% gen_encoder_bin({Name, Size, 'signed-integer'}) ->
%%     [io_lib:format("M_~s:~w/signed", [s2a(Name), Size])];

gen_encoder_bin(#field{type = '_', len = 0}) ->
    [];
gen_encoder_bin(#field{type = '_', len = Size}) ->
    [io_lib:format("0:~w", [Size])];

%% gen_encoder_bin(#field{Value, Size}) when is_integer(Value); is_atom(Value) ->
%%     [io_lib:format("~w:~w", [Value, Size])];
gen_encoder_bin(#field{type = undefined}) ->
    [];
gen_encoder_bin(#field{spec = mccmnc}) ->
    ["(encode_mccmnc(M_mcc, M_mnc))/binary"];
%% gen_encoder_bin(#field{name = Name, len = MinSize, type = flags, spec = Flags}) ->
%%     [io_lib:format("(encode_min_int(~p, encode_flags(M_~s, ~p), little))/binary",
%% 		   [MinSize, Name, reorder_flags(Flags)])];
gen_encoder_bin(#field{name = Name, type = flags, spec = Flags}) ->
    [io_lib:format("(encode_v1_flag('~s', M_~s)):1", [Flag, Name]) || Flag <- Flags];

gen_encoder_bin(#field{rec = Rec, name = Name, len = Size, type = enum}) ->
    [io_lib:format("(enum_v1_~s_~s(M_~s)):~w/integer", [Rec, Name, Name, Size])];
gen_encoder_bin(#field{name = Name, len = Len, type = array, spec = {Size, Type}}) ->
    [io_lib:format("(length(M_~s)):~w/integer, (<< <<X:~w/~w>> || X <- M_~s>>)/binary",
		   [Name, Len, Size, Type, Name])];
gen_encoder_bin(#field{name = Name, len = Len, type = array}) ->
    [io_lib:format("(length(M_~s)):~w/integer, (<< <<X/binary>> || X <- M_~s>>)/binary", [Name, Len, Name])];
gen_encoder_bin(#field{name = Name, len = 0, type = helper, spec = TypeName}) ->
    [io_lib:format("(encode_~s(M_~s))/binary", [TypeName, Name])];
gen_encoder_bin(#field{name = Name, len = Size, type = helper, spec = TypeName}) ->
    [io_lib:format("(encode_~s(M_~s)):~w/bits", [TypeName, Name, Size])];
gen_encoder_bin(#field{name = Name, len = Len, type = length_binary}) ->
    [io_lib:format("(byte_size(M_~s)):~w/integer, M_~s/binary", [Name, Len, Name])];
gen_encoder_bin(#field{name = Name, len = 0, type = Type}) ->
    [io_lib:format("M_~s/~w", [Name, Type])];
gen_encoder_bin(#field{name = Name, len = Size, type = boolean}) ->
    [io_lib:format("(bool2int(M_~s)):~w/integer", [Name, Size])];
gen_encoder_bin(#field{name = Name, len = Size, type = Type}) ->
    [io_lib:format("M_~s:~w/~s", [Name, Size, Type])].

indent(Atom, Extra) when is_atom(Atom) ->
    indent(atom_to_list(Atom), Extra);
indent(List, Extra) ->
    Indent = length(lists:flatten(List)) + Extra,
    Spaces = Indent rem 8,
    Tabs = Indent div 8,
    [lists:duplicate(Tabs, "\t"), lists:duplicate(Spaces, " ")].

s2a(Name) when is_atom(Name) ->
    Name;
s2a(Name) ->
    S = lists:map(fun(32) -> $_;
		     ($/) -> $_;
		     ($-) -> $_;
		     ($.) -> $_;
		     ($,) -> $_;
		     (C)  -> C
		  end,
		  string:to_lower(Name)),
    list_to_atom(S).

s2e(Name) ->
    list_to_atom(Name).
%%     [$', Name, $'].

to_string(S) when is_list(S)   -> S;
to_string(A) when is_atom(A)   -> atom_to_list(A);
to_string(B) when is_binary(B) -> binary_to_list(B).

append([], Acc) ->
    Acc;
append([H|T], Acc) ->
    append(T, [H|Acc]).

collect(_Fun, [], Acc) ->
    lists:reverse(Acc);
collect(Fun, [F|Fields], Acc) ->
    case Fun(F) of
	{stop, L} ->
	    lists:reverse(append(L, Acc));
	L ->
	    collect(Fun, Fields, append(L, Acc))
    end.

collect(Fun, Fields) ->
    collect(Fun, Fields, []).

gen_enum(Rec, Name, Value, Cnt, Next, {FwdFuns, RevFuns}) ->
    Fwd = io_lib:format("enum_v1_~s_~s(~w) -> ~w", [Rec, Name, s2e(Value), Cnt]),
    Rev = io_lib:format("enum_v1_~s_~s(~w) -> ~w", [Rec, Name, Cnt, s2e(Value)]),
    gen_enum(Rec, Name, Next, Cnt + 1, {[Fwd|FwdFuns], [Rev|RevFuns]}).

gen_enum(_, _, [], _, {FwdFuns, RevFuns}) ->
    {lists:reverse(FwdFuns), lists:reverse(RevFuns)};
gen_enum(Rec, Name, [{Cnt, Value}|Rest], _, Acc) ->
    gen_enum(Rec, Name, Value, Cnt, Rest, Acc);
gen_enum(Rec, Name, [Value|Rest], Cnt, Acc) ->
    gen_enum(Rec, Name, Value, Cnt, Rest, Acc).

gen_message_type(Value, Name, Next, {FwdFuns, RevFuns}) ->
    Fwd = io_lib:format("message_type_v1(~s) -> ~w", [s2a(Name), Value]),
    Rev = io_lib:format("message_type_v1(~w) -> ~s", [Value, s2a(Name)]),
    gen_message_type(Next, {[Fwd|FwdFuns], [Rev|RevFuns]}).

gen_message_type([], {FwdFuns, RevFuns}) ->
    {lists:reverse(FwdFuns), lists:reverse(RevFuns)};
gen_message_type([{Value, Name, _, _}|Rest], Acc) ->
    gen_message_type(Value, Name, Rest, Acc).

build_late_assign([]) ->
    [];
build_late_assign([H = #field{type = array} | T]) ->
    build_late_assign(H, T);
build_late_assign([_ | T]) ->
    build_late_assign(T).

build_late_assign(#field{name = Name, len = Len, type = array, spec = Multi}, T)
  when is_list(Multi) ->
    Init = io_lib:format("M_~s_size = M_~s * ~w", [Name, s2a(Multi), Len]),
    build_late_assign(Name, Init, T);
build_late_assign(#field{name = Name, type = array, spec = {Size, Type}}, T)
  when Type =:= integer; Type =:= bits ->
    Init = io_lib:format("M_~s_size = M_~s_len * ~w", [Name, Name, Size]),
    build_late_assign(Name, Init, T);
build_late_assign(#field{name = Name, type = array, spec = {Size, _}}, T) ->
    Init = io_lib:format("M_~s_size = M_~s_len * ~w * 8", [Name, Name, Size]),
    build_late_assign(Name, Init, T).

build_late_assign(Name, Init, Fields) ->
    Match = io_lib:format("M_~s:M_~s_size/bits", [Name, Name]),
    {Body, Next} = collect_late_assign(Fields, [Match]),
    M = io_lib:format("    <<~s>> = M_~s_Rest,", [string:join(Body, ",\n      "), Name]),
    ["    ", Init, ",\n", M, "\n"] ++ build_late_assign(Next).

collect_late_assign([], Acc) ->
    {lists:reverse(Acc), []};
collect_late_assign(Fields = [H | T], Acc) ->
    case gen_decoder_header_match(H) of
	{stop, Match} ->
	    {lists:reverse([Match|Acc]), Fields};
	Match ->
	    collect_late_assign(T, [Match|Acc])
    end.


collect_enum(#field{rec = Rec, name = Name, type = enum, spec = Enum}, Acc) ->
    {FwdFuns, RevFuns} = gen_enum(Rec, Name, Enum, 0, {[], []}),
    Wildcard = io_lib:format("enum_v1_~s_~s(X) when is_integer(X) -> X", [Rec, Name]),
    S = string:join(FwdFuns ++ RevFuns ++ [Wildcard], ";\n") ++ ".\n",
    maps:put({Rec, Name}, S, Acc);
collect_enum(_, Acc) ->
    Acc.

collect_enums(#ie{type = undefined, fields = Fields}, AccIn) ->
    lists:foldr(fun(X, Acc) -> collect_enum(X, Acc) end, AccIn, Fields);
collect_enums(_, AccIn) ->
    AccIn.

write_enums(IEs) ->
    E = lists:foldr(fun collect_enums/2, #{}, IEs),
    Str = maps:values(E),
    string:join(Str, "\n").

write_record(#ie{name = Name, type = undefined, fields = Fields}) ->
    Indent = "\t  ",
    RecordDef = string:join(collect(fun gen_record_def/1, Fields, []), [",\n", Indent]),
    [io_lib:format("-record(~s, {~n~s~s~n}).\n", [Name, Indent, RecordDef])];
write_record(_) ->
    [].

write_decoder(#ie{min_field_count = Min, fields = Fields} = IE, Fns)
  when is_integer(Min), length(Fields) > Min ->
    SubIE = IE#ie{min_field_count = undefined},
    lists:foldl(
      fun (Len, FnsSub) ->
	      {H,T} = lists:split(Len, Fields),
	      case T of
		  [] -> FnsSub;
		  _ ->
		      write_decoder(SubIE#ie{fields = H ++ [?WildCard]}, FnsSub)
	      end
      end, Fns, lists:seq(Min, length(Fields)));


write_decoder(#ie{id = Id, type = undefined, name = Name, fields = Fields}, Fns) ->
    MatchIdent = indent(?DecoderFunName, 3),
    Match = string:join(collect(fun gen_decoder_header_match/1, Fields), [",\n", MatchIdent]),
    Body = build_late_assign(Fields),
    RecIdent = indent(Name, 6),
    RecAssign = string:join(collect(fun gen_decoder_record_assign/1, Fields), [",\n", RecIdent]),
    F = io_lib:format("%% decode ~s~n~s(<<~s>>, ~w) ->~n~s    #~s{~s}",
		      [Name, ?DecoderFunName, Match, Id, Body, Name, RecAssign]),
    [F | Fns];

write_decoder(#ie{name = Name, id = Id, type = Helper}, Fns) ->
    F = io_lib:format("%% decode ~s~n~s(<<Data/binary>>, ~w) ->~n    decode_~s(Data, ~s)",
		      [Name, ?DecoderFunName, Id, Helper, Name]),
    [F | Fns].

write_encoder(#ie{min_field_count = Min, fields = Fields} = IE, Fns)
  when is_integer(Min), length(Fields) > Min ->
    SubIE = IE#ie{min_field_count = undefined},
    lists:foldl(
      fun (Len, FnsSub) ->
	      {H,T} = lists:split(Len, Fields),
	      case T of
		  [] ->
		      write_encoder(SubIE#ie{fields = H}, FnsSub);
		  [#field{type = '_'}|_] -> FnsSub;
		  [M|_] ->
		      write_encoder(SubIE#ie{fields = H ++ [M#field{type = undefined}]}, FnsSub)
	      end
      end, Fns, lists:seq(length(Fields), Min, -1));

write_encoder(#ie{id = Id, name = Name, type = undefined, fields = Fields}, Fns) ->
    RecIdent = indent(?EncoderFunName ++ "(#", 4),
    RecAssign = string:join(collect(fun gen_encoder_record_assign/1, Fields), [",\n", RecIdent]),
    FunHead = io_lib:format("~s(#~s{~n~s~s}, Acc) ->~n", [?EncoderFunName, Name, RecIdent, RecAssign]),
    DecHead = io_lib:format("    encode_tlv(~w, ", [Id]),
    BinIndent = indent(DecHead, 2),
    BinAssign = string:join(collect(fun gen_encoder_bin/1, Fields), [",\n", BinIndent]),
    F = io_lib:format("~s~s<<~s>>, Acc)", [FunHead, DecHead, BinAssign]),
    [F | Fns];

write_encoder(#ie{id = Id, name = Name, type = Helper}, Fns) ->
    F = io_lib:format("~s(#~s{} = IE, Acc) ->~n    encode_tlv(~w, encode_~s(IE), Acc)",
		      [?EncoderFunName, Name, Id, Helper]),
    [F | Fns].

write_pretty_print(_, #ie{name = Name}) ->
    io_lib:format("?PRETTY_PRINT(pretty_print_v1, ~s)", [Name]).

%% ie_v/2
ie_v(_, Atom) when is_atom(Atom) ->
    Atom;
ie_v(IfNo, Grp) ->
    lists:foldl(fun(IE, A) -> ie_v(IE, IfNo, A) end, #{}, Grp).

%% ie_v/4
ie_v(IE, P, 'X', Grp, IfNo, A) ->
    IEsV = ie_v(IfNo, Grp),
    A#{s2a(IE) => {P, IEsV}};
ie_v(_IE, _P, _, _Grp, _IfNo, A) ->
    A.

%% ie_v/3
ie_v({IE, P, Intf}, IfNo, A) ->
    ie_v(IE, P, element(IfNo, Intf), s2a(IE), IfNo, A);
ie_v({IE, P, Intf, Grp}, IfNo, A) ->
    ie_v(IE, P, element(IfNo, Intf), Grp, IfNo, A).

msg_v(Msg, 'X', IfNo, Grp, V) ->
    IEsV = ie_v(IfNo, Grp),
    V#{Msg => IEsV};
msg_v(_Msg, _, _IfNo, _IEs, V) ->
    V.

msg_validation([], V) ->
    V;
msg_validation({_Id, Msg, Ifs, IEs}, V) ->
    lists:foldl(
      fun({IfNo, IfId}, V0) ->
	      V1 = maps:get(IfId, V0, #{}),
	      V2 = msg_v(s2a(Msg), element(IfNo, Ifs), IfNo, IEs, V1),
	      maps:put(IfId, V2, V0)
      end, V, [{1, 'Sxa'}, {2, 'Sxb'}, {3, 'Sxc'}, {4, 'N4'}]);
msg_validation([H|T], V) ->
    msg_validation(H, msg_validation(T, V)).

main(_) ->
    IEs = ies(),

    MsgDescription = string:join(
		       [io_lib:format("msg_description_v1(~s) -> <<\"~s\">>",
				      [s2a(X), X]) || {_, X, _, _} <- msgs()]
		       ++ ["msg_description_v1(X) -> io_lib:format(\"~p\", [X])"], ";\n") ++ ".\n",

    {FwdFuns, RevFuns} = gen_message_type(msgs(), {[], []}),
    ErrorFun = ["message_type_v1(Type) -> error(badarg, [Type])"],
    MTypes = string:join(FwdFuns ++ RevFuns ++ ErrorFun, ";\n") ++ ".\n",

    %%Records = string:join([write_record(X) || X <- IEs], "\n"),
    Records = string:join(collect(fun write_record/1, IEs, []), "\n"),
    HrlRecs = io_lib:format("%% -include(\"pfcp_packet_v1_gen.hrl\").~n~n~s", [Records]),
    Enums = write_enums(IEs),

    CatchAnyDecoder = ?DecoderFunName ++ "(Value, Tag) ->\n    {Tag, Value}",

    DecoderFns = lists:foldr(fun write_decoder/2, [CatchAnyDecoder], IEs),
    Funs = string:join(DecoderFns, ";\n\n"),

    CatchListEncoder = "encode_v1_element(IEs, Acc) when is_list(IEs) ->\n    encode_v1(IEs, Acc)",
    CatchAnyEncoder = "encode_v1_element({Tag, Value}, Acc) when is_binary(Value) ->\n    encode_tlv(Tag, Value, Acc)",
    EncoderFns = lists:foldr(fun write_encoder/2, [CatchListEncoder, CatchAnyEncoder], IEs),
    EncFuns = string:join(EncoderFns, ";\n\n"),

    CatchAnyPretty = "pretty_print_v1(_, _) ->\n    no",
    RecPrettyDefs = string:join([write_pretty_print("pretty_print_v1", X) || X <- IEs]
				++ [CatchAnyPretty] , ";\n"),

    Validate = string:replace(
		 io_lib:format("v1_msg_defs() ->~n    ~95p.~n", [msg_validation(msgs(), #{})]),
		 "        ", 9, all),

    ErlDecls = io_lib:format("%% -include(\"pfcp_packet_v1_gen.hrl\").~n~n~s~n~s~n~s~n~s.~n~n~s.~n~n~s.~n~n~s",
			     [MsgDescription, MTypes, Enums, Funs, EncFuns, RecPrettyDefs,
			     Validate]),

    {ok, HrlF0} = file:read_file("include/pfcp_packet.hrl"),
    [HrlHead, _] = binary:split(HrlF0, [<<"%% -include(\"pfcp_packet_v1_gen.hrl\").">>],[]),
    file:write_file("include/pfcp_packet.hrl", [HrlHead, HrlRecs]),

    {ok, ErlF0} = file:read_file("src/pfcp_packet.erl"),
    [ErlHead, _] = binary:split(ErlF0, [<<"%% -include(\"pfcp_packet_v1_gen.hrl\").">>],[]),
    file:write_file("src/pfcp_packet.erl", [ErlHead, ErlDecls]).
