---------------------------------------------------------------------------------------------
--
-- Copyright (c) 2022, fmad engineering llc 
--
-- top level market data gap detector 
--
---------------------------------------------------------------------------------------------

local buffer 	= require("string.buffer")
local ffi 		= require("ffi")

local STP 		= require("StackTracePlus")			-- bett stack trace
debug.traceback = STP.stacktrace

local cpp		= require("lcpp")					-- pre processor 

ffi.cdef[[

	typedef uint64_t 		u64;
	typedef int64_t 		s64;

	typedef uint32_t 		u32;
	typedef int32_t 		s32;

	typedef uint16_t 		u16;
	typedef int16_t 		s16;

	typedef uint8_t 		u8;
	typedef int8_t 			s8;


	// pcap headers
	#define PCAPHEADER_MAGIC_NANO		0xa1b23c4d
	#define PCAPHEADER_MAGIC_USEC		0xa1b2c3d4
	#define PCAPHEADER_MAGIC_FMAD		0x1337bab3
	#define PCAPHEADER_MAJOR			2
	#define PCAPHEADER_MINOR			4
	#define PCAPHEADER_LINK_ETHERNET	1

	typedef struct fEther_t
	{
		u8		Dst[6];
		u8		Src[6];
		u16		Proto;

	} __attribute__((packed)) fEther_t;

	typedef struct
	{
		u32		HLen  	 : 4;
		u32		Version	 : 4;
		u32		Service	 : 8;
		u32		Len		 : 16;
		u16		Ident;
		u16		Frag;
		u8		TTL;
		u8		Proto;
		u16		CSum;

		u8		Src[4];
		u8		Dst[4];

	} __attribute__((packed)) IPv4Header_t;

	typedef struct
	{
		u16			VIDhi	: 4;
		u16			DEI		: 1;
		u16			PCP		: 3;
		u16			VIDlo	: 8;

		u16		 	Proto;		

	} __attribute__((packed)) VLANHeader_t;

	typedef struct
	{
		u32			L0		: 8; 	// label[19:12]	
		u32			L1		: 8; 	// label[11:4]	


		u32			BOS		: 1;	
		u32			TC		: 3;	

		u32			L2		: 4;	// label[3:0]	

		u32			TTL		: 8;	

	} __attribute__((packed)) MPLSHeader_t;

	typedef struct
	{

		u32				Magic;
		u16				Major;
		u16				Minor;
		u32				TimeZone;
		u32				SigFlag;
		u32				SnapLen;
		u32				Link;

	} __attribute__((packed)) PCAPHeader_t;


	// pcap

	typedef struct PCAPPacket_t
	{
		u32				Sec;					// time stamp sec since epoch 
		u32				NSec;					// nsec fraction since epoch

		u32				LengthCapture;			// captured length, inc trailing / aligned data
		u32				LengthWire; 			// length on the wire

	} __attribute__((packed)) PCAPPacket_t;

	typedef struct
	{
		u16			PortSrc;
		u16			PortDst;
		u16			Length;
		u16			CSum;

	} __attribute__((packed)) UDPHeader_t;


	typedef struct
	{
		u16			PortSrc;
		u16			PortDst;
		u32			SeqNo;
		u32			AckNo;
		u16			Flags;
		u16			Window;
		u16			CSUM;
		u16			Urgent;

	} __attribute__((packed)) TCPHeader_t;

	void* 	malloc(size_t size);
	void  	free  (void* );
    int 	usleep( unsigned long tm);

	u64 ffi_swap64		(u64 a);
	u32 ffi_swap32		(u32 a);
	u16 ffi_swap16		(u16 a);

	u64 ffi_rdtsc		(void);
	u64 ffi_clock_ns	(void);
]]

local swap64 		= ffi.C.ffi_swap64
local swap32 		= ffi.C.ffi_swap32
local swap16 		= ffi.C.ffi_swap16

local ffi_cast 		= ffi.cast
local ffi_string	= ffi.string

---------------------------------------------------------------------------------------------

function trace(Message, ...)

	local str = string.format(Message, table.unpack({...})) 
	os.trace( str)
end

---------------------------------------------------------------------------------------------
-- prints entire table in a single line 
function table.dump(t, desc, level)

	if (desc == nil) then desc = "" end
	if (t    == nil) then trace("[%-20s] NIL Table\n", desc); return end

	local l = {}
	for a,b in pairs(t) do  table.insert(l, {a = a, b = b}) end

	table.sort(l, function(a, b) return a.a < b.a end )

	for i, j in ipairs(l) do
		local a = j.a
		local b = j.b

		--str = str .. string.format("[%s] = %s |",  tostring(a), tostring(b) ) 
		trace("[%-20s] = (%s) (%s)\n", a, tostring(type(b)), tostring(b) )
	end
	trace("\n")
end

---------------------------------------------------------------------------------------------
-- prints entire table in a single line 
function table.dump_r(t, desc, level)

	if (desc  == nil) then desc = "" end
	if (t     == nil) then trace("%s: NIL Table\n", desc); return end
	if (level == nil) then level = 0 end

	local indent = ""
	for i=0,level-1 do indent = indent .. " " end

	local l = {}
	for a,b in pairs(t) do  table.insert(l, {a = a, b = b}) end

	table.sort(l, function(a, b) return a.a < b.a end )

	for i, j in ipairs(l) do

		local a = j.a
		local b = j.b

		--str = str .. string.format("[%s] = %s |",  tostring(a), tostring(b) ) 
		trace("%s:%s[%-20s] = (%s) (%s)\n", desc, indent, a, tostring(type(b)), tostring(b) )

		if (type(b) == "table") then
			table.dump_r(b, desc, level + 1)
		end
	end
	trace("\n")
end

---------------------------------------------------------------------------------------------

function string:split( inSplitPattern, outResults )

	outResults = outResults or { }

	local theStart = 1
	local theSplitStart, theSplitEnd = sfind( self, inSplitPattern, theStart )
	while theSplitStart do
		tinsert( outResults, ssub( self, theStart, theSplitStart-1 ) )
		theStart = theSplitEnd + 1
		theSplitStart, theSplitEnd = sfind( self, inSplitPattern, theStart )
	end

	tinsert( outResults, ssub( self, theStart ) )
	return outResults
end

-----------------------------------------------------------------------------------------------------------------------------------
-- remove any pre/post white space
function string:strip()
	return self:gsub("^%s*(.-)%s*$", "%1")
end

-----------------------------------------------------------------------------------------------------------------------------------
-- alpha numeric only
string.alphanumeric = function(s)

	if (s == nil) then return nil end

	local s1 = ffi.cast("u8*", s)

	for i=0,#s-1 do

		local a = s1[i]

		-- 0-9
		if (a >= 0x30) and (a <= 0x39) then

		-- A-Z
		elseif (a >= 0x41) and (a <= 0x5a) then 

		-- a-z
		elseif (a >= 0x61) and (a <= 0x7a) then 

		-- space
		elseif (a == 0x20) then 
		-- period
		elseif (a == 0x2e) then 
		-- dash 
		elseif (a == 0x2d) then 
		-- amp 
		elseif (a == 0x26) then a = 0x20
		-- left bracket 
		elseif (a == 0x28) then 
		-- right bracket
		elseif (a == 0x29) then 
		else
			-- replace with ??? 
			--trace("invalid char %x (%c)\n", a, a)
			a = 0x3f 
		end
		s1[i] = a
	end

	local s2 = ffi.string(s1)
	return s2 
end

function math.inverse(a)

	if (a == nil) then return 0 end
	if (a == 0) then return 0 end
	return 1.0 / a
end

os.clock_ns = function()

	return ffi.C.ffi_clock_ns()
end

-----------------------------------------------------------------------------------------------------------------------------------

help = function()

	trace("FMADIO Market Data Gap Detector\n")
	trace("\n")
	trace("Required:\n")
	trace("  --proto <path to protocol>            : (required) specifies the protocol to code all incomming pcap data with\n")
	trace("\n")
	trace("Optional:\n")
	trace("  --port <port number>                  : filter a specific port number\n") 
	trace("  --desc \"<text description>\"         : provide a text descriptiong with gap JSON events\n") 
	trace("  --uid <uid number>                    : allows uniquie id to be associated with the process\n") 
	trace("  --cpu <cpu number>                    : pin to a specific CPU number\n") 
	trace("  --timestamp <mode>                    : specify what value to put into the JSON timestamp field\n") 
	trace("  --location <desc>                     : add a location field into the syslog message output\n") 
	trace("                                        : \"wall\" - (default) use wall time\n") 
	trace("                                        : \"pcap\" -           timestamp from the pcap\n") 
	trace("  -v                                    : verbose output\n") 
	trace("  -vv                                   : very verbose  output\n") 
	trace("\n")
	trace("Example Usage:\n")
	trace("  checks for market data gaps using CME MDP3 format\n")
	trace("\n")
	trace("  cat cme.pcap | ./market_gap  --proto ./omi/cme/Cme.Futures.Mdp3.Sbe.v1.12.h --desc \"CME MD Feed AB\"\n") 
	trace("\n")

	os.exit(-1)

end

-----------------------------------------------------------------------------------------------------------------------------------

local ProtoName = nil
local ProtoPort = nil
local ProtoDesc = nil

local s_TimestampMode 	= "wall"				-- default use walltime for the timestamp field
local s_CPUPin			= nil					-- optionally pin to a specific CPU
local s_Location		= "" 					-- location field in the json

local i = 2
while (i <= #ARGV)do

	local c = ARGV[i]
	trace("%s\n", c)
	if (c == "--proto") then
		ProtoName = ARGV[i+1]
		i = i + 1
		trace("   Protocol Name: [%s]\n", ProtoName)

	elseif (c == "--port") then
		ProtoPort = tonumber(ARGV[i+1])
		i = i + 1
		trace("   Protocol Port: %i\n", ProtoPort)

	elseif (c == "--desc") then
		ProtoDesc = (ARGV[i+1])
		i = i + 1
		trace("   Protocol Description: [%s]\n", ProtoDesc)

	elseif (c == "-v") then
		g_IsVerbose = 1
		trace("   Verbose Output\n") 

	elseif (c == "-vv") then
		g_IsVerbose = 2
		trace("   Verbose Output Very\n") 

	elseif (c == "--uid") then
		local UID = ARGV[i+1];	
		trace("   UID [%s]\n", UID) 
		i = i + 1

	elseif (c == "--location") then
		local s_Location = ARGV[i+1];	
		trace("   Location [%s]\n", s_Location) 
		i = i + 1

	elseif (c == "--timestamp") then
		s_TimestampMode = ARGV[i+1];	
		trace("   TimestampMode [%s]\n", s_TimestampMode) 
		i = i + 1

	elseif (c == "--cpu") then
		s_CPUPin = tonumber(ARGV[i+1]);	
		trace("   CPU Pin [%s]\n", tostring(s_CPUPin) ) 
		i = i + 1
	else
		trace("Unkown Arg [%s]\n", ARGV[i])
		help()
	end


	i = i + 1
end

-- check for valid protocol
if (ProtoName == nil) then help() end

-- default to name
if (ProtoDesc == nil) then ProtoDesc = ProtoName end

-- gap detection logic
require("lgap")

g_ProtocolList = {}
require("lOpenMarkets")

----------------------------------------------------------------------------------------------------------------------------
-- write even to syslog for ingest

local SyslogFacility = "local7.info"

-- NOTE: assumes logger is in PATH
Logger = function(Msg)

	-- write to syslog
	local JSON 	= Msg:gsub("\"", "\\\"")
	os.execute('logger -t fmadio -p '..SyslogFacility..' "'..JSON..'"')

	-- optionaly print to screen
	if (g_IsVerbose ~= nil) then
		trace("%s\n", Msg)
		io.flush(io.stdout)
		io.flush(io.stderr)
	end
end

----------------------------------------------------------------------------------------------------------------------------
-- header for all syslog outputs
SyslogHeader = function(Subsystem, PCAPTS)

	local TS = 0 

	-- use wall time 
	if (s_TimestampMode == "wall") then
		TS = os.clock_ns()
	end

	-- optinally use the pcap time for the timestamp field
	if (s_TimestampMode == "pcap") then
		TS = PCAPTS or 0
	end

	local Msg  = string.format([[{"module":"market-data-gap","subsystem":"%s"        ,"timestamp":%i,"Location":"%s",]], 
			Subsystem,
			tonumber(TS) / 1e9,
			s_Location
	)
	return Msg
end

----------------------------------------------------------------------------------------------------------------------------

local DecodeProto = g_ProtocolList[ ProtoName ] 
if (DecodeProto == nil) then

	trace("Unable to find protcol [%s]\n", ProtoName)
	return
end

-- get parser
local ProtoParser = DecodeProto()



--**************************************************************************************************************************************
-- main decoder 
--**************************************************************************************************************************************
lmain = function()

	trace("FMADIO Market Data Gap Detector\n")

	-- optionaly pin a to a CPU
	if (s_CPUPin ~= nil) then
		trace("CPU Affinity %i\n", s_CPUPin) 
		os.cpu_affinity(s_CPUPin)
	end

	local PCAPTotalByte	= 0
	local PCAPTotalPkt	= 0
	local PCAPTScale	= 0

	local pcap 			= io.stdin
	local _PCAPHeader 	= pcap:read(ffi.sizeof("PCAPHeader_t"))
	if (_PCAPHeader == nil) then
		trace("*ERROR* Failed to read from STDIN\n")
		return
	end
	local PCAPHeader 	= ffi.cast("PCAPHeader_t*", _PCAPHeader)

	-- work out timescale 
	if (PCAPHeader.Magic ==  tonumber(ffi.lcpp_defs.PCAPHEADER_MAGIC_NANO)) then
		trace("PCAP Nano\n")
		PCAPTScale	= 1

	elseif (PCAPHeader.Magic ==  tonumber(ffi.lcpp_defs.PCAPHEADER_MAGIC_USEC)) then

		trace("PCAP usec\n")
		PCAPTScale	= 1000
	else
		trace("PCAP Unkonwn type:%x\n", PCAPHeader.Magic)
	end

	local TSStart = os.clock_ns()

	local Sizeof_PCAPPacket_t 	= ffi.sizeof("PCAPPacket_t")

	local Type_PCAPPacket_t 	= ffi.typeof("PCAPPacket_t*")
	local Type_UDPHeader_t 		= ffi.typeof("UDPHeader_t*")
	local Type_Payload_t 		= ffi.typeof("u8*")

	local TotalMsg				= 0
	local TotalGap				= 0
	local TotalDrop				= 0

	local NextStatusTSC			= 0

	while true do 

		-- read pcap header
		local _PktHeader = pcap:read(Sizeof_PCAPPacket_t)
		if (_PktHeader == nil) then break end

		local PktHeader = ffi_cast(Type_PCAPPacket_t, _PktHeader)

		local _PktPayload = pcap:read(PktHeader.LengthCapture)
		if (_PktPayload == nil) then break end
		local PktPayload = ffi_cast(Type_Payload_t, _PktPayload) 

		-- pcap timestamp
		local PCAPTS = PktHeader.Sec * 1000000000ULL + PktHeader.NSec

		-- ethernetheader
		local Ether 	= ffi.cast("fEther_t*", PktPayload)

		-- ip header (assuming)
		local Proto 	= ffi.C.ffi_swap16(Ether.Proto)
		local IPHeader 	= ffi.cast("IPv4Header_t*", Ether + 1)

		-- strip vlan tag
		if (Proto == 0x8100) then
		
			local VLAN = ffi.cast("VLANHeader_t*", Ether + 1)

			IPHeader = ffi.cast("IPv4Header_t*", VLAN + 1) 
		end

		-- udp header
		local DecodePayload = nil
		if (IPHeader.Proto == 0x11) then

			-- move to UDP header
			local UDPHeader = ffi_cast("UDPHeader_t*", ffi.cast("u8*", IPHeader) + IPHeader.HLen*4) 

			-- dst ip
			local IPDst = string.format("%3i.%3i.%3i.%3i", IPHeader.Dst[0], IPHeader.Dst[1], IPHeader.Dst[2], IPHeader.Dst[3])

			-- dst port filter
			local PortDst 	 	= ffi.C.ffi_swap16(UDPHeader.PortDst)
			local PayloadLength = ffi.C.ffi_swap16(UDPHeader.Length)

			if (ProtoPort == nil) or (PortDst == ProtoPort) then 

				-- network flow 
				local Netflow = string.format("%s:udp:%6i", IPDst, PortDst)

				-- decode it
				local Session, SeqNo, Count, MsgTS, JStr = ProtoParser(UDPHeader + 1, Type_Decode, PayloadLength, PCAPTS)
				if (SeqNo ~= nil) then

					-- check for gaps
					local GapCnt, DropCnt = GapDetect(PCAPTS, Netflow, Session, ProtoDesc, SeqNo, Count)

					-- update stats
					TotalMsg  = TotalMsg  + Count
					TotalGap  = TotalGap  + GapCnt
					TotalDrop = TotalDrop + DropCnt

					-- verbose output
					if (g_IsVerbose == 2) then

						if (JStr == nil) then JStr = "" 
						else JStr = JStr .. ","
						end
						local Msg = string.format([[{"timestamp":%i,"TS":"%s_%s",%s"SeqNo":%i,"Count":%i,"GapCnt":%i}]], tonumber(PCAPTS) / 1e9, os.formatDate(PCAPTS), os.formatTS(PCAPTS), JStr, SeqNo, Count, GapCnt) 
						print(Msg)
					end
				end
			end
		end

		-- top level stats
		PCAPTotalByte 	= PCAPTotalByte + Sizeof_PCAPPacket_t + PktHeader.LengthCapture
		PCAPTotalPkt 	= PCAPTotalPkt + 1

		-- print status info
		local TSC = ffi.C.ffi_rdtsc()
		if (TSC > NextStatusTSC) then

			NextStatusTSC = TSC + 3e9

			local TS  = os.clock_ns()
			local dT  = tonumber(TS - TSStart) / 1e9
			local pps = tonumber(PCAPTotalPkt) / dT
			local bps = tonumber(PCAPTotalByte) * 8.0 / dT
			local mps = tonumber(TotalMsg) * 8.0 / dT

			local Lag	= tonumber(TS) - tonumber(PCAPTS)

			-- write progress 
			local Msg = SyslogHeader("status", PCAPTS) 
			Msg = Msg .. string.format([["PCAPTime":"%s_%s","PCAPtimestamp":%i,"Protocol":"%s","TotalByte":%i,"TotalPkt":%i,"TotalGap":%i,"TotalDrop":%i,]],

					os.formatDate(PCAPTS), 
					os.formatTS(PCAPTS), 
					tonumber(PCAPTS)/1e9,
					ProtoDesc,	
					PCAPTotalByte,	
					PCAPTotalPkt,	
					TotalGap,
					TotalDrop
			)

			Msg = Msg .. string.format([["MarketGap_bps":%i,"MarketGap_pps":%i,"MarketGap_mps":%i,"MarketGap_Lag":%.6f]],
					bps,
					pps,
					mps,
					Lag / 1e9
			)

			Msg = Msg .. "}"		
			Logger(Msg)

			io.stderr:write(string.format("%10.3fGB %8.3fM pcap:%6i %10.3fMbps %10.3fMpps %10.3fMmps Gaps:%8i Drops:%8i\n", 	
																					PCAPTotalByte/1e9, 
																					tonumber(PCAPTotalPkt)/1e6, 
																					PktHeader.LengthCapture, 
																					bps/1e6, 
																					pps/1e6, 
																					mps/1e6,
																					TotalGap,
																					TotalDrop))
		end
	end

	-- dump gap stats
	GapDump(ProtoName)
end
