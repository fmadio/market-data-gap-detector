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

local ProtoName = nil
local ProtoPort = nil
local ProtoDesc = nil

local i = 1
while (i <= #ARGV)do

	local c = ARGV[i]
	trace("%s\n", c)
	if (c == "--proto") then
		ProtoName = ARGV[i+1]
		i = i + 1
		trace("   Protocol Name: [%s]\n", ProtoName)
	end
	if (c == "--port") then
		ProtoPort = tonumber(ARGV[i+1])
		i = i + 1
		trace("   Protocol Port: %i\n", ProtoPort)
	end
	if (c == "--desc") then
		ProtoDesc = (ARGV[i+1])
		i = i + 1
		trace("   Protocol Description: [%s]\n", ProtoDesc)
	end
	if (c == "-v") then
		g_IsVerbose = 1
		trace("   Verbose Output\n") 
	end
	if (c == "-vv") then
		g_IsVerbose = 2
		trace("   Verbose Output Very\n") 
	end



	i = i + 1
end

-- check for valid protocol
if (ProtoName == nil) then

	trace("specify a protocol to use e.g\n")
	trace("./market_gap --proto ./omi/siac/Siac.Cts.Output.Cta.v1.91.h\n")
	return
end

-- default to name
if (ProtoDesc == nil) then ProtoDesc = ProtoName end

-- gap detection logic
require("lgap")

g_ProtocolList = {}
require("lOpenMarkets")

----------------------------------------------------------------------------------------------------------------------------
-- write even to syslog for ingest

local SyslogFacility = "local7.info"

Logger = function(Msg)

	-- write to syslog
	local JSON 	= Msg:gsub("\"", "\\\"")
	os.execute('/usr/local/bin/logger -t fmadio -p '..SyslogFacility..' "'..JSON..'"')

	-- optionaly print to screen
	if (g_IsVerbose ~= nil) then
		trace("%s\n", Msg)
		io.flush(io.stdout)
		io.flush(io.stderr)
	end
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


	local PCAPTotalByte	= 0
	local PCAPTotalPkt	= 0
	local PCAPTScale	= 0

	local pcap 			= io.stdin
	local _PCAPHeader 	= pcap:read(ffi.sizeof("PCAPHeader_t"))
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

			local UDPHeader = ffi_cast(Type_UDPHeader_t, IPHeader + 1) 

			-- dst ip
			local IPDst = string.format("%3i.%3i.%3i.%3i", IPHeader.Dst[0], IPHeader.Dst[1], IPHeader.Dst[2], IPHeader.Dst[3])

			-- dst port filter
			local PortDst = ffi.C.ffi_swap16(UDPHeader.PortDst)
			if (ProtoPort == nil) or (PortDst == ProtoPort) then 

				-- decode it
				local Session, SeqNo, Count, MsgTS, JStr = ProtoParser(UDPHeader + 1, Type_Decode)
				if (SeqNo ~= nil) then

					-- network flow 
					local Netflow = IPDst..":udp:"..PortDst

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
						local Msg = string.format([[{"timestamp":%.3f,"TS":"%s_%s",%s"SeqNo":%i,"Count":%i,"GapCnt":%i}]], tonumber(PCAPTS) / 1e9, os.formatDate(PCAPTS), os.formatTS(PCAPTS), JStr, SeqNo, Count, GapCnt) 
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
			local Msg = string.format([[{"module":"market-data-gap","subsystem":"status"        ,"timestamp":%.3f,]], tonumber(os.clock_ns()) / 1e9 ) 
			Msg = Msg .. string.format([["PCAPTime":"%s_%s","PCAPTS":%i,"Protocol":"%s","TotalByte":%i,"TotalPkt":%i,"TotalGap":%i,"TotalDrop":%i,]],

					os.formatDate(PCAPTS), 
					os.formatTS(PCAPTS), 
					tonumber(PCAPTS)/1e9,
					ProtoDesc,	
					PCAPTotalByte,	
					PCAPTotalPkt,	
					TotalGap,
					TotalDrop
			)

			Msg = Msg .. string.format([["MarketGap_bps":%i,"MarketGap_pps":%i,"MarketGap_mps":%i,"MarketGap_Lag":%i]],
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
