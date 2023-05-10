---------------------------------------------------------------------------------------------
--
-- Copyright (c) 2022, fmad engineering llc 
--
-- Open Markets Gap detector 
--
---------------------------------------------------------------------------------------------

local ffi 			= require("ffi")
local bit 			= require("bit")

local ffi_cast 		= ffi.cast
local ffi_string	= ffi.string

----------------------------------------------------------------------------------------------------
-- nasdaq total view itch V5
g_ProtocolList["./omi/nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h"] = function()

	-- load header definitions 
	ffi.cdef('#include "./omi/nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h"')

	-- reference packet
	local RefPacket 	= ffi.new("PacketT")

	-- local accel 
	local Type_PacketT 	= ffi.typeof("PacketT*")

	-- constants 
	local Sizeof_Session = ffi.sizeof(RefPacket.PacketHeader.Session)

	-- actual parser to return id, seqno and msg cnt
	local Parser = function(_Payload, Type)
		
		local Payload 	= ffi_cast(Type_PacketT, _Payload) 

		local Session	= ffi_string(Payload.PacketHeader.Session, Sizeof_Session)
		local SeqNo 	= bit.bswap(Payload.PacketHeader.Sequence)
		local Count 	= bit.bor(bit.lshift( bit.band(Payload.PacketHeader.Count, 0xFF), 8), bit.rshift(Payload.PacketHeader.Count, 8))
		local TS 		= 0 

		return Session, SeqNo, Count, TS
	end 

	-- decode to json
	local Decode = function(_Payload, Type)
		
		local Payload 	= ffi_cast(Type_PacketT, _Payload) 

		local Session	= ffi_string(Payload.PacketHeader.Session, Sizeof_Session)
		local SeqNo 	= bit.bswap(Payload.PacketHeader.Sequence)
		local Count 	= bit.bor(bit.lshift( bit.band(Payload.PacketHeader.Count, 0xFF), 8), bit.rshift(Payload.PacketHeader.Count, 8))
		local TS 		= 0 
		local JStr		= nil

		local Offset	= 0

		local Base = ffi.cast("u8*", Payload + 1)
		for m=0,Count-1 do

			local Msg = ffi.cast("MessageT*", Base + Offset) 

			local Length = ffi.C.ffi_swap16(Msg.MessageHeader.Length)

			JStr = string.format([["MsgID":%i,"MsgLength":%i,"MsgType":"%c"]], 	m,
																						Length,
																						Msg.MessageHeader.MessageType
			)

			Offset = Offset + Length  + 2 
		end

		return Session, SeqNo, Count, TS, JStr
	end

	return Parser,Decode
end

----------------------------------------------------------------------------------------------------
-- siac cqs 
g_ProtocolList["./omi/siac/Siac.Cqs.Output.Cta.v1.91.h"] = function()

	-- load header definitions 
	ffi.cdef('#include "./omi/siac/Siac.Cqs.Output.Cta.v1.91.h"')

	-- reference packet
	local RefPacket 		= ffi.new("BlockHeaderT")

	-- local accel 
	local Type_BlockHeaderT = ffi.typeof("BlockHeaderT*")

	-- constants 

	-- actual parser to return id, seqno and msg cnt
	local Parser = function(_Payload, Type)
	
		local Block 	= ffi_cast(Type_BlockHeaderT, _Payload)

--[[
		local Message 	= ffi_cast("MessageT*", Block + 1)

		--trace("%i %10i %i\n", Block.Version, bit.bswap(Block.BlockSequenceNumber), Block.MessagesInBlock)
		trace("%i %8i %10i MsgCnt:%i retrans:%i FeedInd:%i CSum:%i nanos:%8i Type:%c\n", 
				Block.Version, 
				Block.BlockSize,
				bit.bswap(Block.BlockSequenceNumber), 
				Block.MessagesInBlock, 
				Block.RetransmissionIndicator, 
				Block.DataFeedIndicator[0], 
				Block.BlockChecksum,
				bit.bswap(Block.SipBlockTimestamp.Nanoseconds),
				Message.MessageHeader.MessageCategory	
				)
]]
		local Session	= "" 
		local SeqNo 	= bit.bswap(Block.BlockSequenceNumber)
		local Count 	= Block.MessagesInBlock 
		local TS 		= 0 

		return Session, SeqNo, Count, TS
	end

	local Decode = function(_Payload, Type)
	end

	return Parser, Decode
end


----------------------------------------------------------------------------------------------------
-- siac cts 
g_ProtocolList["./omi/siac/Siac.Cts.Output.Cta.v1.91.h"] = function()

	-- load header definitions 
	ffi.cdef('#include "./omi/siac/Siac.Cts.Output.Cta.v1.91.h"')

	-- reference packet
	local RefPacket 		= ffi.new("BlockHeaderT")

	-- local accel 
	local Type_BlockHeaderT = ffi.typeof("BlockHeaderT*")
	local Type_MessageT 	= ffi.typeof("MessageT*")

	-- constants 


	-- actual parser to return id, seqno and msg cnt
	local Parser = function(_Payload, Type)
	
		local Block 	= ffi_cast(Type_BlockHeaderT, _Payload)
	
		--[[
		local Message 	= ffi_cast(Type_MessageT, Block + 1)

		-- drop line status check message "C" as this may arrive out of order
		if (Message.MessageHeader.MessageCategory == 0x43) then return nil end

		--trace("%i %10i %i\n", Block.Version, bit.bswap(Block.BlockSequenceNumber), Block.MessagesInBlock)
		trace("Version:%i Size:%8i SeqNo:%10i MsgCnt:%i retrans:%i FeedInd:%i CSum:%i nanos:%8i Type:%c\n", 
				Block.Version, 
				Block.BlockSize,
				bit.bswap(Block.BlockSequenceNumber), 
				Block.MessagesInBlock, 
				Block.RetransmissionIndicator, 
				Block.DataFeedIndicator[0], 
				Block.BlockChecksum,
				bit.bswap(Block.SipBlockTimestamp.Nanoseconds),
				Message.MessageHeader.MessageCategory	
				)
		]]	

		local Session	= "" 
		local SeqNo 	= bit.bswap(Block.BlockSequenceNumber)
		local Count 	= Block.MessagesInBlock 
		local TS 		= 0 

		return Session, SeqNo, Count, TS
	end

	local Decode = function(_Payload, Type)
	end

	return Parser, Decode
end

----------------------------------------------------------------------------------------------------
-- siac opra
g_ProtocolList["./omi/siac/Siac.Opra.Recipient.Obi.v4.0.h"] = function()

	-- load header definitions 
	ffi.cdef('#include "./omi/siac/Siac.Opra.Recipient.Obi.v4.0.h"')

	-- reference packet
	local RefPacket 		= ffi.new("BlockHeaderT")

	-- local accel 
	local Type_BlockHeaderT = ffi.typeof("BlockHeaderT*")

	-- constants 


	-- actual parser to return id, seqno and msg cnt
	local Parser = function(_Payload, Type)
	
		local Block 	= ffi_cast(Type_BlockHeaderT, _Payload)
		--trace("%i %10i %i\n", Block.Version, bit.bswap(Block.BlockSequenceNumber), Block.MessagesInBlock)

		local Session	= "" 
		local SeqNo 	= bit.bswap(Block.BlockSequenceNumber)
		local Count 	= Block.MessagesInBlock 
		local TS 		= 0 

		return Session, SeqNo, Count, TS
	end

	local Decode = function(_Payload, Type)
	end

	return Parser,Decode
end

----------------------------------------------------------------------------------------------------
-- Eurex Derivaties 
g_ProtocolList["./omi/eurex/Eurex.Derivatives.Eobi.T7.v9.1.h"] = function()

	-- load header definitions 
	ffi.cdef('#include "./omi/eurex/Eurex.Derivatives.Eobi.T7.v9.1.h"')

	-- local accel 
	local Type_PacketT = ffi.typeof("PacketT*")

	-- constants 

	-- actual parser to return id, seqno and msg cnt
	local Parser = function(_Payload, Type)

		local Packet 	= ffi_cast(Type_PacketT, _Payload)
		local Header 	= Packet.PacketHeader 
		local Info 		= Header.PacketInfo

		local Session	= ""
		local SeqNo		= Header.ApplSeqNum
		local Count		= 1 
		local TS		= tonumber(Header.TransactTime)

		--print(string.format("seq: %i segment:%i part:%i TS:%i\n", Header.ApplSeqNum, Header.MarketSegmentId, Header.PartitionId, TS)) 
 
		return Session, SeqNo, Count, TS
	end

	local Decode = function(_Payload, Type)
	end

	return Parser,Decode
end


----------------------------------------------------------------------------------------------------
-- CME MDP
--
-- https://www.cmegroup.com/confluence/display/EPICSANDBOX/MDP+3.0+-+SBE+Technical+Headers
--
g_ProtocolList["./omi/cme/Cme.Futures.Mdp3.Sbe.v1.12.h"] = function()

	-- load header definitions 
	ffi.cdef('#include "./omi/cme/Cme.Futures.Mdp3.Sbe.v1.12.h"')

	-- local accel 
	local Type_u8 			= ffi.typeof("u8*")

	local Type_PacketT 		= ffi.typeof("PacketT*")
	local Sizeof_PacketT 	= ffi.sizeof("PacketT")

	local Type_MessageT 	= ffi.typeof("MessageT*")
	local Sizeof_MessageT 	= ffi.typeof("MessageT")


	-- constants 

	-- actual parser to return id, seqno and msg cnt
	local Parser = function(_Payload, Type, Length)

		local Payload	= ffi_cast(Type_u8, _Payload)

		local Packet 	= ffi_cast(Type_PacketT, _Payload)

		--print(string.format("%8i %i", Packet.BinaryPacketHeader.MessageSequenceNumber, tonumber(Packet.BinaryPacketHeader.SendingTime)))

		local Session	= ""
		local SeqNo		= Packet.BinaryPacketHeader.MessageSequenceNumber
		local Count		= 1 
		local TS		= tonumber(Packet.BinaryPacketHeader.SendingTime)

		-- iterate thru each message
		--[[
		local Offset	= Sizeof_PacketT
		while (Length - Offset > Sizeof_MessageT) do

			local Message	 = ffi_cast(Type_MessageT, Payload + Offset) 

			local TemplateID = Message.MessageHeader.TemplateId
			--print(string.format("%12i %8i : %8i %8i id:%i", SeqNo, Message.MessageSize, Offset, Length, TemplateID));

			if (TemplateID == 52) then

				local Snapshot 	= ffi.cast("SnapshotFullRefreshT*", Message + 1) 
				print(string.format("        refresh:%12i %12i %8i symbol:%i", Snapshot.LastMsgSeqNumProcessed, Snapshot.RptSeq, Snapshot.TotNumReports, Snapshot.SecurityId))

				Session	= string.format("%08i", Snapshot.SecurityId)
			end

			if (TemplateID == 53) then
				local Snapshot = ffi.cast("SnapshotFullRefreshOrderBookT*", Message + 1) 
				print(string.format("     update book %i security:%i %i/%i", Snapshot.LastMsgSeqNumProcessed, Snapshot.SecurityId, Snapshot.CurrentChunk, Snapshot.NoChunks))
			end

			Offset = Offset + Message.MessageSize + Sizeof_MessageT
		end
		]]
 
		return Session, SeqNo, Count, TS
	end

	local Decode = function(_Payload, Type)
	end

	return Parser,Decode
end

----------------------------------------------------------------------------------------------------
-- LSE MITCH v11.9 
--
--https://www.cmegroup.com/confluence/display/EPICSANDBOX/MDP+3.0+-+SBE+Technical+Header://docs.londonstockexchange.com/sites/default/files/documents/mit303issue119.pdf 
--
-- port config https://docs.londonstockexchange.com/sites/default/files/documents/gtp_004_parameters_guide_issue20.3.pdf
--
-- Level1          - port 60400
-- Level2 MBO      - port 60400
-- Level2 MBP      - port 60400
-- Level2 Inc      - port 60400
-- MBIF Post Trade - port 60400
--
-- seems onhly port 60400 has MITCH data, can drop all other ports
--
g_ProtocolList["./omi/lse/Lse.Millennium.Level2.Mitch.v11.9.h"] = function()

	-- load header definitions 
	ffi.cdef('#include "./omi/lse/Lse.Millennium.Level2.Mitch.v11.9.h"')

	-- local accel 
	local Type_u8 			= ffi.typeof("u8*")

	local Type_PacketT 		= ffi.typeof("PacketT*")
	local Sizeof_PacketT 	= ffi.sizeof("PacketT")

	-- constants 

	-- actual parser to return id, seqno and msg cnt
	local Parser = function(_Payload, Type, Length, PCAPTS)

		local Payload	= ffi_cast(Type_u8, _Payload)

		local Packet 	= ffi_cast(Type_PacketT, _Payload)

		local SeqNo		= Packet.UnitHeader.SequenceNumber 
		local Count		= Packet.UnitHeader.MessageCount
		local TS		= 0			-- nee to track seconds and message type 
		local Session	= string.format("%c", Packet.UnitHeader.MarketDataGroup[0])

	
		if (g_IsVerbose ~= nil) then
			print(string.format("[%s] : Seq:%16i Len:%5i MsgCnt:%i Group:%c", 
					 	tostring(PCAPTS),
						Packet.UnitHeader.SequenceNumber, 
						Packet.UnitHeader.Length, 
						Packet.UnitHeader.MessageCount,
						Packet.UnitHeader.MarketDataGroup[0]
			))
		end
	 
		return Session, SeqNo, Count, TS
	end

	local Decode = function(_Payload, Type)
	end

	return Parser,Decode
end

----------------------------------------------------------------------------------------------------
-- Euronext 4.13 Market data 
--
-- port config https://connect2.euronext.com/sites/default/files/it-documentation/Euronext%20Optiq%20Market%20Data%20Gateway%20Production%20Environment%20v2.3.pdf 
--
-- 10130 - REFT 100M 
-- 10135 - FBOU 10G (FUNDS?)
--
-- Italy
-- 10057 - FBOU 10G
--
g_ProtocolList["./omi/euronext/Euronext.Optiq.MarketDataGateway.Sbe.v4.13.h"] = function()

	-- load header definitions 
	ffi.cdef('#include "./omi/euronext/Euronext.Optiq.MarketDataGateway.Sbe.v4.13.h"')

	-- local accel 
	local Type_u8 			= ffi.typeof("u8*")

	local Type_PacketT 		= ffi.typeof("PacketT*")
	local Sizeof_PacketT 	= ffi.sizeof("PacketT")

	-- constants 

	-- actual parser to return id, seqno and msg cnt
	local Parser = function(_Payload, Type, Length, PCAPTS)

		local Payload	= ffi_cast(Type_u8, _Payload)

		local Packet 	= ffi_cast(Type_PacketT, _Payload)


		local MDHeader 	= Packet.MarketDataPacketHeader;

		local SeqNo		= MDHeader.PacketSequenceNumber
		local Count		= 1 
		local TS		= MDHeader.PacketTime;
		local Session	= string.format("%i", MDHeader.ChannelId) 

	
		if (g_IsVerbose ~= nil) then
			print(string.format("[%s] : Seq:%16i TS:%i Channel:%i", 
					 	tostring(PCAPTS),
						MDHeader.PacketSequenceNumber,
						MDHeader.PacketTime,
						MDHeader.ChannelId
			))
		end
	 
		return Session, SeqNo, Count, TS
	end

	local Decode = function(_Payload, Type)
	end

	return Parser,Decode
end


----------------------------------------------------------------------------------------------------
