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
-- siac opra
g_ProtocolList["./omi/siac/siac.Opra.Recipient.Obi.v4.0.h"] = function()

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
