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

	return Parser
end

----------------------------------------------------------------------------------------------------
-- siac cqs 
g_ProtocolList["./omi/Siac.Cqs.Output.Cta.v1.91.h"] = function()

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
		--trace("%i %10i %i\n", Block.Version, bit.bswap(Block.BlockSequenceNumber), Block.MessagesInBlock)

		local Session	= "" 
		local SeqNo 	= bit.bswap(Block.BlockSequenceNumber)
		local Count 	= 1			-- meessage seq no is not correlated with the block seqno	 
		local TS 		= 0 

		return Session, SeqNo, Count, TS
	end

	return Parser
end


----------------------------------------------------------------------------------------------------
-- siac cts 
g_ProtocolList["./omi/Siac.Cts.Output.Cta.v1.91.h"] = function()

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
		--trace("%i %10i %i\n", Block.Version, bit.bswap(Block.BlockSequenceNumber), Block.MessagesInBlock)

		local Session	= "" 
		local SeqNo 	= bit.bswap(Block.BlockSequenceNumber)
		local Count 	= 1			-- meessage seq no is not correlated with the block seqno	 
		local TS 		= 0 

		return Session, SeqNo, Count, TS
	end

	return Parser
end

----------------------------------------------------------------------------------------------------
-- siac opra
g_ProtocolList["./omi/siac.Opra.Recipient.Obi.v4.0.h"] = function()

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
		local Count 	= 1			-- meessage seq no is not correlated with the block seqno	 
		local TS 		= 0 

		return Session, SeqNo, Count, TS
	end

	return Parser
end

----------------------------------------------------------------------------------------------------
