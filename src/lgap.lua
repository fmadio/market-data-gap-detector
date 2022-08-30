---------------------------------------------------------------------------------------------
--
-- Copyright (c) 2022, fmad engineering llc 
--
-- gap detection logic 
--
---------------------------------------------------------------------------------------------

local buffer 	= require("string.buffer")
local ffi 		= require("ffi")

----------------------------------------------------------------------------------------------------------------------------
-- gap detector

-- gap detector 
local g_SessionList			= {}
setmetatable(g_SessionList, {
__index = function(t, k)
	t[k] =
	{
		LastSeq 	= 0,
		MsgCnt 		= 0,
		GapCnt 		= 0,
		MsgDrop 	= 0,
	}
	return t[k]
end
})


----------------------------------------------------------------------------------------------------------------------------
-- basic gap detector for now
GapDetect = function(PCAPTS, PortDst, Session, ProtoDesc, SeqNo, MsgCnt)

	if (Session == nil) then return end

	local Key = "udp_"..PortDst.."_"..Session

	local S = g_SessionList[Key]
	if (S == nil) then return end

	local GapCnt 	= 0
	local DropCnt 	= 1

	local dSeq = SeqNo - S.LastSeq
	if (dSeq ~= 0) and (S.LastSeq ~= 0) then

		S.GapCnt	= S.GapCnt + 1
		S.MsgDrop	= S.MsgDrop + math.abs( tonumber(dSeq) ) 

		GapCnt 		= 1
		DropCnt		= math.abs(tonumber(dSeq))

		-- generate alert
		local AlertMsg = string.format([[{"module":"market-data-gap","subsystem":"gap"        ,"timestamp":%.3f,]], tonumber(os.clock_ns()) / 1e9 ) 

		AlertMsg = AlertMsg .. string.format([["PCAPTime":"%s_%s","PCAPTS":%i,"Protocol":"%s","Session":"%s","GapSize":%i,"SeqExpect":%i,"SeqFound":%i]],

				os.formatDate(PCAPTS), 
				os.formatTS(PCAPTS), 
				tonumber(PCAPTS)/1e9,
				ProtoDesc,	
				Key, 
				dSeq, 
				SeqNo, 
				S.LastSeq)

		AlertMsg = AlertMsg .. "}"		

		Logger(AlertMsg)
	end

	S.LastSeq 	= SeqNo    + MsgCnt
	S.MsgCnt	= S.MsgCnt + MsgCnt

	return GapCnt, DropCnt
end

