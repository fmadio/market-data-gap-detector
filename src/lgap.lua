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
		NextSeq 	= 0,
		LastSeq 	= 0,
		MsgCnt 		= 0,
		GapCnt 		= 0,
		DupCnt 		= 0,
		DropCnt 	= 0,
		ResetCnt 	= 0,
	}
	return t[k]
end
})


----------------------------------------------------------------------------------------------------------------------------
-- basic gap detector for now
GapDetect = function(PCAPTS, FlowStr, Session, ProtoDesc, SeqNo, MsgCnt)

	if (Session == nil) then return end

	-- netflow + session string as the unique identifier
	local Key = FlowStr.." "..Session

	local S = g_SessionList[Key]
	if (S == nil) then return end
	
	-- for duplicate seq no ignore
	-- e.g. sending of the same message multiple times
	if (SeqNo == S.LastSeq) then 
		S.DupCnt = S.DupCnt + 1
		return  0,0
	end 

	-- calculate the seq gap
	local GapCnt 	= 0
	local DropCnt 	= 0

	local dSeq = SeqNo - S.NextSeq

	if (dSeq > 0) and (S.NextSeq ~= 0) then

		GapCnt 		= 1
		DropCnt		= math.abs(tonumber(dSeq))

		S.GapCnt	= S.GapCnt + 1
		S.DropCnt	= S.DropCnt + DropCnt 

		-- generate alert
		local AlertMsg = SyslogHeader("gap", PCAPTS) 
		AlertMsg = AlertMsg .. string.format([["PCAPTime":"%s_%s","PCAPtimestamp":%i,"Protocol":"%s","Session":"%s","GapSize":%i,"SeqExpect":%i,"SeqFound":%i]],

				os.formatDate(PCAPTS), 
				os.formatTS(PCAPTS), 
				tonumber(PCAPTS)/1e9,
				ProtoDesc,	
				Key, 
				dSeq, 
				S.NextSeq,
				SeqNo)

		AlertMsg = AlertMsg .. "}"		
		Logger(AlertMsg)

	-- count resets
	elseif (dSeq < 0) then

		S.ResetCnt	= S.ResetCnt + 1
	else
	end

	S.LastSeq 	= SeqNo
	S.NextSeq 	= SeqNo    + MsgCnt
	S.MsgCnt	= S.MsgCnt + MsgCnt

	return GapCnt, DropCnt
end

----------------------------------------------------------------------------------------------------------------------------
GapDump = function(Desc)

	trace("Gap Summary (%s)\n", Desc);
	trace("-----------------------------------------------------------------------------------------------------------------------------------------------------------\n");

	for Session,Info in pairs(g_SessionList) do

		local Status = "" 

		-- flag status for any drops 
		if (Info.GapCnt 	~= 0) then Status = "drop" end
		if (Info.DropCnt 	~= 0) then Status = "drop" end


		trace("    [%s] TotalMsg:%10i TotalGap:%10s TotalDrop:%10s TotalDup:%10i TotalReset:%8i : %s\n",
				Session,
				Info.MsgCnt,
				Info.GapCnt,
				Info.DropCnt,
				Info.DupCnt,
				Info.ResetCnt,
				Status
		)
	end
	trace("-----------------------------------------------------------------------------------------------------------------------------------------------------------\n");
end
