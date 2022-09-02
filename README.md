# FMADIO Open Market Data Gap Detector

The FMADIO Open Market Data Gap Detector leverages the Open Markets Initative to provide simple gap detection for market data protocols.  This will allow users to easily identify gaps in individual market data streams from an exchange and log when a gap in sequence number is present.  When paired with FMADIO best in class packet capture hardware with the ability to capture full line rate at 10Gbps, 25Gbps, 40Gbps and 100Gbps users will be able to analyze packets for supported market data protocols and identify any gaps without impacting the line rate capture processing.

[FMADIO Website](https://fmad.io)

[OMI Github](https://github.com/Open-Markets-Initiative)

## Performance

Baseline system parses a PCAP at around 1Gbps with a packet rate of about 1Mpps



## Example Usage:

OPRA gap Detector 

```
lz4 -d -c /mnt/store1/cache/omi/20170926_OPERA_multicast_feed.pcap.lz4  |  ./market_gap --proto ./omi/siac.Opra.Recipient.Obi.v4.0.h --port 16117 --desc "OPRA Feed A"

```

CQS gap Detector 

```
lz4 -d -c /mnt/store1/cache/omi/20170926_OPERA_multicast_feed.pcap.lz4  |  ./market_gap --proto ./omi/siac.cqs.Recipient.Obi.v4.0.h --port 16117 --desc "CQS Feed A"

```

CTS gap Detector 

```
lz4 -d -c /mnt/store1/cache/omi/20170926_OPERA_multicast_feed.pcap.lz4  |  ./market_gap --proto ./omi/siac.cts.Recipient.Obi.v4.0.h --port 16117 --desc "CTS Feed A"

```

NASDAQ ITCH gap detector

```
cat /mnt/store1/cache/omi/20200303_nasdaq_itch.pcap | ./market_gap  --proto ./omi/nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h --port 26400  --desc "NASDAQ ITCH Feed A"

```

## Syslog output


Example syslog output

For Gaps

```
{"module":"market-data-gap","subsystem":"gap"        ,"timestamp":1661829073.957,"PCAPTime":"2017.09.07_14:00:52.892.626.911","PCAPTS":1504792852,"Protocol":"OPRA Market FeedA","Session":"udp_17114_","GapSize":1,"SeqExpect":34165259,"SeqFound":34165258}
{"module":"market-data-gap","subsystem":"gap"        ,"timestamp":1661829073.961,"PCAPTime":"2017.09.07_14:00:52.893.482.781","PCAPTS":1504792852,"Protocol":"OPRA Market FeedA","Session":"udp_17114_","GapSize":1,"SeqExpect":34165300,"SeqFound":34165299}
{"module":"market-data-gap","subsystem":"gap"        ,"timestamp":1661829073.970,"PCAPTime":"2017.09.07_14:00:52.899.304.509","PCAPTS":1504792852,"Protocol":"OPRA Market FeedA","Session":"udp_17114_","GapSize":1,"SeqExpect":34165448,"SeqFound":34165447}
{"module":"market-data-gap","subsystem":"gap"        ,"timestamp":1661829074.027,"PCAPTime":"2017.09.07_14:00:52.945.526.748","PCAPTS":1504792852,"Protocol":"OPRA Market FeedA","Session":"udp_17114_","GapSize":1,"SeqExpect":34167342,"SeqFound":34167341}
{"module":"market-data-gap","subsystem":"gap"        ,"timestamp":1661829074.243,"PCAPTime":"2017.09.07_14:00:53.166.384.905","PCAPTS":1504792853,"Protocol":"OPRA Market FeedA","Session":"udp_17114_","GapSize":1,"SeqExpect":34171571,"SeqFound":34171570}
{"module":"market-data-gap","subsystem":"gap"        ,"timestamp":1661829074.349,"PCAPTime":"2017.09.07_14:00:53.241.933.792","PCAPTS":1504792853,"Protocol":"OPRA Market FeedA","Session":"udp_17114_","GapSize":1,"SeqExpect":34174629,"SeqFound":34174628}
{"module":"market-data-gap","subsystem":"gap"        ,"timestamp":1661829074.431,"PCAPTime":"2017.09.07_14:00:53.282.211.773","PCAPTS":1504792853,"Protocol":"OPRA Market FeedA","Session":"udp_17114_","GapSize":1,"SeqExpect":34177707,"SeqFound":34177706}
{"module":"market-data-gap","subsystem":"gap"        ,"timestamp":1661829075.291,"PCAPTime":"2017.09.07_14:00:54.035.130.307","PCAPTS":1504792854,"Protocol":"OPRA Market FeedA","Session":"udp_17114_","GapSize":1,"SeqExpect":34190873,"SeqFound":34190872}
{"module":"market-data-gap","subsystem":"gap"        ,"timestamp":1661829075.490,"PCAPTime":"2017.09.07_14:00:54.206.939.414","PCAPTS":1504792854,"Protocol":"OPRA Market FeedA","Session":"udp_17114_","GapSize":1,"SeqExpect":34195912,"SeqFound":34195911}
{"module":"market-data-gap","subsystem":"gap"        ,"timestamp":1661829075.907,"PCAPTime":"2017.09.07_14:00:54.691.991.120","PCAPTS":1504792854,"Protocol":"OPRA Market FeedA","Session":"udp_17114_","GapSize":1,"SeqExpect":34202028,"SeqFound":34202027}


{
  "module": "market-data-gap",
  "subsystem": "gap",
  "timestamp": 1661829074.349,
  "PCAPTime": "2017.09.07_14:00:53.241.933.792",
  "PCAPTS": 1504792853,
  "Protocol": "OPRA Market FeedA",
  "Session": "udp_17114_",
  "GapSize": 1,
  "SeqExpect": 34174629,
  "SeqFound": 34174628
}


```


For system monitoring 

```
{"module":"market-data-gap","subsystem":"status"        ,"timestamp":1661829075.175,"PCAPTime":"2017.09.07_14:00:53.916.619.658","PCAPTS":1504792853,"Protocol":"OPRA Market FeedA","TotalByte":455317486,"TotalPkt":3398572,"TotalGap":31,"TotalDrop":65848,"MarketGap_bps":1271890288,"MarketGap_pps":1186702,"MarketGap_mps":183940,"MarketGap_Lag":157036221}


{
  "module": "market-data-gap",
  "subsystem": "status",
  "timestamp": 1661829075.175,
  "PCAPTime": "2017.09.07_14:00:53.916.619.658",
  "PCAPTS": 1504792853,
  "Protocol": "OPRA Market FeedA",
  "TotalByte": 455317486,
  "TotalPkt": 3398572,
  "TotalGap": 31,
  "TotalDrop": 65848,
  "MarketGap_bps": 1271890288,
  "MarketGap_pps": 1186702,
  "MarketGap_mps": 183940,
  "MarketGap_Lag": 157036221
}

```
