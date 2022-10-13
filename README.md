# FMADIO Open Market Data Gap Detector

The FMADIO Open Market Data Gap Detector leverages the Open Markets Initative to provide simple gap detection for market data protocols.  This will allow users to easily identify gaps in individual market data streams from an exchange and log when a gap in sequence number is present.  When paired with FMADIO best in class packet capture hardware with the ability to capture full line rate at 10Gbps, 25Gbps, 40Gbps and 100Gbps users will be able to analyze packets for supported market data protocols and identify any gaps without impacting the line rate capture processing.

[FMADIO Website](https://fmad.io)

[OMI Github](https://github.com/Open-Markets-Initiative)

## Performance

Baseline system parses a PCAP at around 1Gbps with a packet rate of about 1Mpps


## Options

```
FMADIO Market Data Gap Detector

Required:
  --proto <path to protocol>            : (required) specifies the protocol to code all incomming pcap data with

Optional:
  --port <port number>                  : filter a specific port number
  --desc "<text description>"         : provide a text descriptiong with gap JSON events
  --uid <uid number>                    : allows uniquie id to be associated with the process
  --timestamp <mode>                    : specify what value to put into the JSON timestamp field
                                        : "wall" - (default) use wall time
                                        : "pcap" -           timestamp from the pcap
  -v                                    : verbose output
  -vv                                   : very verbose  output

Example Usage:
  checks for market data gaps using CME MDP3 format

  cat cme.pcap | ./market_gap  --proto ./omi/cme/Cme.Futures.Mdp3.Sbe.v1.12.h --desc "CME MD Feed AB"

fmadio@fmadio100v2-228U:/mnt/store0/git/market_gap_20220924_rc1$
```


## Example Usage:

OPRA gap Detector 

```
lz4 -d -c /mnt/store1/cache/omi/20170926_OPERA_multicast_feed.pcap.lz4  | ./market_gap --proto ./omi/siac/Siac.Opra.Recipient.Obi.v4.0.h  --port 16117 --desc "OPRA Feed A"

```

CQS gap Detector 

```
lz4 -d -c /mnt/store1/cache/omi/20170926_CQS_multicast_feed.pcap.lz4  |  ./market_gap --proto ./omi/siac/Siac.cqs.Recipient.Obi.v4.0.h --desc "CQS Feed A"

```

CTS gap Detector 

```
lz4 -d -c /mnt/store1/cache/omi/20170926_CTS_multicast_feed.pcap.lz4  |  ./market_gap --proto ./omi/siac/Siac.cts.Recipient.Obi.v4.0.h --desc "CTS Feed A"

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

## NASDAQ TotalView ITCH March 9th 2020

One of the highest volume days on NASDAQ, 200GB with 1.7Bn packets. Total run time 34minutes for Full day processing A and B Feeds.


```
fmadio@fmadio100v2-228U:/mnt/store0/git/market_gap_20220830_rc1$ sudo stream_cat nasdaq_20220829_1521 | ./market_gap --proto ./omi/nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h
--proto
   Protocol Name: [./omi/nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h]
FMADIO Market Data Gap Detector
StartChunkID: 63845
StartChunk: 63845 Offset: 0 Stride: 1
StartChunk: 63845
PCAP Nano
     0.000GB    0.000M pcap:   112     25.600Mbps      0.025Mpps      0.200Mmps Gaps:       0 Drops:       0
     0.146GB    1.190M pcap:   112    816.140Mbps      0.831Mpps      7.078Mmps Gaps:       0 Drops:       0
     0.292GB    2.383M pcap:   112    816.368Mbps      0.832Mpps      7.094Mmps Gaps:       0 Drops:       0
     0.439GB    3.575M pcap:    95    817.341Mbps      0.832Mpps      7.117Mmps Gaps:       0 Drops:       0
     0.585GB    4.764M pcap:   112    817.383Mbps      0.832Mpps      7.128Mmps Gaps:       0 Drops:       0
     0.731GB    5.951M pcap:   112    817.225Mbps      0.831Mpps      7.140Mmps Gaps:       0 Drops:       0
     0.878GB    7.140M pcap:    95    817.979Mbps      0.831Mpps      7.146Mmps Gaps:       0 Drops:       0
     1.038GB    8.314M pcap:   116    828.348Mbps      0.829Mpps      7.105Mmps Gaps:       0 Drops:       0
     1.198GB    9.488M pcap:   126    836.874Mbps      0.828Mpps      7.061Mmps Gaps:       0 Drops:       0
     1.357GB   10.663M pcap:    95    842.300Mbps      0.827Mpps      7.039Mmps Gaps:       0 Drops:       0
     1.540GB   11.846M pcap:   302    860.337Mbps      0.827Mpps      7.516Mmps Gaps:       0 Drops:       0
     1.702GB   13.004M pcap:    99    864.400Mbps      0.826Mpps      7.717Mmps Gaps:       0 Drops:       0
     1.873GB   14.169M pcap:   112    871.976Mbps      0.825Mpps      7.999Mmps Gaps:       0 Drops:       0
     2.043GB   15.355M pcap:    95    877.975Mbps      0.825Mpps      8.209Mmps Gaps:       0 Drops:       0
     2.192GB   16.544M pcap:   112    874.541Mbps      0.825Mpps      8.165Mmps Gaps:       0 Drops:       0
     2.340GB   17.736M pcap:    95    871.654Mbps      0.826Mpps      8.129Mmps Gaps:       0 Drops:       0
     2.490GB   18.929M pcap:    99    869.297Mbps      0.826Mpps      8.103Mmps Gaps:       0 Drops:       0
     2.639GB   20.121M pcap:    95    867.435Mbps      0.827Mpps      8.088Mmps Gaps:       0 Drops:       0
     2.789GB   21.315M pcap:    95    865.554Mbps      0.827Mpps      8.064Mmps Gaps:       0 Drops:       0
     2.938GB   22.508M pcap:   112    863.917Mbps      0.827Mpps      8.045Mmps Gaps:       0 Drops:       0
     3.088GB   23.700M pcap:   111    862.676Mbps      0.828Mpps      8.035Mmps Gaps:       0 Drops:       0
     3.239GB   24.892M pcap:   112    861.820Mbps      0.828Mpps      8.035Mmps Gaps:       0 Drops:       0
     3.389GB   26.085M pcap:    99    860.688Mbps      0.828Mpps      8.024Mmps Gaps:       0 Drops:       0
     3.539GB   27.280M pcap:   112    859.575Mbps      0.828Mpps      8.011Mmps Gaps:       0 Drops:       0
     3.689GB   28.470M pcap:   112    858.734Mbps      0.828Mpps      8.007Mmps Gaps:       0 Drops:       0
     3.840GB   29.662M pcap:    95    858.141Mbps      0.829Mpps      8.008Mmps Gaps:       0 Drops:       0
     3.991GB   30.853M pcap:   170    857.484Mbps      0.829Mpps      8.006Mmps Gaps:       0 Drops:       0
     4.140GB   32.044M pcap:   112    856.734Mbps      0.829Mpps      8.001Mmps Gaps:       0 Drops:       0
     4.289GB   33.237M pcap:    95    855.839Mbps      0.829Mpps      7.986Mmps Gaps:       0 Drops:       0
     4.440GB   34.430M pcap:   112    855.442Mbps      0.829Mpps      7.989Mmps Gaps:       0 Drops:       0
     4.590GB   35.613M pcap:    95    854.827Mbps      0.829Mpps      7.987Mmps Gaps:       0 Drops:       0
.
.
.
.
.
.
.

   214.355GB 1668.720M pcap:    95    851.757Mbps      0.829Mpps      8.443Mmps Gaps:       0 Drops:       0
   214.511GB 1669.901M pcap:   111    851.771Mbps      0.829Mpps      8.443Mmps Gaps:       0 Drops:       0
   214.667GB 1671.083M pcap:   133    851.788Mbps      0.829Mpps      8.443Mmps Gaps:       0 Drops:       0
   214.823GB 1672.265M pcap:   126    851.802Mbps      0.829Mpps      8.443Mmps Gaps:       0 Drops:       0
   214.979GB 1673.445M pcap:    95    851.817Mbps      0.829Mpps      8.443Mmps Gaps:       0 Drops:       0
   215.135GB 1674.625M pcap:   126    851.830Mbps      0.829Mpps      8.443Mmps Gaps:       0 Drops:       0
   215.291GB 1675.801M pcap:   112    851.845Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   215.448GB 1676.979M pcap:    95    851.860Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   215.605GB 1678.158M pcap:   132    851.880Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   215.762GB 1679.337M pcap:   112    851.896Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   215.919GB 1680.515M pcap:    95    851.913Mbps      0.829Mpps      8.445Mmps Gaps:       0 Drops:       0
   216.074GB 1681.697M pcap:   455    851.925Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   216.229GB 1682.877M pcap:   112    851.934Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   216.385GB 1684.056M pcap:   126    851.950Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   216.539GB 1685.237M pcap:    95    851.955Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   216.694GB 1686.416M pcap:   150    851.965Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   216.849GB 1687.597M pcap:    95    851.973Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   217.004GB 1688.778M pcap:    95    851.985Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   217.161GB 1689.956M pcap:   112    852.001Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   217.318GB 1691.134M pcap:   112    852.018Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   217.474GB 1692.311M pcap:    95    852.031Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   217.628GB 1693.489M pcap:   171    852.039Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   217.783GB 1694.668M pcap:   112    852.047Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   217.937GB 1695.844M pcap:   112    852.054Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   218.093GB 1697.021M pcap:   126    852.069Mbps      0.829Mpps      8.444Mmps Gaps:       0 Drops:       0
   218.247GB 1698.200M pcap:    95    852.074Mbps      0.829Mpps      8.443Mmps Gaps:       0 Drops:       0
   218.400GB 1699.381M pcap:   289    852.076Mbps      0.829Mpps      8.443Mmps Gaps:       0 Drops:       0
   218.554GB 1700.558M pcap:   112    852.081Mbps      0.829Mpps      8.443Mmps Gaps:       0 Drops:       0
   218.707GB 1701.735M pcap:   112    852.081Mbps      0.829Mpps      8.443Mmps Gaps:       0 Drops:       0
   218.861GB 1702.913M pcap:   112    852.089Mbps      0.829Mpps      8.443Mmps Gaps:       0 Drops:       0
   219.014GB 1704.093M pcap:   133    852.090Mbps      0.829Mpps      8.442Mmps Gaps:       0 Drops:       0
   219.205GB 1705.267M pcap:    95    852.239Mbps      0.829Mpps      8.451Mmps Gaps:       0 Drops:       0
   219.356GB 1706.457M pcap:    95    852.233Mbps      0.829Mpps      8.451Mmps Gaps:       0 Drops:       0
packet stream end
20220902_073816 2060.271s : Pkt:1706519522 Byte:320102094 SUCCESS
Gap Summary (./omi/nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h)
--------------------------------------------------------------------------------------------------------------------------
    [233. 54. 12.111:udp:26477 000008792B] TotalMsg:1005353584 TotalGap:           TotalDrop:           TotalDup:         0 :
    [233. 54. 12. 40:udp:25475 000008792D] TotalMsg: 164630384 TotalGap:           TotalDrop:           TotalDup:         0 :
    [233. 54. 12.101:udp:26400 000008792B] TotalMsg:1005353585 TotalGap:           TotalDrop:           TotalDup:         0 :
--------------------------------------------------------------------------------------------------------------------------
Total Time: 2059.372677 sec (34.323 min)
fmadio@fmadio100v2-228U:/mnt/store0/git/market_gap_20220830_rc1$

```


## EUREX EOBI 

Both Incremental and Snapshot feeds using EOBI T7 latest

Incremental feed


```
fmadio@fmadio100v2-228U:/mnt/store0/git/market_gap_20220830_rc1$ cat xeur_59001.pcap   | ./market_gap  --proto ./omi/eurex/Eurex.Derivatives.Eobi.T7.v9.1.h
Setup
./market_gap
--proto
   Protocol Name: [./omi/eurex/Eurex.Derivatives.Eobi.T7.v9.1.h]
FMADIO Market Data Gap Detector
PCAP Nano
     0.000GB    0.000M pcap:    90     36.870Mbps      0.043Mpps      0.348Mmps Gaps:       0 Drops:       0
     0.154GB    1.010M pcap:   154    861.698Mbps      0.705Mpps      5.642Mmps Gaps:       0 Drops:       0
     0.322GB    2.092M pcap:   154    898.701Mbps      0.730Mpps      5.844Mmps Gaps:       0 Drops:       0
     0.477GB    3.093M pcap:   154    887.785Mbps      0.720Mpps      5.761Mmps Gaps:       0 Drops:       0
Gap Summary (./omi/eurex/Eurex.Derivatives.Eobi.T7.v9.1.h)
--------------------------------------------------------------------------------------------------------------------------
    [224.  0.114. 33:udp:59001 ] TotalMsg:   3372644 TotalGap:           TotalDrop:           TotalDup:         0 :
--------------------------------------------------------------------------------------------------------------------------
Total Time: 4.731946 sec (0.079 min)
fmadio@fmadio100v2-228U:/mnt/store0/git/market_gap_20220830_rc1$

```

Snapshot feed:


```
fmadio@fmadio100v2-228U:/mnt/store0/git/market_gap_20220830_rc1$ cat xeur_59000.pcap   | ./market_gap  --proto ./omi/eurex/Eurex.Derivatives.Eobi.T7.v9.1.h
Setup
./market_gap
--proto
   Protocol Name: [./omi/eurex/Eurex.Derivatives.Eobi.T7.v9.1.h]
FMADIO Market Data Gap Detector
PCAP Nano
     0.000GB    0.000M pcap:  1370    462.000Mbps      0.042Mpps      0.333Mmps Gaps:       0 Drops:       0
Gap Summary (./omi/eurex/Eurex.Derivatives.Eobi.T7.v9.1.h)
--------------------------------------------------------------------------------------------------------------------------
    [224.  0.114. 32:udp:59000 ] TotalMsg:    300000 TotalGap:           TotalDrop:           TotalDup:         0 :
--------------------------------------------------------------------------------------------------------------------------
Total Time: 0.886274 sec (0.015 min)
fmadio@fmadio100v2-228U:/mnt/store0/git/market_gap_20220830_rc1$
```


## CME MDP3 

MDP3 Sequence number checks


```
fmadio@fmadio100v2-228U:/mnt/store0/git/market_gap_20220830_rc1$ cat cme_mdp_snapshot.pcap    | ./market_gap  --proto ./omi/cme/Cme.Futures.Mdp3.Sbe.v1.9.h
Setup
./market_gap
--proto
   Protocol Name: [./omi/cme/Cme.Futures.Mdp3.Sbe.v1.9.h]
FMADIO Market Data Gap Detector
PCAP Nano
     0.000GB    0.000M pcap:   412    126.815Mbps      0.037Mpps      0.296Mmps Gaps:       0 Drops:       0
     0.120GB    0.082M pcap:  1280    668.593Mbps      0.057Mpps      0.460Mmps Gaps:     504 Drops:   82555
Gap Summary (./omi/cme/Cme.Futures.Mdp3.Sbe.v1.12.h)
-----------------------------------------------------------------------------------------------------------------------------------------------------------
    [233. 72. 75.  1:udp:23310 ] TotalMsg:    100000 TotalGap:           TotalDrop:           TotalDup:         0 TotalReset:     593 :
-----------------------------------------------------------------------------------------------------------------------------------------------------------
Total Time: 0.478509 sec (0.008 min)


Total Time: 1.726253 sec (0.029 min)
fmadio@fmadio100v2-228U:/mnt/store0/git/market_gap_20220830_rc1$
```




