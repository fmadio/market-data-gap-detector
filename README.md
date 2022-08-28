# FMADIO Open Market Data Gap Detector
[FMADIO Website](https://fmad.io)




Example Usage:

OPERA gap Detector 


'''

lz4 -d -c /mnt/store1/cache/omi/20170926_OPERA_multicast_feed.pcap.lz4  |  ./market_gap --proto ./omi/siac.Opra.Recipient.Obi.v4.0.h --port 16117


'''

NASDAQ ITCH gap detector

'''
cat /mnt/store1/cache/omi/20200303_nasdaq_itch.pcap | ./market_gap  --proto ./omi/nasdaq/Nasdaq.Equities.TotalView.Itch.v5.0.h --port 26400  

'''

