# iSniff

iSniff is a command line tool that interfaces with the built-in packet capture capabilities of iOS 5+ devices. 

iSniff outputs a raw packet trace in pcap format which can then be used to save to a file or piped to other commonly used packet capture software.

## Usage

```
Usage: isniff [OPTIONS] [PCAPFILE]
Capture packets on a connected iDevice.

  If PCAPFILE is passed, write the raw packets to file
  rather than writing to STDOUT.

  -u, --udid UDID       Target specific device by its 40-digit device UDID.
  -l, --list            list UDID of all attached devices
  -h, --help            prints usage information
  -d, --debug           enable communication debugging
```

## Getting Started

By default iSniff will connect to the first connected device it finds and output the raw pcap data to *stdout*. This may not seem very useful but it allows easy use of the data in whatever tool you are most fluent with.

The easiest way to get started is to simply capture all packets on a connected iDevice to a pcap file:

```
isniff capture.pcap
```

This will start the packet capture service on the connected iDevice and start capturing all network to `capture.pcap`. To stop capturing packets signal the program to stop with `Ctrl+C`. iSniff will then flush the capture to disk and close.

### Using iSniff with tcpdump

This is nice but what if you want to monitor the capture in real-time? Normally the goto command line packet capture program is `tcpdump` a lightweight but feature packed packet sniffer based on libpcap. To use `tcpdump` like you normally would, simply pipe the output of iSniff to `tcpdump` with the flags `-r-`:

```
isniff | tcpdump -r-
```

`tcpdump` will then start logging the packets as they are received as if you had have just called `tcpdump` on the iDevice itself!

### Using iSniff with Wireshark

The same principle above applies to any packet tracing or capture program that can parse pcap-format packet captures from *stdin*. To view a live capture in Wireshark simply start it with the following command and flags:

```
isniff | wireshark -Ski-
```

This will start Wireshark and display packets as they are captured.