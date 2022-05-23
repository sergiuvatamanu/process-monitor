# Process Monitor

A simple process monitor that emulates the native windows resource monitor.

For each process that constitutes a TCP or UDP endpoint, shows the source and remote communication addresses and ports, and the transfer speed.

To find out process details, the application uses Windows' [IP Helper](https://docs.microsoft.com/en-us/windows/win32/api/_iphlp/). To compute the transfer speed, libpcap([npcap implementation](https://npcap.com/)) has been used. Multiple packets are matched to their process source and destination ports, and the sum of their lengths is averaged over time.
