/* nt_txstat <port> : print "<txPkts> <txOctets>" for a Napatech port.
 * Built against the real NTAPI headers so struct layout is exact.
 * Used by test_ntacc.py to verify NtaccSocket actually transmits. */
#include <stdio.h>
#include <stdlib.h>
#include <nt.h>

int main(int argc, char **argv) {
    int port = (argc > 1) ? atoi(argv[1]) : 0;
    char errbuf[NT_ERRBUF_SIZE];
    int status;

    if ((status = NT_Init(NTAPI_VERSION)) != NT_SUCCESS) {
        NT_ExplainError(status, errbuf, sizeof(errbuf));
        fprintf(stderr, "NT_Init: %s\n", errbuf);
        return 2;
    }

    NtStatStream_t hStat;
    if ((status = NT_StatOpen(&hStat, "nt_txstat")) != NT_SUCCESS) {
        NT_ExplainError(status, errbuf, sizeof(errbuf));
        fprintf(stderr, "NT_StatOpen: %s\n", errbuf);
        return 2;
    }

    NtStatistics_t stat;
    stat.cmd = NT_STATISTICS_READ_CMD_QUERY_V4;
    stat.u.query_v4.poll = 1;   /* return current values */
    stat.u.query_v4.clear = 0;
    if ((status = NT_StatRead(hStat, &stat)) != NT_SUCCESS) {
        NT_ExplainError(status, errbuf, sizeof(errbuf));
        fprintf(stderr, "NT_StatRead: %s\n", errbuf);
        return 2;
    }

    printf("%llu %llu\n",
           (unsigned long long)stat.u.query_v4.data.port.aPorts[port].tx.RMON1.pkts,
           (unsigned long long)stat.u.query_v4.data.port.aPorts[port].tx.RMON1.octets);

    NT_StatClose(hStat);
    return 0;
}
