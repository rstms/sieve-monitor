# sieve-monitor

Scans for a directory named 'sieve_trace' in each user's home directory.
For any file matching the pattern `~/sieve_trace/*.trace`, the contents 
are emailed to the user as a message from "SIEVE_DAEMON".
After sending, the trace file is deleted.
