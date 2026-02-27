# NullSec PortWatch

Port scanner and service detector built with Erlang/OTP, demonstrating actor model patterns for security tools.

## Security Features

- **Immutable Data**: All Erlang data is immutable by default
- **Tagged Tuples**: `{ok, Result}` / `{error, Reason}` pattern
- **Pattern Matching**: Protocol and service identification
- **Actor Model**: gen_server for concurrent scanning
- **Supervisor Trees**: Fault-tolerant architecture
- **Hot Code Reload**: Update without stopping scans

## Capabilities

- TCP port scanning with configurable timeout
- 35+ known service signatures
- Banner grabbing and service fingerprinting
- Severity classification (Critical/High/Medium/Low)
- JSON output for automation
- Concurrent scanning with OTP processes

## Known Services

| Severity | Services |
|----------|----------|
| **Critical** | Metasploit (4444), Elite (31337), SubSeven, NetBus, ADB (5555) |
| **High** | Telnet, FTP, rlogin, rsh, RPC, NetBIOS, SMB |
| **Medium** | SSH, HTTP/S, DNS, MySQL, PostgreSQL, MongoDB, Redis, RDP, VNC |
| **Low** | POP3, IMAP, HTTP proxies |

## Installation

```bash
# Build with rebar3
rebar3 compile

# Create escript
rebar3 escriptize
```

## Usage

```bash
# Scan common ports
./portwatch 192.168.1.1

# Scan specific port
./portwatch 192.168.1.1 -p 22

# Scan port range
./portwatch 192.168.1.1 -p 1-1024

# Scan multiple ports
./portwatch 192.168.1.1 -p 22,80,443,3306

# JSON output
./portwatch 192.168.1.1 --json

# Custom timeout (ms)
./portwatch 192.168.1.1 -t 2000
```

## API Usage

```erlang
% Start the scanner
{ok, _} = portwatch:start_link().

% Scan a single port
{ok, Result} = portwatch:scan_port("192.168.1.1", 22).

% Scan a range
{ok, Results} = portwatch:scan_range("192.168.1.1", 1, 1024).

% Scan common ports
{ok, Results} = portwatch:scan_host("192.168.1.1").

% Get all results
AllResults = portwatch:get_results().

% Clear results
ok = portwatch:clear_results().

% Identify a service
Service = portwatch:identify_service(22, <<"SSH-2.0-OpenSSH">>).
```

## Result Structure

```erlang
#{
    host => "192.168.1.1",
    port => 22,
    state => open,           % open | closed | filtered
    service => #{
        name => "SSH",
        severity => medium,
        description => "Secure Shell"
    },
    banner => <<"SSH-2.0-OpenSSH_8.9">>,
    timestamp => {1706, 123456, 789012}
}
```

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Supervisor Tree                          │
├─────────────────────────────────────────────────────────────┤
│  ┌─────────────────────────────────────────────────────┐   │
│  │              portwatch (gen_server)                  │   │
│  │  ┌─────────────┐  ┌──────────────┐  ┌───────────┐  │   │
│  │  │ State:      │  │ scan_port/2  │  │ Services  │  │   │
│  │  │  - results  │  │ scan_range/3 │  │ Database  │  │   │
│  │  │  - stats    │  │ scan_host/1  │  │           │  │   │
│  │  └─────────────┘  └──────────────┘  └───────────┘  │   │
│  └─────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

## License

MIT License - Part of the NullSec Framework

## Author

- GitHub: [bad-antics](https://github.com/bad-antics)
- Twitter: [x.com/AnonAntics](https://x.com/AnonAntics)
