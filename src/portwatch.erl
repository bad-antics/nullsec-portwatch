%%%-------------------------------------------------------------------
%%% @doc NullSec PortWatch - Port Scanner & Service Detector
%%%
%%% Erlang security tool demonstrating:
%%% - Pattern matching for protocol detection
%%% - Immutable data (all Erlang data is immutable)
%%% - Actor model with gen_server
%%% - Supervisor trees for fault tolerance
%%% - Tagged tuples for error handling
%%% - Hot code reloading capability
%%%-------------------------------------------------------------------
-module(portwatch).
-behaviour(gen_server).

%% API
-export([start_link/0, start_link/1]).
-export([scan_port/2, scan_port/3]).
-export([scan_range/3, scan_range/4]).
-export([scan_host/1, scan_host/2]).
-export([get_results/0, clear_results/0]).
-export([identify_service/2]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-define(SERVER, ?MODULE).
-define(DEFAULT_TIMEOUT, 1000).
-define(CONNECT_TIMEOUT, 500).

%%%===================================================================
%%% Type Definitions
%%%===================================================================

-type port_num() :: 1..65535.
-type ip_address() :: string() | inet:ip_address().
-type port_state() :: open | closed | filtered.
-type severity() :: critical | high | medium | low | info.

-type service_info() :: #{
    name := string(),
    severity := severity(),
    description := string()
}.

-type scan_result() :: #{
    host := ip_address(),
    port := port_num(),
    state := port_state(),
    service => service_info(),
    banner => binary(),
    timestamp := erlang:timestamp()
}.

-record(state, {
    results = [] :: [scan_result()],
    config = #{} :: map(),
    stats = #{scanned => 0, open => 0, closed => 0, filtered => 0} :: map()
}).

%%%===================================================================
%%% Known Services Database
%%%===================================================================

-spec known_services() -> [{port_num(), service_info()}].
known_services() ->
    [
        %% Critical - Remote Access & Backdoors
        {4444, #{name => "Metasploit", severity => critical, 
                 description => "Metasploit default handler"}},
        {31337, #{name => "Elite Backdoor", severity => critical,
                  description => "Classic hacker backdoor port"}},
        {27374, #{name => "SubSeven", severity => critical,
                  description => "SubSeven trojan"}},
        {12345, #{name => "NetBus", severity => critical,
                  description => "NetBus trojan"}},
        {5555, #{name => "Android ADB", severity => critical,
                 description => "Android Debug Bridge"}},
        
        %% High - Dangerous Services
        {23, #{name => "Telnet", severity => high,
               description => "Unencrypted remote access"}},
        {21, #{name => "FTP", severity => high,
               description => "File Transfer Protocol"}},
        {513, #{name => "rlogin", severity => high,
                description => "Remote login"}},
        {514, #{name => "rsh", severity => high,
                description => "Remote shell"}},
        {111, #{name => "RPC", severity => high,
                description => "RPC portmapper"}},
        {135, #{name => "MSRPC", severity => high,
                description => "Microsoft RPC"}},
        {139, #{name => "NetBIOS", severity => high,
                description => "NetBIOS Session"}},
        {445, #{name => "SMB", severity => high,
                description => "Server Message Block"}},
        
        %% Medium - Standard Services
        {22, #{name => "SSH", severity => medium,
               description => "Secure Shell"}},
        {25, #{name => "SMTP", severity => medium,
               description => "Mail Transfer"}},
        {53, #{name => "DNS", severity => medium,
               description => "Domain Name System"}},
        {80, #{name => "HTTP", severity => medium,
               description => "Web Server"}},
        {443, #{name => "HTTPS", severity => medium,
                description => "Secure Web Server"}},
        {3306, #{name => "MySQL", severity => medium,
                 description => "MySQL Database"}},
        {5432, #{name => "PostgreSQL", severity => medium,
                 description => "PostgreSQL Database"}},
        {27017, #{name => "MongoDB", severity => medium,
                  description => "MongoDB Database"}},
        {6379, #{name => "Redis", severity => medium,
                 description => "Redis Cache"}},
        {11211, #{name => "Memcached", severity => medium,
                  description => "Memcached"}},
        {3389, #{name => "RDP", severity => medium,
                 description => "Remote Desktop"}},
        {5900, #{name => "VNC", severity => medium,
                 description => "Virtual Network Computing"}},
        
        %% Low/Info - Common Services
        {110, #{name => "POP3", severity => low,
                description => "Post Office Protocol"}},
        {143, #{name => "IMAP", severity => low,
                description => "Internet Message Access"}},
        {993, #{name => "IMAPS", severity => low,
                description => "Secure IMAP"}},
        {995, #{name => "POP3S", severity => low,
                description => "Secure POP3"}},
        {8080, #{name => "HTTP-Proxy", severity => low,
                 description => "HTTP Proxy/Alt"}},
        {8443, #{name => "HTTPS-Alt", severity => low,
                 description => "Alternative HTTPS"}},
        {9050, #{name => "Tor SOCKS", severity => medium,
                 description => "Tor SOCKS Proxy"}},
        {9051, #{name => "Tor Control", severity => medium,
                 description => "Tor Control Port"}}
    ].

%%%===================================================================
%%% API
%%%===================================================================

start_link() ->
    start_link(#{}).

start_link(Config) ->
    gen_server:start_link({local, ?SERVER}, ?MODULE, Config, []).

%% @doc Scan a single port on a host
-spec scan_port(ip_address(), port_num()) -> {ok, scan_result()} | {error, term()}.
scan_port(Host, Port) ->
    scan_port(Host, Port, ?DEFAULT_TIMEOUT).

-spec scan_port(ip_address(), port_num(), pos_integer()) -> {ok, scan_result()} | {error, term()}.
scan_port(Host, Port, Timeout) ->
    gen_server:call(?SERVER, {scan_port, Host, Port, Timeout}, Timeout + 1000).

%% @doc Scan a range of ports
-spec scan_range(ip_address(), port_num(), port_num()) -> {ok, [scan_result()]}.
scan_range(Host, StartPort, EndPort) ->
    scan_range(Host, StartPort, EndPort, ?DEFAULT_TIMEOUT).

-spec scan_range(ip_address(), port_num(), port_num(), pos_integer()) -> {ok, [scan_result()]}.
scan_range(Host, StartPort, EndPort, Timeout) ->
    gen_server:call(?SERVER, {scan_range, Host, StartPort, EndPort, Timeout}, 
                    (EndPort - StartPort + 1) * Timeout + 5000).

%% @doc Scan common ports on a host
-spec scan_host(ip_address()) -> {ok, [scan_result()]}.
scan_host(Host) ->
    scan_host(Host, ?DEFAULT_TIMEOUT).

-spec scan_host(ip_address(), pos_integer()) -> {ok, [scan_result()]}.
scan_host(Host, Timeout) ->
    gen_server:call(?SERVER, {scan_host, Host, Timeout}, 60000).

%% @doc Get all scan results
-spec get_results() -> [scan_result()].
get_results() ->
    gen_server:call(?SERVER, get_results).

%% @doc Clear all results
-spec clear_results() -> ok.
clear_results() ->
    gen_server:cast(?SERVER, clear_results).

%% @doc Identify service on a port
-spec identify_service(port_num(), binary()) -> service_info() | undefined.
identify_service(Port, Banner) ->
    case lists:keyfind(Port, 1, known_services()) of
        {Port, Service} -> Service;
        false -> identify_by_banner(Banner)
    end.

%%%===================================================================
%%% gen_server callbacks
%%%===================================================================

init(Config) ->
    {ok, #state{config = Config}}.

handle_call({scan_port, Host, Port, Timeout}, _From, State) ->
    Result = do_scan_port(Host, Port, Timeout),
    NewState = update_state(Result, State),
    {reply, {ok, Result}, NewState};

handle_call({scan_range, Host, StartPort, EndPort, Timeout}, _From, State) ->
    Results = [do_scan_port(Host, P, Timeout) || P <- lists:seq(StartPort, EndPort)],
    NewState = lists:foldl(fun update_state/2, State, Results),
    OpenResults = [R || R <- Results, maps:get(state, R) =:= open],
    {reply, {ok, OpenResults}, NewState};

handle_call({scan_host, Host, Timeout}, _From, State) ->
    CommonPorts = [P || {P, _} <- known_services()],
    Results = [do_scan_port(Host, P, Timeout) || P <- CommonPorts],
    NewState = lists:foldl(fun update_state/2, State, Results),
    OpenResults = [R || R <- Results, maps:get(state, R) =:= open],
    {reply, {ok, OpenResults}, NewState};

handle_call(get_results, _From, State) ->
    {reply, State#state.results, State};

handle_call(_Request, _From, State) ->
    {reply, {error, unknown_request}, State}.

handle_cast(clear_results, State) ->
    {noreply, State#state{results = [], stats = #{scanned => 0, open => 0, closed => 0, filtered => 0}}};

handle_cast(_Msg, State) ->
    {noreply, State}.

handle_info(_Info, State) ->
    {noreply, State}.

terminate(_Reason, _State) ->
    ok.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

%%%===================================================================
%%% Internal functions
%%%===================================================================

-spec do_scan_port(ip_address(), port_num(), pos_integer()) -> scan_result().
do_scan_port(Host, Port, Timeout) ->
    HostStr = case Host of
        H when is_list(H) -> H;
        H when is_tuple(H) -> inet:ntoa(H)
    end,
    
    BaseResult = #{
        host => HostStr,
        port => Port,
        timestamp => os:timestamp()
    },
    
    case gen_tcp:connect(HostStr, Port, [binary, {active, false}], Timeout) of
        {ok, Socket} ->
            Banner = try_grab_banner(Socket),
            gen_tcp:close(Socket),
            Service = identify_service(Port, Banner),
            Result = BaseResult#{
                state => open,
                banner => Banner
            },
            case Service of
                undefined -> Result;
                S -> Result#{service => S}
            end;
        {error, econnrefused} ->
            BaseResult#{state => closed};
        {error, timeout} ->
            BaseResult#{state => filtered};
        {error, _} ->
            BaseResult#{state => filtered}
    end.

-spec try_grab_banner(gen_tcp:socket()) -> binary().
try_grab_banner(Socket) ->
    inet:setopts(Socket, [{active, false}]),
    case gen_tcp:recv(Socket, 0, ?CONNECT_TIMEOUT) of
        {ok, Data} -> Data;
        {error, _} -> <<>>
    end.

-spec identify_by_banner(binary()) -> service_info() | undefined.
identify_by_banner(<<>>) ->
    undefined;
identify_by_banner(Banner) ->
    BannerLower = string:lowercase(binary_to_list(Banner)),
    identify_banner_patterns(BannerLower).

identify_banner_patterns(Banner) ->
    Patterns = [
        {"ssh", #{name => "SSH", severity => medium, description => "SSH Server"}},
        {"openssh", #{name => "OpenSSH", severity => medium, description => "OpenSSH Server"}},
        {"dropbear", #{name => "Dropbear", severity => medium, description => "Dropbear SSH"}},
        {"http", #{name => "HTTP", severity => medium, description => "HTTP Server"}},
        {"apache", #{name => "Apache", severity => medium, description => "Apache HTTP"}},
        {"nginx", #{name => "Nginx", severity => medium, description => "Nginx HTTP"}},
        {"ftp", #{name => "FTP", severity => high, description => "FTP Server"}},
        {"vsftpd", #{name => "vsftpd", severity => high, description => "vsftpd FTP"}},
        {"proftpd", #{name => "ProFTPD", severity => high, description => "ProFTPD"}},
        {"mysql", #{name => "MySQL", severity => medium, description => "MySQL Server"}},
        {"mariadb", #{name => "MariaDB", severity => medium, description => "MariaDB Server"}},
        {"postgres", #{name => "PostgreSQL", severity => medium, description => "PostgreSQL"}},
        {"redis", #{name => "Redis", severity => medium, description => "Redis Server"}},
        {"mongodb", #{name => "MongoDB", severity => medium, description => "MongoDB"}},
        {"smtp", #{name => "SMTP", severity => medium, description => "Mail Server"}},
        {"postfix", #{name => "Postfix", severity => medium, description => "Postfix MTA"}},
        {"exim", #{name => "Exim", severity => medium, description => "Exim MTA"}}
    ],
    find_pattern(Banner, Patterns).

find_pattern(_Banner, []) ->
    undefined;
find_pattern(Banner, [{Pattern, Service} | Rest]) ->
    case string:find(Banner, Pattern) of
        nomatch -> find_pattern(Banner, Rest);
        _ -> Service
    end.

-spec update_state(scan_result(), #state{}) -> #state{}.
update_state(Result, #state{results = Results, stats = Stats} = State) ->
    PortState = maps:get(state, Result),
    NewStats = Stats#{
        scanned => maps:get(scanned, Stats) + 1,
        PortState => maps:get(PortState, Stats, 0) + 1
    },
    State#state{
        results = [Result | Results],
        stats = NewStats
    }.

%%%===================================================================
%%% CLI Interface
%%%===================================================================

-export([main/1]).

main(Args) ->
    application:start(sasl),
    {ok, _} = start_link(),
    
    case parse_args(Args) of
        {help} ->
            print_help();
        {scan, Host, Ports, Opts} ->
            run_scan(Host, Ports, Opts);
        {error, Reason} ->
            io:format("Error: ~s~n", [Reason]),
            print_help()
    end.

parse_args([]) ->
    {help};
parse_args(["--help" | _]) ->
    {help};
parse_args(["-h" | _]) ->
    {help};
parse_args([Host | Rest]) ->
    parse_scan_args(Host, Rest, #{json => false, timeout => ?DEFAULT_TIMEOUT}).

parse_scan_args(Host, [], Opts) ->
    {scan, Host, common, Opts};
parse_scan_args(Host, ["-p", PortSpec | Rest], Opts) ->
    Ports = parse_port_spec(PortSpec),
    parse_scan_args(Host, Rest, Opts#{ports => Ports});
parse_scan_args(Host, ["--json" | Rest], Opts) ->
    parse_scan_args(Host, Rest, Opts#{json => true});
parse_scan_args(Host, ["-j" | Rest], Opts) ->
    parse_scan_args(Host, Rest, Opts#{json => true});
parse_scan_args(Host, ["-t", Timeout | Rest], Opts) ->
    parse_scan_args(Host, Rest, Opts#{timeout => list_to_integer(Timeout)});
parse_scan_args(Host, [_ | Rest], Opts) ->
    parse_scan_args(Host, Rest, Opts).

parse_port_spec(Spec) ->
    case string:split(Spec, "-") of
        [Start, End] ->
            {range, list_to_integer(Start), list_to_integer(End)};
        [Single] ->
            case string:split(Single, ",", all) of
                [_] -> {single, list_to_integer(Single)};
                Ports -> {list, [list_to_integer(P) || P <- Ports]}
            end
    end.

run_scan(Host, Ports, Opts) ->
    Timeout = maps:get(timeout, Opts, ?DEFAULT_TIMEOUT),
    
    case maps:get(json, Opts, false) of
        false -> print_banner();
        true -> ok
    end,
    
    Results = case Ports of
        common ->
            {ok, R} = scan_host(Host, Timeout),
            R;
        {single, P} ->
            {ok, R} = scan_port(Host, P, Timeout),
            [R];
        {range, Start, End} ->
            {ok, R} = scan_range(Host, Start, End, Timeout),
            R;
        {list, PortList} ->
            lists:flatten([begin {ok, R} = scan_port(Host, P, Timeout), [R] end || P <- PortList])
    end,
    
    case maps:get(json, Opts, false) of
        true -> print_json(Results);
        false -> print_results(Results)
    end.

print_banner() ->
    io:format("~n"),
    io:format("╔══════════════════════════════════════════════════════════════════╗~n"),
    io:format("║             NullSec PortWatch - Port Scanner                     ║~n"),
    io:format("╚══════════════════════════════════════════════════════════════════╝~n"),
    io:format("~n").

print_help() ->
    io:format("~n"),
    io:format("╔══════════════════════════════════════════════════════════════════╗~n"),
    io:format("║             NullSec PortWatch - Port Scanner                     ║~n"),
    io:format("╚══════════════════════════════════════════════════════════════════╝~n"),
    io:format("~n"),
    io:format("USAGE:~n"),
    io:format("    portwatch <HOST> [OPTIONS]~n"),
    io:format("~n"),
    io:format("OPTIONS:~n"),
    io:format("    -h, --help          Show this help~n"),
    io:format("    -p <PORTS>          Port specification (single, range, or list)~n"),
    io:format("    -t <TIMEOUT>        Timeout in milliseconds (default: 1000)~n"),
    io:format("    -j, --json          Output as JSON~n"),
    io:format("~n"),
    io:format("EXAMPLES:~n"),
    io:format("    portwatch 192.168.1.1              Scan common ports~n"),
    io:format("    portwatch 192.168.1.1 -p 22        Scan single port~n"),
    io:format("    portwatch 192.168.1.1 -p 1-1024    Scan port range~n"),
    io:format("    portwatch 192.168.1.1 -p 22,80,443 Scan specific ports~n"),
    io:format("    portwatch 192.168.1.1 --json       JSON output~n"),
    io:format("~n").

print_results([]) ->
    io:format("No open ports found.~n");
print_results(Results) ->
    io:format("~nOpen Ports:~n"),
    io:format("~s~n", [string:copies("-", 70)]),
    lists:foreach(fun print_result/1, Results),
    io:format("~n").

print_result(#{state := open, port := Port, host := Host} = Result) ->
    Service = maps:get(service, Result, undefined),
    Banner = maps:get(banner, Result, <<>>),
    
    {Color, SevStr} = case Service of
        undefined -> {"\e[32m", "INFO"};
        #{severity := critical} -> {"\e[91m", "CRIT"};
        #{severity := high} -> {"\e[31m", "HIGH"};
        #{severity := medium} -> {"\e[33m", "MED "};
        #{severity := low} -> {"\e[36m", "LOW "};
        _ -> {"\e[32m", "INFO"}
    end,
    
    ServiceName = case Service of
        undefined -> "unknown";
        #{name := N} -> N
    end,
    
    io:format("~s[~s]\e[0m ~s:~p (~s)~n", [Color, SevStr, Host, Port, ServiceName]),
    
    case Banner of
        <<>> -> ok;
        _ -> 
            BannerStr = binary_to_list(Banner),
            CleanBanner = string:trim(BannerStr),
            case CleanBanner of
                "" -> ok;
                _ -> io:format("       └─ Banner: ~s~n", [string:slice(CleanBanner, 0, 60)])
            end
    end;
print_result(_) ->
    ok.

print_json(Results) ->
    OpenResults = [R || R <- Results, maps:get(state, R) =:= open],
    JsonResults = [result_to_json(R) || R <- OpenResults],
    io:format("{\"results\": [~s]}~n", [string:join(JsonResults, ",")]).

result_to_json(#{port := Port, host := Host} = Result) ->
    Service = maps:get(service, Result, #{}),
    ServiceName = maps:get(name, Service, "unknown"),
    Severity = atom_to_list(maps:get(severity, Service, info)),
    io_lib:format("{\"host\":\"~s\",\"port\":~p,\"service\":\"~s\",\"severity\":\"~s\"}", 
                  [Host, Port, ServiceName, Severity]).
