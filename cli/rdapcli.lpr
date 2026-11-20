program rdapcli;

{$mode objfpc}{$H+}

uses
  SysUtils, rdapclient
  {$IFDEF MSWINDOWS}, Windows{$ENDIF};

const
  // Fallback base URL when the IANA bootstrap files are not available.
  DefaultBaseURL = 'https://rdap.org/';
  // Exit codes: ok / not found / rate limited / everything else.
  ExitOK = 0;
  ExitNotFound = 1;
  ExitRateLimited = 2;
  ExitError = 3;

type
  { Parsed command line of the utility. }
  TCLIOptions = record
    Query: string;         // the first positional argument
    QueryType: TRDAPQueryType;
    Raw: Boolean;
    BootstrapDir: string;  // '' = current directory
    ProxyHost: string;
    ProxyPort: Integer;
    ProxyUser: string;
    ProxyPass: string;
  end;

{$IFDEF MSWINDOWS}
type
  { Return type of CommandLineToArgvW: an array of PWideChar, NULL-terminated. }
  PWArgv = ^PWideChar;

// Declared locally: the FPC 3.2.2 Windows unit does not expose
// CommandLineToArgvW (and GetCommandLineW is shadowed deliberately to pin
// the exact signature).
function GetCommandLineW: PWideChar; stdcall; external 'kernel32' name 'GetCommandLineW';
function CommandLineToArgvW(lpCmdLine: PWideChar; var pNumArgs: Integer): PWArgv; stdcall;
  external 'shell32' name 'CommandLineToArgvW';

var
  OldOutputCP: Cardinal;
  GParams: array of string; // UTF-8 command line, see InitParams
  GParamsReady: Boolean = False;

// FPC's ParamStr on Windows parses the ANSI command line (GetCommandLineA):
// non-ASCII arguments go through the system ANSI codepage and are mangled on
// hosts whose ACP cannot represent them (cp1252 turns Cyrillic into '?').
// RDAP queries are international, so the wide command line is parsed here and
// each argument is converted to UTF-8 - the library contract. The conversion
// runs after the rdapclient initialization, which already set
// DefaultSystemCodePage to CP_UTF8, so it is lossless.
procedure InitParams;
var
  WCmd: PWideChar;
  WArgs: PWArgv;
  N, I: Integer;
begin
  WCmd := GetCommandLineW;
  if WCmd = nil then
    Exit;
  N := 0;
  WArgs := CommandLineToArgvW(WCmd, N);
  if (WArgs = nil) or (N < 1) then
    Exit;
  SetLength(GParams, N);
  for I := 0 to N - 1 do
    GParams[I] := WArgs[I];
  GParamsReady := True;
  // The argv array itself is not freed (LocalFree): a single allocation that
  // lives until process exit, reclaimed by the OS.
end;

// Command line accessors over the UTF-8 parameters (the wide command line on
// Windows, the RTL ParamStr elsewhere).
function CParamCount: Integer;
begin
  if GParamsReady then
    Result := Length(GParams) - 1
  else
    Result := ParamCount;
end;

function CParamStr(AIndex: Integer): string;
begin
  if GParamsReady then
    Result := GParams[AIndex]
  else
    Result := ParamStr(AIndex);
end;
{$ENDIF}

{$IFNDEF MSWINDOWS}
function CParamCount: Integer;
begin
  Result := ParamCount;
end;

function CParamStr(AIndex: Integer): string;
begin
  Result := ParamStr(AIndex);
end;
{$ENDIF}

// Notices and diagnostics: stderr, so stdout stays parseable and in --raw
// mode contains exactly the response body (ready for redirection to a file).
procedure Diag(const S: string);
begin
  Writeln(ErrOutput, S);
end;

// Usage error: message plus a hint on stderr. The caller sets ExitCode.
procedure UsageError(const AMsg: string);
begin
  Writeln(ErrOutput, 'Error: ', AMsg);
  Writeln(ErrOutput, 'Usage: rdapcli [options] <query>');
  Writeln(ErrOutput, 'Run "rdapcli --help" for usage.');
end;

function QueryTypeName(AType: TRDAPQueryType): string;
begin
  case AType of
    rqtIP: Result := 'ip';
    rqtAutNum: Result := 'autnum';
    rqtEntity: Result := 'entity';
  else
    Result := 'domain';
  end;
end;

// Human-readable status of the last query (the enum names rqsOK etc. are
// library jargon, the CLI spells them out).
function StatusText(AStatus: TRDAPQueryStatus): string;
begin
  case AStatus of
    rqsOK: Result := 'ok';
    rqsNotFound: Result := 'not found';
    rqsRateLimited: Result := 'rate limited';
    rqsError: Result := 'error';
  else
    Result := 'no response';
  end;
end;

function StatusToExitCode(AStatus: TRDAPQueryStatus): Integer;
begin
  case AStatus of
    rqsOK: Result := ExitOK;
    rqsNotFound: Result := ExitNotFound;
    rqsRateLimited: Result := ExitRateLimited;
  else
    Result := ExitError;
  end;
end;

// Maps the --type= value to a query type; False for an unknown value.
function ParseQueryType(const S: string; out AType: TRDAPQueryType): Boolean;
begin
  Result := True;
  if S = 'domain' then
    AType := rqtDomain
  else if S = 'ip' then
    AType := rqtIP
  else if S = 'autnum' then
    AType := rqtAutNum
  else if S = 'entity' then
    AType := rqtEntity
  else
    Result := False;
end;

procedure PrintHelp;
begin
  Writeln('rdapcli - RDAP command-line client (fp-rdap library showcase)');
  Writeln;
  Writeln('Usage:');
  Writeln('  rdapcli [options] <query>');
  Writeln;
  Writeln('The query type is detected automatically: a valid IPv4/IPv6 address');
  Writeln('is queried as "ip", "AS" followed by digits as "autnum", anything');
  Writeln('else as "domain". Entity handles cannot be detected, use --type=entity.');
  Writeln;
  Writeln('Options:');
  Writeln('  -h, --help              Show this help and exit');
  Writeln('  --type=TYPE             Query type: domain | ip | autnum | entity');
  Writeln('                          (default: auto-detect)');
  Writeln('  --raw                   Print the raw RDAP JSON to stdout (only the');
  Writeln('                          JSON is printed, suitable for redirection)');
  Writeln('  --bootstrap-dir=DIR     Directory with the IANA bootstrap files');
  Writeln('                          dns.json/ipv4.json/ipv6.json (default: current');
  Writeln('                          directory; without them the queries go through');
  Writeln('                          https://rdap.org/)');
  Writeln('  --proxy=HOST:PORT       Route the query through a SOCKS5 proxy');
  Writeln('  --proxy-user=USER       SOCKS5 user name (no-auth when omitted)');
  Writeln('  --proxy-pass=PASS       SOCKS5 password');
  Writeln;
  Writeln('Exit codes:');
  Writeln('  0  success');
  Writeln('  1  object not found (HTTP 404)');
  Writeln('  2  rate limited (HTTP 429, see Retry-After)');
  Writeln('  3  everything else: RDAP error status, network failure, invalid');
  Writeln('     query or usage error');
  Writeln;
  Writeln('Results go to stdout; notices and errors go to stderr.');
  Writeln;
  Writeln('Examples:');
  Writeln('  rdapcli example.ru');
  Writeln('  rdapcli 8.8.8.8');
  Writeln('  rdapcli AS15169');
  Writeln('  rdapcli 2001:db8::1');
  Writeln('  rdapcli --type=entity NIC-HDL-ANR30-RIPE');
  Writeln('  rdapcli --raw example.com > result.json');
  Writeln('  rdapcli --bootstrap-dir=C:\rdap --proxy=127.0.0.1:9050 example.ru');
end;

// Parses the command line. Returns False (after printing a diagnostic) on a
// usage error. AHelp is set for -h/--help. The first positional argument is
// the query; further positional arguments are a usage error. Option names
// are case-sensitive, values of --type are validated here. Without an
// explicit --type the query type is auto-detected from the query string.
function ParseOptions(out AOpts: TCLIOptions; out AHelp: Boolean): Boolean;
var
  I, P: Integer;
  S, Value, PortStr: string;
  ExplicitType: Boolean;

  // S without the leading "=value" option prefix.
  function OptValue(const APrefix: string): string;
  begin
    Result := Copy(S, Length(APrefix) + 1, MaxInt);
  end;

begin
  AOpts := Default(TCLIOptions);
  AOpts.QueryType := rqtDomain;
  ExplicitType := False;
  AHelp := False;
  Result := True;
  for I := 1 to CParamCount do
  begin
    S := CParamStr(I);
    if Pos('--type=', S) = 1 then
    begin
      Value := OptValue('--type=');
      if not ParseQueryType(Value, AOpts.QueryType) then
      begin
        UsageError('unknown value "' + Value + '" for --type ' +
          '(expected domain, ip, autnum or entity)');
        Exit(False);
      end;
      ExplicitType := True;
    end
    else if Pos('--bootstrap-dir=', S) = 1 then
    begin
      Value := OptValue('--bootstrap-dir=');
      if Value = '' then
      begin
        UsageError('--bootstrap-dir requires a directory path');
        Exit(False);
      end;
      AOpts.BootstrapDir := Value;
    end
    else if Pos('--proxy-user=', S) = 1 then
      AOpts.ProxyUser := OptValue('--proxy-user=')
    else if Pos('--proxy-pass=', S) = 1 then
      AOpts.ProxyPass := OptValue('--proxy-pass=')
    else if Pos('--proxy=', S) = 1 then
    begin
      Value := OptValue('--proxy=');
      P := Pos(':', Value);
      if P <= 1 then
      begin
        UsageError('--proxy expects --proxy=host:port, got "' + Value + '"');
        Exit(False);
      end;
      AOpts.ProxyHost := Copy(Value, 1, P - 1);
      PortStr := Copy(Value, P + 1, MaxInt);
      AOpts.ProxyPort := StrToIntDef(PortStr, 0);
      if (AOpts.ProxyPort < 1) or (AOpts.ProxyPort > 65535) then
      begin
        UsageError('invalid proxy port "' + PortStr + '"');
        Exit(False);
      end;
    end
    else if S = '--raw' then
      AOpts.Raw := True
    else if (S = '-h') or (S = '--help') then
      AHelp := True
    else if (Length(S) > 1) and (S[1] = '-') then
    begin
      UsageError('unknown option: ' + S);
      Exit(False);
    end
    else if AOpts.Query = '' then
      AOpts.Query := S
    else
    begin
      UsageError('unexpected extra argument: ' + S);
      Exit(False);
    end;
  end;
  // No explicit --type: suggest the type from the query string itself (the
  // library helper uses the same IP syntax QueryIP accepts; "AS"+digits is
  // the autnum rule; the fallback is a domain).
  if not ExplicitType then
    AOpts.QueryType := DetectQueryType(AOpts.Query);
end;

// Bootstrap file name for ADir: '' loads from the current directory (plain
// names, like the demo), otherwise from the given directory.
function BootstrapFilePath(const ADir, AName: string): string;
begin
  if ADir = '' then
    Result := AName
  else
    Result := IncludeTrailingPathDelimiter(ADir) + AName;
end;

// Loads the three IANA bootstrap files; False (with notices) when they are
// unavailable - the caller falls back to DefaultBaseURL. The utility never
// downloads the bootstrap from the network (no such API in the library).
function TryLoadBootstrap(B: TRDAPBootstrap; const ADir: string): Boolean;
var
  Where: string;
begin
  if ADir = '' then
    Where := 'current directory'
  else
    Where := ADir;
  try
    B.LoadFromLocalFiles(
      BootstrapFilePath(ADir, 'dns.json'),
      BootstrapFilePath(ADir, 'ipv4.json'),
      BootstrapFilePath(ADir, 'ipv6.json'));
    Diag('Bootstrap loaded from local files (' + Where + ')');
    Result := True;
  except
    on E: ERDAPError do
    begin
      Diag('Bootstrap files not available (' + Where + '): ' + E.Message);
      Diag('Get dns.json/ipv4.json/ipv6.json from https://data.iana.org/rdap/');
      Diag('Falling back to ' + DefaultBaseURL);
      Result := False;
    end;
  end;
end;

// Human-readable summary of the last query (demo-style): URL, status and the
// object/error details. Written to AStream: stdout in the default mode,
// stderr in --raw mode (stdout carries the JSON body there).
procedure PrintSummary(var AStream: Text; const C: TRDAPClient;
  const AQuery: string; AType: TRDAPQueryType);
begin
  Writeln(AStream, 'Query:  ', AQuery, ' (', QueryTypeName(AType), ')');
  Writeln(AStream, 'URL:    ', C.LastURL);
  Writeln(AStream, 'Status: ', StatusText(C.LastStatus));
  case C.LastStatus of
    rqsOK:
      begin
        Writeln(AStream, 'Title:  ', C.GetObjectTitle);
        Writeln(AStream, 'Type:   ', C.GetObjectType);
        Writeln(AStream, 'Size:   ', Length(C.LastRawJSON), ' bytes');
      end;
    rqsNotFound:
      Writeln(AStream, 'Object not found');
    rqsRateLimited:
      // Retry-After of the last response (both RFC 7231 forms, in seconds); 0
      // when the header is absent.
      if C.RetryAfter > 0 then
        Writeln(AStream, 'Retry-After: ', C.RetryAfter, ' seconds');
    rqsError:
      // 400/401/403/503 arrive as a status (not an exception) since the RFC
      // 9083 error handling; network failures and unexpected codes land here
      // too, without an HTTP status.
      if C.LastHTTPCode > 0 then
        Writeln(AStream, 'HTTP ', C.LastHTTPCode, ' error')
      else
        Writeln(AStream, 'Request failed');
  end;
  // errorCode/title of an RFC 9083 error object in the response, if any.
  if C.LastErrorCode <> 0 then
    Writeln(AStream, 'Error ', C.LastErrorCode, ': ', C.LastErrorTitle);
end;

procedure Run(const AOpts: TCLIOptions);
var
  B: TRDAPBootstrap;
  C: TRDAPClient;
  Query: string;
begin
  Query := Trim(AOpts.Query);
  if Query = '' then
  begin
    // ParseOptions rejects a missing query; an all-blank argument cannot be
    // told apart there, so check the trimmed value here.
    UsageError('query is empty');
    ExitCode := ExitError;
    Exit;
  end;

  if AOpts.ProxyHost <> '' then
    Diag(Format('Using SOCKS5 proxy: %s:%d', [AOpts.ProxyHost, AOpts.ProxyPort]));

  B := TRDAPBootstrap.Create;
  C := TRDAPClient.Create;
  try
    // SOCKS5 proxy: applied even when empty - the client goes through the
    // proxy only when ProxyHost <> '', otherwise the transport is unchanged.
    C.ProxyHost := AOpts.ProxyHost;
    C.ProxyPort := AOpts.ProxyPort;
    C.ProxyUser := AOpts.ProxyUser;
    C.ProxyPass := AOpts.ProxyPass;

    if TryLoadBootstrap(B, AOpts.BootstrapDir) then
      C.Bootstrap := B // not owned by the client: freed by this procedure
    else
      C.BaseURL := DefaultBaseURL;

    try
      case AOpts.QueryType of
        rqtIP:     C.QueryIP(Query);
        rqtAutNum: C.QueryAutNum(Query); // the client folds the AS prefix itself
        rqtEntity: C.QueryEntity(Query);
      else
        C.QueryDomain(Query);
      end;
    except
      // The library reports all its errors as ERDAPError; anything else would
      // be a bug, still reported as exit code 3.
      on E: Exception do
      begin
        Writeln(ErrOutput, 'Error: ', E.Message);
        ExitCode := ExitError;
        Exit;
      end;
    end;

    if AOpts.Raw then
    begin
      // The body as-is on stdout (for redirection); the summary is a
      // diagnostic and goes to stderr.
      Writeln(C.LastRawJSON);
      PrintSummary(ErrOutput, C, Query, AOpts.QueryType);
    end
    else
      PrintSummary(Output, C, Query, AOpts.QueryType);

    ExitCode := StatusToExitCode(C.LastStatus);
  finally
    C.Free;
    B.Free;
  end;
end;

var
  Opts: TCLIOptions;
  Help: Boolean;
begin
  {$IFDEF MSWINDOWS}
  // Library strings are UTF-8 by contract, while a Windows console usually
  // starts in the OEM codepage (e.g. cp866), which would garble non-ASCII
  // titles and error messages. Switch the console output to UTF-8 for the
  // run (needs a Unicode-capable console font) and restore the previous
  // codepage on exit. No ReadLn at the end: this is a scriptable utility.
  OldOutputCP := GetConsoleOutputCP;
  SetConsoleOutputCP(CP_UTF8);
  {$ENDIF}
  try
    {$IFDEF MSWINDOWS}
    InitParams;
    {$ENDIF}
    if not ParseOptions(Opts, Help) then
      ExitCode := ExitError
    else if Help then
    begin
      PrintHelp;
      ExitCode := ExitOK;
    end
    else if Opts.Query = '' then
    begin
      UsageError('no query given');
      ExitCode := ExitError;
    end
    else
      Run(Opts);
  finally
    {$IFDEF MSWINDOWS}
    SetConsoleOutputCP(OldOutputCP);
    {$ENDIF}
  end;
end.
