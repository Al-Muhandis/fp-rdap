unit rdapclient;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, fpjson
  ;

type
  ERDAPError = class(Exception);

  TIPv6Bytes = array[0..15] of Byte;

  TRDAPQueryStatus = (rqsNone, rqsOK, rqsNotFound, rqsRateLimited, rqsError);

{ Pure helper functions. They are exposed in the interface so unit tests can cover IP parsing, CIDR matching,
  domain suffix matching and path encoding without any network or filesystem access. }

function TryStrToIPv4(const S: string; out aIP: Cardinal): Boolean;
function TryStrToIPv6(const S: string; out aIP: TIPv6Bytes): Boolean;
{ True when AIP falls inside ANetworkIP/APrefixLen; APrefixLen 0 matches everything. }
function IPv4InNetwork(aIP, aNetworkIP: Cardinal; aPrefixLen: Integer): Boolean;
function IPv6InNetwork(const aIP, aNetworkIP: TIPv6Bytes; aPrefixLen: Integer): Boolean;
{ Number of trailing domain labels shared with AKey (case-insensitive, multi-label keys such as "co.uk" are supported).
 0 means no match, so a longer key always wins over a shorter one. }
function DomainMatchesKey(const aDomain, aKey: string): Integer;
{ Converts a UTF-8 domain name to the A-label form expected by RFC 9082: every
  non-ASCII label is punycode-encoded (RFC 3492, via the fp-idn package) and
  prefixed with "xn--". Besides punycode the fp-idn IDNA mapping applies:
  ASCII/Cyrillic/Greek uppercase folds to lowercase, the label separators
  U+FF0E/U+3002/U+FF61 map to '.', and already converted A-labels pass
  through unchanged. Raises ERDAPError for domains fp-idn rejects (malformed
  UTF-8, control characters or space in a label, forbidden ASCII <>"/\?#@:|,
  DNS length limits); empty input yields an empty result. No NFC
  normalization: pass names in NFC form. }
function DomainToASCII(const ADomain: string): string;
{ Percent-encodes a string so it is safe to embed as a single URL path segment. }
function EncodePathSegment(const S: string): string;
{ Parses a Retry-After header value (RFC 7231 §7.1.3): either a delay in seconds
  or an IMF-fixdate HTTP-date ("Sun, 06 Nov 1994 08:49:37 GMT"). ASeconds is the
  delay in whole seconds; a date in the past yields 0. False (and ASeconds = 0)
  for an empty or unparseable value. }
function TryParseRetryAfter(const AValue: string; out ASeconds: Integer): Boolean;

type
  { TRDAPBootstrap }

  { IANA RDAP bootstrap files (RFC 8524 for DNS, RFC 9224/9225 for IPv4/IPv6) have a "services" array;
    each entry is a pair: a list of keys (TLDs or CIDRs) and a list of RDAP base URLs, e.g.

    //   "services": [
    //     [["net", "com"], ["https://rdap.verisign.com/com/v1/"]],
    //     [["8.0.0.0/8"], ["https://rdap.arin.net/registry/"]]
    //   ]

    The second element is an array of URLs in the official files; a plain string is accepted as well. }

  TRDAPBootstrap = class
  private
    fDNSData, fIPv4Data, fIPv6Data: TJSONData;
    fServicesDNS, fServicesIPv4, fServicesIPv6: TJSONArray;
    procedure LoadJSON(const aFileName: string; out aData: TJSONData);
    procedure ParseJSON(const aJSON: string; out aData: TJSONData; const aKind: string);
    procedure LoadServices(aData: TJSONData; out aServices: TJSONArray; const aKind: string);
    // Parse-then-swap core of the Load* methods: validates the freshly parsed
    // aNewData ("services" array) and only on full success replaces aData and
    // aServices. Takes over ownership of aNewData: freed on a validation
    // error, so a failed reload leaves the previously loaded data intact.
    procedure InstallServices(aNewData: TJSONData; var aData: TJSONData;
      var aServices: TJSONArray; const aKind: string);
    function FindDNSService(const aDomain: string): Integer;
    function FindIPv4Service(aIP: Cardinal): Integer;
    function FindIPv6Service(const aIP: TIPv6Bytes): Integer;
    function ServiceURL(aServices: TJSONArray; aIndex: Integer): string;
  public
    destructor Destroy; override;
    { Loads the DNS bootstrap from a raw JSON string (embedded snapshot
      fallback when the canonical file is not deployed next to the exe). }
    procedure LoadDNSFromString(const aJSON: string);
    { String variants of LoadIPv4/LoadIPv6, symmetric to LoadDNSFromString. }
    procedure LoadIPv4FromString(const aJSON: string);
    procedure LoadIPv6FromString(const aJSON: string);
    procedure LoadDNS(const aFileName: string = 'dns.json');
    procedure LoadIPv4(const aFileName: string = 'ipv4.json');
    procedure LoadIPv6(const aFileName: string = 'ipv6.json');
    { Loads only the files whose names are not empty. }
    procedure LoadFromLocalFiles(const aDNSFile: string = 'dns.json';const aIPv4File: string = 'ipv4.json';
      const aIPv6File: string = 'ipv6.json');
    function GetBaseURLForDomain(const aDomain: string): string;
    function GetBaseURLForIP(const aIP: string): string;
  end;

  { TRDAPClient }

  { RDAP client for a single base URL or, when no base URL is set, for the IANA bootstrap.
    Only QueryDomain and QueryIP are bootstrap-aware; entity and autnum queries always need BaseURL.
    Not thread-safe: all queries share the Last* result state, so use one instance per thread. }

  TRDAPClient = class
  private
    FBaseURL: string;
    FBootstrap: TRDAPBootstrap; // not owned by the client
    FUserAgent: string;
    FConnectTimeout: Integer;
    FIOTimeout: Integer;
    FProxyHost: string;
    FProxyPort: Integer;
    FProxyUser: string;
    FProxyPass: string;
    FMaxResponseSize: Int64;
    FSSLInitialized: Boolean;
    FLastRawJSON: string;
    FLastJSON: TJSONData;
    FLastURL: string;
    FLastHTTPCode: Integer;
    FLastStatus: TRDAPQueryStatus;
    FLastErrorCode: Integer;
    FLastErrorTitle: string;
    FRetryAfter: Integer;
    procedure ClearLastState;
    procedure InitSSLIfNeeded(const AURL: string);
    procedure ProcessLastResponse;
    procedure ExtractRDAPError;
    // Shared by all Query* methods: builds the URL, performs the request
    // and fills the Last* state.
    function ExecuteQuery(const APath, ABase: string): string;
    function RequireBaseURL: string;
  protected
    // Snapshot of the last response's headers ("Name: value" wire lines);
    // filled by DoHTTPGetJSON (real client and mock alike), cleared in
    // ClearLastState.
    FResponseHeaders: TStringList;
    // Case-insensitive lookup of a header of the last response, '' if absent.
    function GetResponseHeader(const AName: string): string; virtual;
    // Performs the actual HTTP GET and returns the response body.
    // Override to mock the network layer in tests.
    function DoHTTPGetJSON(const AURL, AUserAgent: string): string; virtual;
    // SOCKS5-proxy transport behind DoHTTPGetJSON, dispatched to when
    // ProxyHost <> '' (Synapse THTTPSend). See the implementation comment
    // for the redirect, size-limit and error-handling contract.
    function DoHTTPGetJSONViaProxy(const AURL, AUserAgent: string): string; virtual;
    // Raises ERDAPError when ASize exceeds MaxResponseSize (0 = no limit);
    // a body of exactly the limit is accepted. The real download aborts
    // mid-read in TLimitedResponseStream; this check applies the same
    // contract to whatever DoHTTPGetJSON returned - the path the mock
    // (and hence the tests) exercises.
    procedure CheckResponseLimit(const AURL: string; ASize: Int64);
  public
    constructor Create(const ABaseURL: string = ''); virtual;
    destructor Destroy; override;

    property BaseURL: string read FBaseURL write FBaseURL;
    property UserAgent: string read FUserAgent write FUserAgent;
    property ConnectTimeout: Integer read FConnectTimeout write FConnectTimeout;
    property IOTimeout: Integer read FIOTimeout write FIOTimeout;
    { SOCKS5 proxy settings, mirroring fp-whois TWhoisClient: queries go
      through the proxy only when ProxyHost <> '' - the whole transport then
      switches to the SOCKS5-capable HTTP client; with an empty ProxyHost the
      behavior is exactly as without a proxy. ProxyUser <> '' switches the
      SOCKS5 user/pass authentication on. ProxyPort has no hidden default:
      0 is written through as-is, so set it together with ProxyHost. }
    property ProxyHost: string read FProxyHost write FProxyHost;
    property ProxyPort: Integer read FProxyPort write FProxyPort;
    property ProxyUser: string read FProxyUser write FProxyUser;
    property ProxyPass: string read FProxyPass write FProxyPass;
    { Maximum accepted response body size in bytes (default 10 MB): a larger
      response aborts the download with ERDAPError instead of growing memory
      without bound - protection against broken or hostile servers.
      0 (or less) disables the limit. }
    property MaxResponseSize: Int64 read FMaxResponseSize write FMaxResponseSize;

    property LastRawJSON: string read FLastRawJSON;
    { JSON tree of the last response. Owned by the client and invalidated by
      the next query (freed in ClearLastState): the pointer is only valid until
      the next Query* call; nil when nothing was parsed. }
    property LastJSON: TJSONData read FLastJSON;
    property LastURL: string read FLastURL;
    property LastHTTPCode: Integer read FLastHTTPCode;
    property LastStatus: TRDAPQueryStatus read FLastStatus;
    // errorCode/title from an RFC 9083 error object in the last response, if any.
    property LastErrorCode: Integer read FLastErrorCode;
    property LastErrorTitle: string read FLastErrorTitle;
    // Retry-After header (in seconds) of the last response, 0 if absent.
    // Both RFC 7231 forms are accepted: delay-seconds and HTTP-date.
    property RetryAfter: Integer read FRetryAfter;

    // The bootstrap is not owned by the client: create and free it yourself.
    property Bootstrap: TRDAPBootstrap read FBootstrap write FBootstrap;

    { Queries the domain object for ADomain. Non-ASCII U-labels are converted
      to A-label (punycode) form before the bootstrap lookup and the request;
      domains rejected by IDNA validation raise ERDAPError - see DomainToASCII
      for the conversion limits. }
    function QueryDomain(const ADomain: string): string;
    function QueryIP(const AIP: string): string;
    function QueryAutNum(const AAutNum: string): string;
    function QueryEntity(const AHandle: string): string;

    function GetObjectTitle: string;
    function GetObjectType: string;
  end;

  { TRDAPClientMock - records request URLs and replays a canned response
    (optionally with response headers), so unit tests never touch the network. }

  TRDAPClientMock = class(TRDAPClient)
  private
    FMockResponse: string;
    FMockHTTPCode: Integer;
    FMockError: string;
    FMockEnabled: Boolean;
    FMockRequests: TStringList;
    FMockHeaders: TStringList; // headers replayed with the canned response
    function GetMockRequestCount: Integer;
  protected
    function DoHTTPGetJSON(const AURL, AUserAgent: string): string; override;
  public
    constructor Create(const ABaseURL: string = ''); override;
    destructor Destroy; override;

    procedure SetupMock(const AMockResponse: string; AHTTPCode: Integer = 200); overload;
    { Same as SetupMock, but the response also carries the given raw header
      lines ("Name: value"), e.g. ['Retry-After: 120']. }
    procedure SetupMock(const AMockResponse: string; AHTTPCode: Integer;
      const AHeaders: array of string); overload;
    // Makes the next requests raise ERDAPError with the given message,
    // as if the network layer had failed.
    procedure SetupMockError(const AError: string);
    procedure DisableMock;

    property MockRequestCount: Integer read GetMockRequestCount;
    function MockRequestURL(AIndex: Integer): string;
  end;

implementation

uses
  StrUtils, fpidn, fphttpclient, jsonparser, opensslsockets, openssl,
  httpsend, ssl_openssl;

// Single trailing-slash normalization point for base URLs, both the client's
// BaseURL and the bootstrap URLs: appends the missing '/' before APath.
function NormalizePath(const ABase, APath: string): string;
begin
  if (ABase <> '') and (ABase[Length(ABase)] <> '/') then
    Result := ABase + '/' + APath
  else
    Result := ABase + APath;
end;

// GetJSON takes a TJSONStringType (= UTF8String) parameter, so an argument
// carrying a non-UTF-8 codepage label gets byte-converted before fcl-json sees
// it. RDAP payloads are UTF-8 bytes by contract, so hand over a private copy
// relabeled CP_UTF8 without conversion: the bytes reach the scanner unchanged
// even when DefaultSystemCodePage is not UTF-8 (a no-op relabel when it is).
// Verified on 3.2.2 with a simulated cp1251 default codepage: without the
// relabel the literal non-ASCII bytes are double-encoded at the call boundary,
// with it the parse keeps them byte-exact.
function Utf8JSONArg(const AJSON: string): string;
begin
  SetString(Result, PChar(Pointer(AJSON)), Length(AJSON));
  SetCodePage(RawByteString(Result), CP_UTF8, False);
end;

procedure ParseJSONSafe(const AJSON: string; out AData: TJSONData);
begin
  AData := nil;
  if AJSON = '' then
    Exit;
  try
    AData := GetJSON(Utf8JSONArg(AJSON), True);
  except
    on E: Exception do
      raise ERDAPError.CreateFmt('JSON parse error: %s', [E.Message]);
  end;
end;

// Tolerant variant for bodies that are allowed to be non-JSON (4xx/429).
procedure TryParseJSON(const AJSON: string; out AData: TJSONData);
begin
  AData := nil;
  if AJSON = '' then
    Exit;
  try
    AData := GetJSON(Utf8JSONArg(AJSON), True);
  except
    AData := nil;
  end;
end;

function EncodePathSegment(const S: string): string;
const
  HexDigits: array[0..15] of Char = ('0', '1', '2', '3', '4', '5', '6', '7',
    '8', '9', 'A', 'B', 'C', 'D', 'E', 'F');
var
  I: Integer;
  C: Char;
begin
  Result := '';
  for I := 1 to Length(S) do
  begin
    C := S[I];
    if C in ['A'..'Z', 'a'..'z', '0'..'9', '-', '.', '_', '~', ':'] then
      Result := Result + C
    else
      Result := Result + '%' + HexDigits[Ord(C) shr 4] + HexDigits[Ord(C) and $0F];
  end;
end;

// Splits S by ADelim keeping empty parts ("a..b" -> "a", "", "b"),
// which TStringList.DelimitedText does not guarantee.
procedure SplitByChar(const S: string; ADelim: Char; AParts: TStrings);
var
  StartPos, P: Integer;
begin
  AParts.Clear;
  if S = '' then
    Exit;
  StartPos := 1;
  repeat
    P := PosEx(ADelim, S, StartPos);
    if P = 0 then
    begin
      AParts.Add(Copy(S, StartPos, MaxInt));
      Break;
    end;
    AParts.Add(Copy(S, StartPos, P - StartPos));
    StartPos := P + 1;
  until False;
end;

function AllDigits(const S: string): Boolean;
var
  I: Integer;
begin
  Result := S <> '';
  if not Result then
    Exit;
  for I := 1 to Length(S) do
    if not (S[I] in ['0'..'9']) then
      Exit(False);
end;

// U-label to A-label conversion (RFC 3492 punycode + the fp-idn IDNA
// mapping): see the interface comment for the exact contract. TryUnicodeToIDN
// instead of the plain wrapper so a domain rejected by the fp-idn validation
// (space, forbidden ASCII, length limits) raises instead of silently turning
// into an empty URL path (fp-idn 1.1.0.0 semantics).
function DomainToASCII(const ADomain: string): string;
begin
  if not TryUnicodeToIDN(ADomain, Result) then
    raise ERDAPError.CreateFmt('Domain rejected by IDNA validation: %s', [ADomain]);
end;

// Parses an IMF-fixdate HTTP-date (RFC 7231 §7.1.1.1), e.g.
// 'Sun, 06 Nov 1994 08:49:37 GMT'. The two obsolete formats (RFC 850, asctime)
// are not supported. The day name is skipped unvalidated. The result is a plain
// wall-clock value: comparing it against Now yields the correct UTC delta in
// any time zone, so no timezone conversion is needed here.
function TryParseHTTPFixdate(const S: string; out ADate: TDateTime): Boolean;
var
  Tokens, TimeParts: TStringList;
  CommaPos, I: Integer;
  Day, Month, Year, Hour, Minute, Second: Integer;
  TimeOfDay: TDateTime;

  function MonthIndex(const AMonth: string): Integer;
  const
    Months: array[1..12] of string = ('Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
      'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec');
  var
    I: Integer;
  begin
    Result := 0;
    for I := Low(Months) to High(Months) do
      if CompareText(AMonth, Months[I]) = 0 then
        Exit(I);
  end;

begin
  Result := False;
  ADate := 0;
  CommaPos := Pos(',', S);
  if CommaPos = 0 then
    Exit;
  Tokens := TStringList.Create;
  TimeParts := TStringList.Create;
  try
    // Drop the day name: the remainder is "06 Nov 1994 08:49:37 GMT".
    SplitByChar(Trim(Copy(S, CommaPos + 1, MaxInt)), ' ', Tokens);
    for I := Tokens.Count - 1 downto 0 do
      if Tokens[I] = '' then
        Tokens.Delete(I); // tolerate doubled spaces
    if (Tokens.Count <> 5) or (CompareText(Tokens[4], 'GMT') <> 0) then
      Exit;
    if not AllDigits(Tokens[0]) or not AllDigits(Tokens[2]) or
       (Length(Tokens[2]) <> 4) then
      Exit; // day, 4-digit year
    SplitByChar(Tokens[3], ':', TimeParts);
    if (TimeParts.Count <> 3) or not AllDigits(TimeParts[0]) or
       not AllDigits(TimeParts[1]) or not AllDigits(TimeParts[2]) then
      Exit;
    Day := StrToIntDef(Tokens[0], 0);
    Month := MonthIndex(Tokens[1]);
    Year := StrToIntDef(Tokens[2], 0);
    Hour := StrToIntDef(TimeParts[0], 0);
    Minute := StrToIntDef(TimeParts[1], 0);
    Second := StrToIntDef(TimeParts[2], 0);
    // Keep the Word parameters of TryEncodeDate/TryEncodeTime in range even
    // with range checking on; they validate the remaining semantics.
    if (Day < 1) or (Day > 31) or (Month = 0) or (Year < 1) or (Year > 9999) or
       (Hour > 23) or (Minute > 59) or (Second > 59) then
      Exit;
    if not TryEncodeDate(Year, Month, Day, ADate) or
       not TryEncodeTime(Hour, Minute, Second, 0, TimeOfDay) then
      Exit;
    ADate := ADate + TimeOfDay;
    Result := True;
  finally
    Tokens.Free;
    TimeParts.Free;
  end;
end;

function TryParseRetryAfter(const AValue: string; out ASeconds: Integer): Boolean;
var
  S: string;
  N: Integer;
  DT: TDateTime;
  Secs: Int64;
begin
  ASeconds := 0;
  S := Trim(AValue);
  if S = '' then
    Exit(False);
  // Delay-seconds form (1*DIGIT); overflow or a negative is not a valid delay.
  if AllDigits(S) then
  begin
    if TryStrToInt(S, N) then
    begin
      ASeconds := N;
      Exit(True);
    end;
    Exit(False);
  end;
  // HTTP-date form: whole seconds until the date, 0 when already in the past.
  // Values beyond MaxInt are clamped - Retry-After is advisory anyway.
  if TryParseHTTPFixdate(S, DT) then
  begin
    Secs := Trunc((DT - Now) * SecsPerDay);
    if Secs < 0 then
      Secs := 0
    else if Secs > High(Integer) then
      Secs := High(Integer);
    ASeconds := Integer(Secs);
    Exit(True);
  end;
  Result := False;
end;

function TryStrToIPv4(const S: string; out aIP: Cardinal): Boolean;
var
  Parts: TStringList;
  I, V: Integer;
begin
  Result := False;
  aIP := 0;
  Parts := TStringList.Create;
  try
    SplitByChar(S, '.', Parts);
    if Parts.Count <> 4 then
      Exit;
    for I := 0 to 3 do
    begin
      if not AllDigits(Parts[I]) then
        Exit;
      V := StrToIntDef(Parts[I], 256);
      if V > 255 then
        Exit;
      aIP := (aIP shl 8) or Cardinal(V);
    end;
    Result := True;
  finally
    Parts.Free;
  end;
end;

function TryHexToWord(const S: string; out AValue: Word): Boolean;
var
  I, D: Integer;
begin
  Result := False;
  AValue := 0;
  if (S = '') or (Length(S) > 4) then
    Exit;
  for I := 1 to Length(S) do
  begin
    case S[I] of
      '0'..'9': D := Ord(S[I]) - Ord('0');
      'a'..'f': D := Ord(S[I]) - Ord('a') + 10;
      'A'..'F': D := Ord(S[I]) - Ord('A') + 10;
    else
      Exit;
    end;
    AValue := Word((AValue shl 4) or D);
  end;
  Result := True;
end;

procedure SetIPv6Group(var AIP: TIPv6Bytes; AIndex: Integer; AValue: Word);
begin
  AIP[AIndex * 2] := Byte(AValue shr 8);
  AIP[AIndex * 2 + 1] := Byte(AValue and $FF);
end;

function TryStrToIPv6(const S: string; out aIP: TIPv6Bytes): Boolean;

  procedure DropSingleBlank(AParts: TStrings);
  begin
    if (AParts.Count = 1) and (AParts[0] = '') then
      AParts.Clear;
  end;

  // Parses one side of "::" (or the whole address without "::") into groups.
  // An embedded IPv4 tail ("::ffff:192.0.2.1") counts as two groups.
  // Only AGroups[0..ACount-1] are written, so the caller's array needs no
  // pre-initialization; on failure the caller exits without reading it.
  function ParseSide(AParts: TStrings; var AGroups: array of Word;
    out ACount: Integer): Boolean;
  var
    I: Integer;
    W: Word;
    V4: Cardinal;
  begin
    Result := False;
    ACount := 0;
    for I := 0 to AParts.Count - 1 do
      if Pos('.', AParts[I]) > 0 then
      begin
        if I <> AParts.Count - 1 then
          Exit; // embedded IPv4 is only valid at the end
        if not TryStrToIPv4(AParts[I], V4) then
          Exit;
        if ACount + 2 > 8 then
          Exit;
        AGroups[ACount] := Word(V4 shr 16);
        Inc(ACount);
        AGroups[ACount] := Word(V4 and $FFFF);
        Inc(ACount);
      end
      else
      begin
        if not TryHexToWord(AParts[I], W) then
          Exit;
        if ACount + 1 > 8 then
          Exit;
        AGroups[ACount] := W;
        Inc(ACount);
      end;
    Result := True;
  end;

const
  ZeroIPv6: TIPv6Bytes = (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
  ZeroGroups: array[0..7] of Word = (0, 0, 0, 0, 0, 0, 0, 0);
var
  DoubleColonPos: Integer;
  LeftParts, RightParts: TStringList;
  LeftGroups, RightGroups: array[0..7] of Word;
  LeftCount, RightCount, I: Integer;
begin
  Result := False;
  // Zeroed via real assignments: the flow analyzer does not recognize FillChar
  // as initialization (it would hint "not initialized" at the out parameter
  // and at the open-array var parameters of ParseSide otherwise).
  aIP := ZeroIPv6;
  LeftGroups := ZeroGroups;
  RightGroups := ZeroGroups;
  if (S = '') or (Pos(':', S) = 0) then
    Exit;

  DoubleColonPos := Pos('::', S);
  if (DoubleColonPos > 0) and (PosEx('::', S, DoubleColonPos + 2) > 0) then
    Exit; // only one "::" allowed

  LeftParts := TStringList.Create;
  RightParts := TStringList.Create;
  try
    if DoubleColonPos > 0 then
    begin
      SplitByChar(Copy(S, 1, DoubleColonPos - 1), ':', LeftParts);
      SplitByChar(Copy(S, DoubleColonPos + 2, MaxInt), ':', RightParts);
      DropSingleBlank(LeftParts);
      DropSingleBlank(RightParts);
      if not ParseSide(LeftParts, LeftGroups, LeftCount) then
        Exit;
      if not ParseSide(RightParts, RightGroups, RightCount) then
        Exit;
      if LeftCount + RightCount > 7 then
        Exit; // "::" must stand for at least one zero group
      for I := 0 to LeftCount - 1 do
        SetIPv6Group(aIP, I, LeftGroups[I]);
      for I := 0 to RightCount - 1 do
        SetIPv6Group(aIP, 8 - RightCount + I, RightGroups[I]);
    end
    else
    begin
      SplitByChar(S, ':', RightParts);
      if not ParseSide(RightParts, RightGroups, RightCount) then
        Exit;
      if RightCount <> 8 then
        Exit;
      for I := 0 to 7 do
        SetIPv6Group(aIP, I, RightGroups[I]);
    end;
    Result := True;
  finally
    LeftParts.Free;
    RightParts.Free;
  end;
end;

function IPv4PrefixMask(APrefixLen: Integer): Cardinal;
begin
  if APrefixLen <= 0 then
    Result := 0
  else if APrefixLen >= 32 then
    Result := Cardinal($FFFFFFFF)
  else
    Result := Cardinal($FFFFFFFF) shl (32 - APrefixLen);
end;

function IPv4InNetwork(aIP, aNetworkIP: Cardinal; aPrefixLen: Integer): Boolean;
begin
  if (aPrefixLen < 0) or (aPrefixLen > 32) then
    Exit(False);
  Result := (aIP and IPv4PrefixMask(aPrefixLen)) =
    (aNetworkIP and IPv4PrefixMask(aPrefixLen));
end;

function IPv6InNetwork(const aIP, aNetworkIP: TIPv6Bytes; aPrefixLen: Integer): Boolean;
var
  FullBytes, RemainderBits, I: Integer;
begin
  if (aPrefixLen < 0) or (aPrefixLen > 128) then
    Exit(False);
  if aPrefixLen = 0 then
    Exit(True);
  FullBytes := aPrefixLen div 8;
  for I := 0 to FullBytes - 1 do
    if aIP[I] <> aNetworkIP[I] then
      Exit(False);
  RemainderBits := aPrefixLen mod 8;
  if RemainderBits > 0 then
    Exit((aIP[FullBytes] shr (8 - RemainderBits)) =
      (aNetworkIP[FullBytes] shr (8 - RemainderBits)));
  Result := True;
end;

function DomainMatchesKey(const aDomain, aKey: string): Integer;
var
  D, K: string;
  I: Integer;
begin
  Result := 0;
  D := Trim(LowerCase(aDomain));
  K := Trim(LowerCase(aKey));
  while (D <> '') and (D[1] = '.') do
    Delete(D, 1, 1);
  while (D <> '') and (D[Length(D)] = '.') do
    Delete(D, Length(D), 1);
  while (K <> '') and (K[1] = '.') do
    Delete(K, 1, 1);
  while (K <> '') and (K[Length(K)] = '.') do
    Delete(K, Length(K), 1);
  if (D = '') or (K = '') or (Length(D) < Length(K)) then
    Exit;
  if Length(D) = Length(K) then
  begin
    if D <> K then
      Exit;
  end
  else if Copy(D, Length(D) - Length(K), Length(K) + 1) <> '.' + K then
    Exit; // "." must align on a label boundary
  Result := 1;
  for I := 1 to Length(K) do
    if K[I] = '.' then
      Inc(Result);
end;

function TryParseCIDR4(const S: string; out ANetIP: Cardinal;
  out APrefixLen: Integer): Boolean;
var
  P: Integer;
begin
  P := Pos('/', S);
  if P <= 1 then
    Exit(False);
  if not TryStrToIPv4(Copy(S, 1, P - 1), ANetIP) then
    Exit(False);
  APrefixLen := StrToIntDef(Copy(S, P + 1, MaxInt), -1);
  Result := (APrefixLen >= 0) and (APrefixLen <= 32);
end;

function TryParseCIDR6(const S: string; out ANetIP: TIPv6Bytes;
  out APrefixLen: Integer): Boolean;
var
  P: Integer;
  PL: string;
begin
  P := Pos('/', S);
  if P <= 1 then
    Exit(False);
  if not TryStrToIPv6(Copy(S, 1, P - 1), ANetIP) then
    Exit(False);
  PL := Copy(S, P + 1, MaxInt);
  if not AllDigits(PL) then
    Exit(False);
  APrefixLen := StrToIntDef(PL, -1);
  Result := (APrefixLen >= 0) and (APrefixLen <= 128);
end;

{ TRDAPBootstrap }

procedure TRDAPBootstrap.ParseJSON(const aJSON: string; out aData: TJSONData;
  const aKind: string);
begin
  aData := nil;
  if Trim(aJSON) = '' then
    raise ERDAPError.Create('Bootstrap JSON is empty');
  ParseJSONSafe(aJSON, aData);
  if (aData = nil) or (aData.JSONType <> jtObject) then
    raise ERDAPError.CreateFmt('Invalid bootstrap JSON: %s', [aKind]);
end;

procedure TRDAPBootstrap.LoadJSON(const aFileName: string; out aData: TJSONData);
var
  SL: TStringList;
begin
  aData := nil;
  if aFileName = '' then
    raise ERDAPError.Create('Bootstrap file name is empty');
  if not FileExists(aFileName) then
    raise ERDAPError.CreateFmt('Bootstrap file not found: %s', [aFileName]);
  SL := TStringList.Create;
  try
    // Bootstrap files are UTF-8 by definition (RFC 9224/9225); without an
    // explicit encoding TStrings would decode them with the system ANSI codepage.
    SL.LoadFromFile(aFileName, TEncoding.UTF8);
    ParseJSON(SL.Text, aData, aFileName);
  finally
    SL.Free;
  end;
end;

procedure TRDAPBootstrap.LoadServices(aData: TJSONData;
  out aServices: TJSONArray; const aKind: string);
var
  N: TJSONData;
begin
  aServices := nil;
  if aData <> nil then
  begin
    N := aData.FindPath('services');
    if (N <> nil) and (N.JSONType = jtArray) then
      aServices := TJSONArray(N);
  end;
  if aServices = nil then
    raise ERDAPError.CreateFmt('No "services" array in %s bootstrap', [aKind]);
end;

procedure TRDAPBootstrap.InstallServices(aNewData: TJSONData; var aData: TJSONData;
  var aServices: TJSONArray; const aKind: string);
var
  NewServices: TJSONArray;
begin
  try
    LoadServices(aNewData, NewServices, aKind);
  except
    aNewData.Free;
    raise;
  end;
  // Full success: swap fields. aServices still points into the old aData
  // tree, so repoint it before that tree is freed.
  aServices := NewServices;
  aData.Free;
  aData := aNewData;
end;

// Service entry layout check: [ [keys...], [urls...] ].
function TryGetServiceKeys(AService: TJSONData; out AKeys: TJSONArray): Boolean;
var
  Arr: TJSONArray;
begin
  AKeys := nil;
  Result := (AService <> nil) and (AService.JSONType = jtArray);
  if not Result then
    Exit;
  Arr := TJSONArray(AService);
  Result := (Arr.Count >= 2) and (Arr.Types[0] = jtArray);
  if Result then
    AKeys := Arr.Arrays[0];
end;

function TRDAPBootstrap.FindDNSService(const aDomain: string): Integer;
var
  I, J, M, Best: Integer;
  Keys: TJSONArray;
begin
  Result := -1;
  Best := 0;
  if fServicesDNS = nil then
    Exit;
  for I := 0 to fServicesDNS.Count - 1 do
  begin
    if not TryGetServiceKeys(fServicesDNS[I], Keys) then
      Continue;
    for J := 0 to Keys.Count - 1 do
      if Keys.Types[J] = jtString then
      begin
        M := DomainMatchesKey(aDomain, Keys.Strings[J]);
        if M > Best then
        begin
          Best := M;
          Result := I;
        end;
      end;
  end;
end;

function TRDAPBootstrap.FindIPv4Service(aIP: Cardinal): Integer;
var
  I, J, PrefixLen, BestPrefix: Integer;
  Keys: TJSONArray;
  NetIP: Cardinal;
begin
  Result := -1;
  BestPrefix := -1;
  if fServicesIPv4 = nil then
    Exit;
  for I := 0 to fServicesIPv4.Count - 1 do
  begin
    if not TryGetServiceKeys(fServicesIPv4[I], Keys) then
      Continue;
    for J := 0 to Keys.Count - 1 do
      if (Keys.Types[J] = jtString) and
         TryParseCIDR4(Keys.Strings[J], NetIP, PrefixLen) and
         (PrefixLen > BestPrefix) and
         IPv4InNetwork(aIP, NetIP, PrefixLen) then
      begin
        BestPrefix := PrefixLen;
        Result := I;
      end;
  end;
end;

function TRDAPBootstrap.FindIPv6Service(const aIP: TIPv6Bytes): Integer;
var
  I, J, PrefixLen, BestPrefix: Integer;
  Keys: TJSONArray;
  NetIP: TIPv6Bytes;
begin
  Result := -1;
  BestPrefix := -1;
  if fServicesIPv6 = nil then
    Exit;
  for I := 0 to fServicesIPv6.Count - 1 do
  begin
    if not TryGetServiceKeys(fServicesIPv6[I], Keys) then
      Continue;
    for J := 0 to Keys.Count - 1 do
      if (Keys.Types[J] = jtString) and
         TryParseCIDR6(Keys.Strings[J], NetIP, PrefixLen) and
         (PrefixLen > BestPrefix) and
         IPv6InNetwork(aIP, NetIP, PrefixLen) then
      begin
        BestPrefix := PrefixLen;
        Result := I;
      end;
  end;
end;

// Base URL of service entry aIndex ([ [keys...], urls ]). The entry layout is
// validated strictly - urls is an array of strings (a single URL string is
// tolerated as well) - so a malformed bootstrap entry raises ERDAPError naming
// the entry, never a bare EConvertError/EJSONError from fpjson.
function TRDAPBootstrap.ServiceURL(aServices: TJSONArray; aIndex: Integer): string;
var
  Service, URLs: TJSONArray;
  I: Integer;
begin
  if (aIndex < 0) or (aIndex >= aServices.Count) then
    raise ERDAPError.CreateFmt('Service %d: entry index out of range', [aIndex]);
  if aServices.Types[aIndex] <> jtArray then
    raise ERDAPError.CreateFmt('Service %d: entry is not an array', [aIndex]);
  Service := aServices.Arrays[aIndex];
  if Service.Count < 2 then
    raise ERDAPError.CreateFmt('Service %d: entry has no URL part', [aIndex]);
  case Service.Types[1] of
    jtString:
      Result := Service.Strings[1];
    jtArray:
      begin
        URLs := Service.Arrays[1];
        if URLs.Count = 0 then
          raise ERDAPError.CreateFmt('Service %d has an empty URL list', [aIndex]);
        for I := 0 to URLs.Count - 1 do
          if URLs.Types[I] <> jtString then
            raise ERDAPError.CreateFmt('Service %d: URL %d is not a string',
              [aIndex, I]);
        Result := URLs.Strings[0];
      end;
  else
    raise ERDAPError.CreateFmt(
      'Service %d: URL part is neither an array nor a string', [aIndex]);
  end;
  if Result = '' then
    raise ERDAPError.CreateFmt('Service %d has an empty base URL', [aIndex]);
end;

destructor TRDAPBootstrap.Destroy;
begin
  fDNSData.Free;
  fIPv4Data.Free;
  fIPv6Data.Free;
  inherited Destroy;
end;

// All Load* methods are parse-then-swap: the new tree is parsed and validated
// into temporaries first, the fields are replaced only on full success, so a
// failed reload keeps the previously loaded bootstrap operational.
procedure TRDAPBootstrap.LoadDNSFromString(const aJSON: string);
var
  NewData: TJSONData;
begin
  ParseJSON(aJSON, NewData, 'DNS');
  InstallServices(NewData, fDNSData, fServicesDNS, 'DNS');
end;

procedure TRDAPBootstrap.LoadIPv4FromString(const aJSON: string);
var
  NewData: TJSONData;
begin
  ParseJSON(aJSON, NewData, 'IPv4');
  InstallServices(NewData, fIPv4Data, fServicesIPv4, 'IPv4');
end;

procedure TRDAPBootstrap.LoadIPv6FromString(const aJSON: string);
var
  NewData: TJSONData;
begin
  ParseJSON(aJSON, NewData, 'IPv6');
  InstallServices(NewData, fIPv6Data, fServicesIPv6, 'IPv6');
end;

procedure TRDAPBootstrap.LoadDNS(const aFileName: string);
var
  NewData: TJSONData;
begin
  LoadJSON(aFileName, NewData);
  InstallServices(NewData, fDNSData, fServicesDNS, 'DNS');
end;

procedure TRDAPBootstrap.LoadIPv4(const aFileName: string);
var
  NewData: TJSONData;
begin
  LoadJSON(aFileName, NewData);
  InstallServices(NewData, fIPv4Data, fServicesIPv4, 'IPv4');
end;

procedure TRDAPBootstrap.LoadIPv6(const aFileName: string);
var
  NewData: TJSONData;
begin
  LoadJSON(aFileName, NewData);
  InstallServices(NewData, fIPv6Data, fServicesIPv6, 'IPv6');
end;

procedure TRDAPBootstrap.LoadFromLocalFiles(const aDNSFile: string; const aIPv4File: string; const aIPv6File: string);
begin
  if aDNSFile <> '' then
    LoadDNS(aDNSFile);
  if aIPv4File <> '' then
    LoadIPv4(aIPv4File);
  if aIPv6File <> '' then
    LoadIPv6(aIPv6File);
end;

function TRDAPBootstrap.GetBaseURLForDomain(const aDomain: string): string;
var
  Idx: Integer;
begin
  if fServicesDNS = nil then
    raise ERDAPError.Create('DNS bootstrap not loaded');
  Idx := FindDNSService(aDomain);
  if Idx < 0 then
    raise ERDAPError.CreateFmt('No RDAP server found for domain: %s', [aDomain]);
  Result := ServiceURL(fServicesDNS, Idx);
end;

function TRDAPBootstrap.GetBaseURLForIP(const aIP: string): string;
var
  IPv4: Cardinal;
  IPv6: TIPv6Bytes;
  Idx: Integer;
  Services: TJSONArray;
begin
  if Pos(':', aIP) > 0 then
  begin
    if not TryStrToIPv6(aIP, IPv6) then
      raise ERDAPError.CreateFmt('Invalid IP address: %s', [aIP]);
    if fServicesIPv6 = nil then
      raise ERDAPError.Create('IPv6 bootstrap not loaded');
    Idx := FindIPv6Service(IPv6);
    Services := fServicesIPv6;
  end
  else
  begin
    if not TryStrToIPv4(aIP, IPv4) then
      raise ERDAPError.CreateFmt('Invalid IP address: %s', [aIP]);
    if fServicesIPv4 = nil then
      raise ERDAPError.Create('IPv4 bootstrap not loaded');
    Idx := FindIPv4Service(IPv4);
    Services := fServicesIPv4;
  end;
  if Idx < 0 then
    raise ERDAPError.CreateFmt('No RDAP server found for IP: %s', [aIP]);
  Result := ServiceURL(Services, Idx);
end;

{ TLimitedResponseStream }

// Download buffer of DoHTTPGetJSON: aborts the HTTP read with ERDAPError as
// soon as the total body exceeds AMaxSize bytes (0 = unlimited), so a broken
// or hostile server cannot exhaust memory. fphttpclient calls Write directly
// in its read loop (no wrapping except), so the exception terminates the
// download; the true total is unknown at that point - the message reports the
// minimum size seen so far.
type
  TLimitedResponseStream = class(TRawByteStringStream)
  private
    FMaxSize: Int64;
    FURL: string;
  public
    constructor Create(AMaxSize: Int64; const AURL: string);
    function Write(const ABuffer; ACount: LongInt): LongInt; override;
  end;

constructor TLimitedResponseStream.Create(AMaxSize: Int64; const AURL: string);
begin
  inherited Create;
  FMaxSize := AMaxSize;
  FURL := AURL;
end;

function TLimitedResponseStream.Write(const ABuffer; ACount: LongInt): LongInt;
begin
  // Size is the byte count accumulated so far (TBytesStream tracks it).
  if (FMaxSize > 0) and (Size + ACount > FMaxSize) then
    raise ERDAPError.CreateFmt(
      'Response from %s exceeds the size limit: at least %d > %d bytes',
      [FURL, Size + ACount, FMaxSize]);
  Result := inherited Write(ABuffer, ACount);
end;

{ TRDAPClient }

procedure TRDAPClient.ClearLastState;
begin
  FreeAndNil(FLastJSON);
  FLastRawJSON := '';
  FLastURL := '';
  FLastHTTPCode := 0;
  FLastStatus := rqsNone;
  FLastErrorCode := 0;
  FLastErrorTitle := '';
  FRetryAfter := 0;
  FResponseHeaders.Clear;
end;

procedure TRDAPClient.InitSSLIfNeeded(const AURL: string);
begin
  if CompareText(Copy(AURL, 1, 8), 'https://') <> 0 then
    Exit;
  if FSSLInitialized then
    Exit;
  if not InitSSLInterface then
    raise ERDAPError.Create('SSL init failed: OpenSSL libraries not found');
  FSSLInitialized := True;
end;

// Case-insensitive lookup of a header of the last response, '' if absent.
// Both header sources keep raw "Name: value" wire lines with ':' as the
// name/value separator (TFPHttpClient.ResponseHeaders, and the mock copies
// that via Assign), so TStrings.Values applies. The Trim is correct by
// definition: an HTTP field value excludes surrounding whitespace (RFC 7230 §3.2).
function TRDAPClient.GetResponseHeader(const AName: string): string;
begin
  Result := Trim(FResponseHeaders.Values[AName]);
end;

procedure TRDAPClient.ProcessLastResponse;
begin
  case FLastHTTPCode of
    200:
      begin
        FLastStatus := rqsOK;
        ParseJSONSafe(FLastRawJSON, FLastJSON);
      end;

    404:
      begin
        // RFC 9083: the body may carry an error object; keep it if present.
        FLastStatus := rqsNotFound;
        TryParseJSON(FLastRawJSON, FLastJSON);
      end;

    429:
      begin
        FLastStatus := rqsRateLimited;
        TryParseJSON(FLastRawJSON, FLastJSON);
      end;

    400, 401, 403, 503:
      begin
        // RFC 9083 §6.2: the body carries an error object (not guaranteed to
        // be well-formed JSON). Reported as the rqsError status instead of an
        // exception; the raw body stays in LastRawJSON for the caller.
        FLastStatus := rqsError;
        TryParseJSON(FLastRawJSON, FLastJSON);
      end;

  else
    begin
      // Codes outside the accepted list never reach this branch from the real
      // client (TFPHttpClient raises EHTTPClient on them); the mock can feed
      // any code, so the branch stays alive for non-standard ones.
      FLastStatus := rqsError;
      raise ERDAPError.CreateFmt('Unexpected HTTP status %d for %s',
        [FLastHTTPCode, FLastURL]);
    end;
  end;
  // Retry-After (RFC 7231) is parsed here rather than in DoHTTPGetJSON, so
  // mock and real responses share one code path; 0 when the header is
  // absent or unparseable.
  TryParseRetryAfter(GetResponseHeader('Retry-After'), FRetryAfter);
  ExtractRDAPError;
end;

procedure TRDAPClient.ExtractRDAPError;
var
  N: TJSONData;
begin
  FLastErrorCode := 0;
  FLastErrorTitle := '';
  if (FLastJSON = nil) or (FLastJSON.JSONType <> jtObject) then
    Exit;
  N := FLastJSON.FindPath('errorCode');
  if N <> nil then
  begin
    if N.JSONType = jtNumber then
      FLastErrorCode := N.AsInteger
    else if N.JSONType = jtString then
      FLastErrorCode := StrToIntDef(N.AsString, 0);
  end;
  N := FLastJSON.FindPath('title');
  if (N <> nil) and (N.JSONType = jtString) then
    FLastErrorTitle := N.AsString;
end;

function TRDAPClient.DoHTTPGetJSON(const AURL, AUserAgent: string): string;
var
  C: TFPHttpClient;
  SS: TRawByteStringStream;
begin
  Result := '';
  // Proxy mode replaces the whole transport (mocked clients override this
  // method wholesale and never reach the dispatcher).
  if FProxyHost <> '' then
    Exit(DoHTTPGetJSONViaProxy(AURL, AUserAgent));
  InitSSLIfNeeded(AURL);

  C := TFPHttpClient.Create(nil);
  try
    C.AllowRedirect := True;
    C.MaxRedirects := 5;
    C.ConnectTimeout := FConnectTimeout;
    C.IOTimeout := FIOTimeout;

    C.AddHeader('User-Agent', AUserAgent);
    C.AddHeader('Accept', 'application/rdap+json,*/*');

    // The download buffer enforces MaxResponseSize: a body over the limit
    // aborts the read with ERDAPError instead of accumulating unbounded data.
    SS := TLimitedResponseStream.Create(FMaxResponseSize, AURL);
    try
      // RFC 9083 §6.2 error responses (400/401/403/503) are accepted too, so
      // ProcessLastResponse can turn them into rqsError instead of the HTTP
      // client raising on a disallowed status.
      C.HTTPMethod('GET', AURL, SS, [200, 400, 401, 403, 404, 429, 503]);
      Result := SS.DataString;
      // Snapshot the response headers; Assign also carries over the ':'
      // name/value separator that GetResponseHeader relies on. Retry-After
      // itself is parsed later, in ProcessLastResponse.
      FResponseHeaders.Assign(C.ResponseHeaders);
    finally
      FLastHTTPCode := C.ResponseStatusCode;
      SS.Free;
    end;
  finally
    C.Free;
  end;
end;

// SOCKS5-proxy transport of DoHTTPGetJSON (used only when ProxyHost <> '').
// The SOCKS5 negotiation happens inside the socket connect (Synapse
// SocksOpen/SocksRequest: SOCKS5 with the no-auth method when ProxyUser is
// empty, user/pass otherwise - verified against the Synapse 40.1 sources);
// TLS to the RDAP server then runs transparently through the established
// tunnel via the ssl_openssl plugin, which self-registers at unit
// initialization, so no explicit SSL init is needed here (unlike the direct
// path). THTTPSend does not follow redirects: they are handled manually, up
// to 5 hops with absolute Location URLs only (parity with the direct path's
// AllowRedirect=True/MaxRedirects=5); a relative Location is an ERDAPError
// (v1 limitation). Unlike the direct path, the body cannot be aborted
// mid-read here, so MaxResponseSize is enforced after the full download,
// with the Last* state already captured. Transport errors raise ERDAPError
// naming the URL and the proxy right where they occur: ExecuteQuery's
// wrap-up is a backstop, not something to rely on.
function TRDAPClient.DoHTTPGetJSONViaProxy(const AURL, AUserAgent: string): string;
const
  MaxRedirects = 5; // as TFPHttpClient.MaxRedirects on the direct path
var
  HTTP: THTTPSend;
  URL, Location: string;
  Hop: Integer;
begin
  Result := '';
  URL := AURL;
  HTTP := THTTPSend.Create;
  try
    // The proxy settings map 1-to-1 onto the socket (as fp-whois does); the
    // proxy is enabled by ProxyHost alone, ProxyPort goes through as-is.
    // SocksType stays at the Synapse default (ST_Socks5) and SocksResolver
    // at True: symbolic targets are resolved by the proxy (ATYP=domain), so
    // no local DNS lookup happens.
    HTTP.Sock.SocksIP := FProxyHost;
    HTTP.Sock.SocksPort := IntToStr(FProxyPort);
    HTTP.Sock.SocksUsername := FProxyUser;
    HTTP.Sock.SocksPassword := FProxyPass;
    HTTP.Timeout := FIOTimeout;
    HTTP.Sock.ConnectionTimeout := FConnectTimeout;

    Hop := 0;
    while True do
    begin
      // Wipe the previous hop's response body and the request headers that
      // HTTPMethod inserts (User-Agent, Connection, ...), so every pass
      // starts clean.
      HTTP.Clear;
      HTTP.UserAgent := AUserAgent;
      HTTP.Headers.Add('Accept: application/rdap+json,*/*');

      if not HTTP.HTTPMethod('GET', URL) then
        raise ERDAPError.CreateFmt('GET %s via SOCKS5 proxy %s:%d failed: %s',
          [URL, FProxyHost, FProxyPort, HTTP.Sock.LastErrorDesc]);

      // Last* snapshot: every hop overwrites it, so the final response is
      // what ProcessLastResponse sees. Synapse keeps raw wire lines too, but
      // with the default '=' name/value separator (unlike
      // TFPHttpClient.ResponseHeaders, which uses ':' and whose separator
      // Assign copies over) - restore ':' so GetResponseHeader works for
      // both transports.
      FResponseHeaders.Assign(HTTP.Headers);
      FResponseHeaders.NameValueSeparator := ':';
      FLastHTTPCode := HTTP.ResultCode;

      if (HTTP.ResultCode >= 301) and (HTTP.ResultCode <= 308) then
      begin
        // From the normalized snapshot (the raw Synapse Headers list keeps
        // its '=' separator, so Values[] does not apply to it directly).
        Location := GetResponseHeader('Location');
        if Location <> '' then
        begin
          if Hop >= MaxRedirects then
            raise ERDAPError.CreateFmt('GET %s: too many redirects (limit %d)',
              [AURL, MaxRedirects]);
          // v1: only absolute URLs are followed, like the direct path for
          // this request shape.
          if (Pos('http://', LowerCase(Location)) <> 1) and
             (Pos('https://', LowerCase(Location)) <> 1) then
            raise ERDAPError.CreateFmt(
              'Redirect from %s: relative Location is not followed: %s',
              [URL, Location]);
          URL := Location;
          Inc(Hop);
          Continue;
        end;
        // 3xx without a Location header is treated as a final response.
      end;
      Break;
    end;

    // The body was downloaded in full (no mid-read abort like
    // TLimitedResponseStream on the direct path); enforce the limit before
    // the body leaves this method - an over-limit response raises with the
    // LastHTTPCode/headers of that response already in place.
    CheckResponseLimit(URL, HTTP.Document.Size);
    if HTTP.Document.Size > 0 then
      SetString(Result, PChar(HTTP.Document.Memory), HTTP.Document.Size);
  finally
    HTTP.Free;
  end;
end;

constructor TRDAPClient.Create(const ABaseURL: string);
begin
  inherited Create;
  // BaseURL is stored as given; the trailing '/' is appended by NormalizePath
  // at query time (which also normalizes bootstrap URLs) - one place by design.
  FBaseURL := ABaseURL;
  FUserAgent := 'fp-rdap-client/1.0';
  FConnectTimeout := 15000;
  FIOTimeout := 30000;
  // No hidden default proxy port (parity with fp-whois): 0 is written
  // through as-is until the caller configures the proxy.
  FProxyPort := 0;
  // 10 MB: real RDAP responses are far smaller; the default limit only guards
  // against broken or hostile servers dumping unbounded data.
  FMaxResponseSize := 10 * 1024 * 1024;
  FResponseHeaders := TStringList.Create;
end;

destructor TRDAPClient.Destroy;
begin
  ClearLastState;
  FResponseHeaders.Free;
  inherited Destroy;
end;

// Shared response-size contract of ExecuteQuery: applies MaxResponseSize to
// whatever DoHTTPGetJSON returned (the real download aborts earlier, in
// TLimitedResponseStream). The body reaches LastRawJSON only after this check.
procedure TRDAPClient.CheckResponseLimit(const AURL: string; ASize: Int64);
begin
  if (FMaxResponseSize > 0) and (ASize > FMaxResponseSize) then
    raise ERDAPError.CreateFmt(
      'Response from %s exceeds the size limit: %d > %d bytes',
      [AURL, ASize, FMaxResponseSize]);
end;

function TRDAPClient.ExecuteQuery(const APath, ABase: string): string;
var
  URL: string;
  Body: string;
begin
  ClearLastState;
  URL := NormalizePath(ABase, APath);
  FLastURL := URL;
  try
    // The body is kept out of LastRawJSON until it passes the size check.
    Body := DoHTTPGetJSON(URL, FUserAgent);
    CheckResponseLimit(URL, Length(Body));
    FLastRawJSON := Body;
  except
    on E: Exception do
    begin
      FLastStatus := rqsError;
      if E is ERDAPError then
        raise
      else
        raise ERDAPError.CreateFmt('GET %s failed: %s', [URL, E.Message]);
    end;
  end;
  ProcessLastResponse;
  Result := FLastRawJSON;
end;

function TRDAPClient.RequireBaseURL: string;
begin
  if FBaseURL = '' then
    raise ERDAPError.Create('Base URL not set (autnum and entity queries are not covered by bootstrap)');
  Result := FBaseURL;
end;

function TRDAPClient.QueryDomain(const ADomain: string): string;
var
  Base: string;
  Domain: string;
begin
  Domain := Trim(ADomain);
  if Domain = '' then
    raise ERDAPError.Create('Domain is empty');
  // RFC 9082 puts the LDH name in the URL path as an A-label (punycode):
  // U-labels are converted instead of rejected. The conversion runs before
  // the bootstrap lookup - RFC 9224 bootstrap files list IDN TLD keys in
  // A-label form (the official dns.json is ASCII-only).
  Domain := DomainToASCII(Domain);
  if FBaseURL <> '' then
    Base := FBaseURL
  else if Assigned(FBootstrap) then
    Base := FBootstrap.GetBaseURLForDomain(Domain)
  else
    raise ERDAPError.Create('No base URL and no bootstrap configured');
  Result := ExecuteQuery('domain/' + EncodePathSegment(Domain), Base);
end;

function TRDAPClient.QueryIP(const AIP: string): string;
var
  V4: Cardinal;
  V6: TIPv6Bytes;
  Base: string;
  IP: string;
begin
  IP := Trim(AIP);
  if IP = '' then
    raise ERDAPError.Create('IP is empty');
  if Pos(':', IP) > 0 then
  begin
    if not TryStrToIPv6(IP, V6) then
      raise ERDAPError.CreateFmt('Invalid IP address: %s', [AIP]);
  end
  else if not TryStrToIPv4(IP, V4) then
    raise ERDAPError.CreateFmt('Invalid IP address: %s', [AIP]);

  if FBaseURL <> '' then
    Base := FBaseURL
  else if Assigned(FBootstrap) then
    Base := FBootstrap.GetBaseURLForIP(IP)
  else
    raise ERDAPError.Create('No base URL and no bootstrap configured');
  Result := ExecuteQuery('ip/' + EncodePathSegment(IP), Base);
end;

function TRDAPClient.QueryAutNum(const AAutNum: string): string;
begin
  if Trim(AAutNum) = '' then
    raise ERDAPError.Create('AutNum is empty');
  Result := ExecuteQuery('autnum/' + EncodePathSegment(Trim(AAutNum)), RequireBaseURL);
end;

function TRDAPClient.QueryEntity(const AHandle: string): string;
begin
  if Trim(AHandle) = '' then
    raise ERDAPError.Create('Handle is empty');
  Result := ExecuteQuery('entity/' + EncodePathSegment(Trim(AHandle)), RequireBaseURL);
end;

function TRDAPClient.GetObjectTitle: string;
var
  J: TJSONData;
begin
  Result := '';
  J := FLastJSON;
  if (J <> nil) and (J.JSONType = jtObject) then
  begin
    if J.FindPath('handle') <> nil then
      Result := J.FindPath('handle').AsString
    else
    if J.FindPath('ldhName') <> nil then
      Result := J.FindPath('ldhName').AsString
    else
    if J.FindPath('name') <> nil then
      Result := J.FindPath('name').AsString;
  end;
end;

function TRDAPClient.GetObjectType: string;
var
  J: TJSONData;
begin
  Result := '';
  J := FLastJSON;
  if (J <> nil) and (J.JSONType = jtObject) then
  begin
    if J.FindPath('objectClassName') <> nil then
      Result := J.FindPath('objectClassName').AsString;
  end;
end;

{ TRDAPClientMock }

constructor TRDAPClientMock.Create(const ABaseURL: string);
begin
  inherited Create(ABaseURL);
  FMockRequests := TStringList.Create;
  FMockHeaders := TStringList.Create;
  // Same wire format as TFPHttpClient.ResponseHeaders ("Name: value" with a
  // ':' name/value separator) - Assign into FResponseHeaders carries the
  // separator over, so GetResponseHeader works the same for both.
  FMockHeaders.NameValueSeparator := ':';
end;

destructor TRDAPClientMock.Destroy;
begin
  FMockRequests.Free;
  FMockHeaders.Free;
  inherited Destroy;
end;

procedure TRDAPClientMock.SetupMock(const AMockResponse: string; AHTTPCode: Integer);
begin
  SetupMock(AMockResponse, AHTTPCode, []);
end;

procedure TRDAPClientMock.SetupMock(const AMockResponse: string; AHTTPCode: Integer;
  const AHeaders: array of string);
var
  I: Integer;
begin
  FMockResponse := AMockResponse;
  FMockHTTPCode := AHTTPCode;
  FMockError := '';
  FMockHeaders.Clear;
  for I := 0 to High(AHeaders) do
    FMockHeaders.Add(AHeaders[I]);
  FMockEnabled := True;
end;

procedure TRDAPClientMock.SetupMockError(const AError: string);
begin
  FMockError := AError;
  FMockEnabled := True;
end;

procedure TRDAPClientMock.DisableMock;
begin
  FMockEnabled := False;
end;

function TRDAPClientMock.GetMockRequestCount: Integer;
begin
  Result := FMockRequests.Count;
end;

function TRDAPClientMock.MockRequestURL(AIndex: Integer): string;
begin
  Result := FMockRequests[AIndex];
end;

function TRDAPClientMock.DoHTTPGetJSON(const AURL, AUserAgent: string): string;
begin
  FMockRequests.Add(AURL);
  if not FMockEnabled then
    Result := inherited DoHTTPGetJSON(AURL, AUserAgent)
  else if FMockError <> '' then
    raise ERDAPError.Create(FMockError)
  else
  begin
    // Same mechanism as the real client: snapshot the headers and let
    // ProcessLastResponse parse Retry-After from them.
    FResponseHeaders.Assign(FMockHeaders);
    FLastHTTPCode := FMockHTTPCode;
    Result := FMockResponse;
  end;
end;

initialization
  // RDAP payloads and bootstrap files are guaranteed UTF-8 (RFC 9083/9224/9225),
  // and all strings of this library are UTF-8 by contract. On Windows with a
  // non-UTF-8 ANSI codepage fcl-json 3.2.2 mangles such data: literal non-ASCII
  // bytes are converted at the GetJSON(string -> UTF8String) call boundary with
  // any UseUTF8 value, and with UseUTF8=False the \uXXXX escapes additionally
  // end up in the system codepage without a re-encode. Making the default
  // AnsiString codepage UTF-8 turns every such conversion into an identity, so
  // strings keep their bytes on input and on output (TJSONData.AsString ->
  // String assignments too). The parse inputs are additionally relabeled by
  // Utf8JSONArg, so parsing itself is codepage-independent; this setting still
  // guards the value-extraction (ExtractRDAPError and similar) and the
  // bootstrap-loading boundaries. fcl-json parses label-independently since
  // FPC 3.3.1 (the scanner emits UTF-8 and labels tokens CP_UTF8; verified
  // against sources 2026-11-14), but the AsString -> String conversions do not:
  // dropping this assignment requires making every string boundary
  // codepage-explicit first.
  // NOTE: this affects the whole process using this unit, not just the library.
  DefaultSystemCodePage := CP_UTF8;

end.
