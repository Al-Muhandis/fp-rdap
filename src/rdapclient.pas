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
{ Percent-encodes a string so it is safe to embed as a single URL path segment. }
function EncodePathSegment(const S: string): string;

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
    function FindDNSService(const aDomain: string): Integer;
    function FindIPv4Service(aIP: Cardinal): Integer;
    function FindIPv6Service(const aIP: TIPv6Bytes): Integer;
    function ServiceURL(aServices: TJSONArray; aIndex: Integer): string;
  public
    destructor Destroy; override;
    { Loads the DNS bootstrap from a raw JSON string (embedded snapshot
      fallback when the canonical file is not deployed next to the exe). }
    procedure LoadDNSFromString(const aJSON: string);
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
    Only QueryDomain and QueryIP are bootstrap-aware; entity and autnum queries always need BaseURL. }

  TRDAPClient = class
  private
    FBaseURL: string;
    FBootstrap: TRDAPBootstrap; // not owned by the client
    FUserAgent: string;
    FConnectTimeout: Integer;
    FIOTimeout: Integer;
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
    // Performs the actual HTTP GET and returns the response body.
    // Override to mock the network layer in tests.
    function DoHTTPGetJSON(const AURL, AUserAgent: string): string; virtual;
  public
    constructor Create(const ABaseURL: string = ''); virtual;
    destructor Destroy; override;

    property BaseURL: string read FBaseURL write FBaseURL;
    property UserAgent: string read FUserAgent write FUserAgent;
    property ConnectTimeout: Integer read FConnectTimeout write FConnectTimeout;
    property IOTimeout: Integer read FIOTimeout write FIOTimeout;

    property LastRawJSON: string read FLastRawJSON;
    property LastJSON: TJSONData read FLastJSON;
    property LastURL: string read FLastURL;
    property LastHTTPCode: Integer read FLastHTTPCode;
    property LastStatus: TRDAPQueryStatus read FLastStatus;
    // errorCode/title from an RFC 9083 error object in the last response, if any.
    property LastErrorCode: Integer read FLastErrorCode;
    property LastErrorTitle: string read FLastErrorTitle;
    // Retry-After header (seconds) of a 429 response, 0 if absent.
    property RetryAfter: Integer read FRetryAfter;

    // The bootstrap is not owned by the client: create and free it yourself.
    property Bootstrap: TRDAPBootstrap read FBootstrap write FBootstrap;

    function QueryDomain(const ADomain: string): string;
    function QueryIP(const AIP: string): string;
    function QueryAutNum(const AAutNum: string): string;
    function QueryEntity(const AHandle: string): string;

    function GetObjectTitle: string;
    function GetObjectType: string;
  end;

  { TRDAPClientMock - records request URLs and replays a canned response,
    so unit tests never touch the network. }

  TRDAPClientMock = class(TRDAPClient)
  private
    FMockResponse: string;
    FMockHTTPCode: Integer;
    FMockError: string;
    FMockEnabled: Boolean;
    FMockRequests: TStringList;
    function GetMockRequestCount: Integer;
  protected
    function DoHTTPGetJSON(const AURL, AUserAgent: string): string; override;
  public
    constructor Create(const ABaseURL: string = ''); override;
    destructor Destroy; override;

    procedure SetupMock(const AMockResponse: string; AHTTPCode: Integer = 200);
    // Makes the next requests raise ERDAPError with the given message,
    // as if the network layer had failed.
    procedure SetupMockError(const AError: string);
    procedure DisableMock;

    property MockRequestCount: Integer read GetMockRequestCount;
    function MockRequestURL(AIndex: Integer): string;
  end;

implementation

uses
  StrUtils, fphttpclient, jsonparser, opensslsockets, openssl;

function NormalizePath(const ABase, APath: string): string;
begin
  if (ABase <> '') and (ABase[Length(ABase)] <> '/') then
    Result := ABase + '/' + APath
  else
    Result := ABase + APath;
end;

procedure ParseJSONSafe(const AJSON: string; out AData: TJSONData);
begin
  AData := nil;
  if AJSON = '' then
    Exit;
  try
    AData := GetJSON(AJSON, True);
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
    AData := GetJSON(AJSON, True);
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

var
  DoubleColonPos: Integer;
  LeftParts, RightParts: TStringList;
  LeftGroups, RightGroups: array[0..7] of Word;
  LeftCount, RightCount, I: Integer;
begin
  Result := False;
  // Initialize на статическом массиве - no-op: байты остаются мусорными
  FillChar(aIP, SizeOf(aIP), 0);
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
      FillChar(LeftGroups, SizeOf(LeftGroups), 0);
      if not ParseSide(LeftParts, LeftGroups, LeftCount) then
        Exit;
      FillChar(RightGroups, SizeOf(RightGroups), 0);
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

function TRDAPBootstrap.ServiceURL(aServices: TJSONArray; aIndex: Integer): string;
var
  Service: TJSONArray;
begin
  Service := aServices.Arrays[aIndex];
  if Service.Types[1] = jtArray then
  begin
    if Service.Arrays[1].Count = 0 then
      raise ERDAPError.CreateFmt('Service %d has an empty URL list', [aIndex]);
    Result := Service.Arrays[1].Strings[0];
  end
  else
    Result := Service.Strings[1];
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

procedure TRDAPBootstrap.LoadDNSFromString(const aJSON: string);
begin
  FreeAndNil(fDNSData);
  fServicesDNS := nil;
  ParseJSON(aJSON, fDNSData, 'DNS');
  LoadServices(fDNSData, fServicesDNS, 'DNS');
end;

procedure TRDAPBootstrap.LoadDNS(const aFileName: string);
begin
  FreeAndNil(fDNSData);
  fServicesDNS := nil;
  LoadJSON(aFileName, fDNSData);
  LoadServices(fDNSData, fServicesDNS, 'DNS');
end;

procedure TRDAPBootstrap.LoadIPv4(const aFileName: string);
begin
  FreeAndNil(fIPv4Data);
  fServicesIPv4 := nil;
  LoadJSON(aFileName, fIPv4Data);
  LoadServices(fIPv4Data, fServicesIPv4, 'IPv4');
end;

procedure TRDAPBootstrap.LoadIPv6(const aFileName: string);
begin
  FreeAndNil(fIPv6Data);
  fServicesIPv6 := nil;
  LoadJSON(aFileName, fIPv6Data);
  LoadServices(fIPv6Data, fServicesIPv6, 'IPv6');
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

  else
    begin
      FLastStatus := rqsError;
      raise ERDAPError.CreateFmt('Unexpected HTTP status %d for %s',
        [FLastHTTPCode, FLastURL]);
    end;
  end;
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
  InitSSLIfNeeded(AURL);

  C := TFPHttpClient.Create(nil);
  try
    C.AllowRedirect := True;
    C.MaxRedirects := 5;
    C.ConnectTimeout := FConnectTimeout;
    C.IOTimeout := FIOTimeout;

    C.AddHeader('User-Agent', AUserAgent);
    C.AddHeader('Accept', 'application/rdap+json,*/*');

    SS := TRawByteStringStream.Create;
    try
      C.HTTPMethod('GET', AURL, SS, [200, 404, 429]);
      Result := SS.DataString;
      FRetryAfter := StrToIntDef(C.ResponseHeaders.Values['Retry-After'], 0);
    finally
      FLastHTTPCode := C.ResponseStatusCode;
      SS.Free;
    end;
  finally
    C.Free;
  end;
end;

constructor TRDAPClient.Create(const ABaseURL: string);
begin
  inherited Create;
  if ABaseURL <> '' then
    FBaseURL := ABaseURL;
  if (FBaseURL <> '') and (FBaseURL[Length(FBaseURL)] <> '/') then
    FBaseURL := FBaseURL + '/';
  FUserAgent := 'fp-rdap-client/1.0';
  FConnectTimeout := 15000;
  FIOTimeout := 30000;
end;

destructor TRDAPClient.Destroy;
begin
  ClearLastState;
  inherited Destroy;
end;

function TRDAPClient.ExecuteQuery(const APath, ABase: string): string;
var
  URL: string;
begin
  ClearLastState;
  URL := NormalizePath(ABase, APath);
  FLastURL := URL;
  try
    FLastRawJSON := DoHTTPGetJSON(URL, FUserAgent);
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
begin
  if Trim(ADomain) = '' then
    raise ERDAPError.Create('Domain is empty');
  if FBaseURL <> '' then
    Base := FBaseURL
  else if Assigned(FBootstrap) then
    Base := FBootstrap.GetBaseURLForDomain(ADomain)
  else
    raise ERDAPError.Create('No base URL and no bootstrap configured');
  Result := ExecuteQuery('domain/' + EncodePathSegment(Trim(ADomain)), Base);
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
end;

destructor TRDAPClientMock.Destroy;
begin
  FMockRequests.Free;
  inherited Destroy;
end;

procedure TRDAPClientMock.SetupMock(const AMockResponse: string; AHTTPCode: Integer);
begin
  FMockResponse := AMockResponse;
  FMockHTTPCode := AHTTPCode;
  FMockError := '';
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
    FLastHTTPCode := FMockHTTPCode;
    Result := FMockResponse;
  end;
end;

initialization
  // RDAP payloads and bootstrap files are guaranteed UTF-8 (RFC 9083/9224/9225),
  // and all strings of this library are UTF-8 by contract. On Windows with a
  // non-UTF-8 ANSI codepage fcl-json 3.2.2 mangles \uXXXX escapes (it decodes
  // them to the ANSI codepage and then re-decodes the result as UTF-8) and
  // distorts literal non-ASCII bytes (the system-codepage conversion at the
  // GetJSON call boundary). Making the default Ansistring codepage UTF-8 turns
  // every such conversion into an identity, so parsed strings keep their bytes.
  // NOTE: this affects the whole process using this unit, not just the library.
  DefaultSystemCodePage := CP_UTF8;

end.
