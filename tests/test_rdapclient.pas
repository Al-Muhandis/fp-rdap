unit test_rdapclient;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, SyncObjs, fpcunit, testregistry, rdapclient, blcksock;

const
  // Realistic subsets of the IANA bootstrap files (RFC 8524 / RFC 9224 / RFC 9225).
  BootstrapDNS =
    '{' +
    '  "version": "1.0",' +
    '  "publication": "2026-01-01T00:00:00Z",' +
    '  "services": [' +
    '    [["net", "com"], ["https://rdap.verisign.com/com/v1/", "https://rdap2.verisign.com/com/v1/"]],' +
    '    [["org"], ["https://rdap.pir.org/"]],' +
    '    [["co.uk", "org.uk"], ["https://rdap.nominet.uk/"]],' +
    '    [["uk"], ["https://rdap.ukregistry.example/"]],' +
    '    [["ru"], ["https://rdap.tcinet.ru/"]]' +
    '  ]' +
    '}';

  BootstrapIPv4 =
    '{' +
    '  "version": "1.0",' +
    '  "publication": "2026-01-01T00:00:00Z",' +
    '  "services": [' +
    '    [["8.0.0.0/8"], ["https://rdap.arin.net/registry/"]],' +
    '    [["8.8.8.0/24"], ["https://rdap.lucky.example/"]],' +
    '    [["192.0.2.0/24", "198.51.100.0/24"], ["https://rdap.test.example/"]],' +
    '    [["203.0.113.0/24"], ["https://rdap.test2.example/"]]' +
    '  ]' +
    '}';

  BootstrapIPv6 =
    '{' +
    '  "version": "1.0",' +
    '  "publication": "2026-01-01T00:00:00Z",' +
    '  "services": [' +
    '    [["2001:db8::/32"], ["https://rdap.db8.example/"]],' +
    '    [["2a00::/12"], ["https://rdap.ripe.example/"]],' +
    '    [["2620:0:2d0::/48"], ["https://rdap.v6nic.example/"]]' +
    '  ]' +
    '}';

type
  { Base test case: keeps a list of temp files created by MakeFile and
    deletes them in TearDown. }

  TRDAPTestCase = class(TTestCase)
  private
    FFiles: TStringList;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
    { Writes AContent to a temp file (deleted in TearDown). AEncoding = nil
      keeps the TStringList default (system ANSI); pass TEncoding.UTF8 to
      simulate a real bootstrap file. }
    function MakeFile(const AContent: string; AEncoding: TEncoding = nil): string;
  end;

  { TTestIPUtils - pure helper functions, no I/O }

  TTestIPUtils = class(TRDAPTestCase)
  published
    procedure TestStrToIPv4_OK;
    procedure TestStrToIPv4_Invalid;
    procedure TestStrToIPv6_OK;
    procedure TestStrToIPv6_Invalid;
    procedure TestIPv4InNetwork;
    procedure TestIPv4InNetwork_EdgePrefixes;
    procedure TestIPv6InNetwork;
    procedure TestDomainMatchesKey;
    procedure TestDomainToASCII;
    procedure TestEncodePathSegment;
    procedure TestParseRetryAfter;
  end;

  { TTestBootstrap - bootstrap file loading and server lookup }

  TTestBootstrap = class(TRDAPTestCase)
  private
    FBootstrap: TRDAPBootstrap;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
    procedure LoadAll;
  published
    procedure TestGetBaseURLForDomain;
    procedure TestGetBaseURLForDomain_MultiLabelTLD;
    procedure TestGetBaseURLForDomain_CaseInsensitive;
    procedure TestGetBaseURLForDomain_NotFound;
    procedure TestGetBaseURLForDomain_Reload;
    procedure TestGetBaseURLForIP_IPv4;
    procedure TestGetBaseURLForIP_IPv4_LongestPrefixWins;
    procedure TestGetBaseURLForIP_IPv6;
    procedure TestGetBaseURLForIP_Invalid;
    procedure TestGetBaseURLForIP_NotFound;
    procedure TestNotLoaded;
    procedure TestLoadFromLocalFiles_SkipsEmptyNames;
    procedure TestLoadFromLocalFiles_MissingFile;
    procedure TestLoad_InvalidJSON;
    procedure TestLoadDNS_UTF8File;
    procedure TestLoadDNSFromString;
    procedure TestLoadDNSFromString_InvalidJSON;
    procedure TestFailedReload_KeepsPreviousData;
    procedure TestServiceURL_MalformedURLs;
    procedure TestLoadIPv4IPv6FromString;
  end;

  { TTestRDAPClient - client behaviour on a mocked network layer }

  TTestRDAPClient = class(TRDAPTestCase)
  private
    FClient: TRDAPClientMock;
    FMockJSON: string;
    FMockJSONIP: string;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
    function NewDNSBootstrap: TRDAPBootstrap;
  published
    procedure TestConstructor;
    procedure TestConstructor_BaseURLStoredAsIs;
    procedure TestMaxResponseSize_Default;
    procedure TestMaxResponseSize_Exceeded;
    procedure TestMaxResponseSize_Boundary;
    procedure TestMaxResponseSize_Unlimited;
    procedure TestQueryDomain_Mock;
    procedure TestQueryDomain_BaseURLNormalized;
    procedure TestQueryDomain_BaseURLOverridesBootstrap;
    procedure TestQueryDomain_UsesBootstrapBaseURL;
    procedure TestQueryDomain_NoBaseNoBootstrap;
    procedure TestQueryDomain_EmptyDomain;
    procedure TestQueryDomain_ULabelToALabel;
    procedure TestQueryDomain_ALabelPassThrough;
    procedure TestQueryDomain_BootstrapWithULabel;
    procedure TestQueryDomain_RejectsInvalidDomain;
    procedure TestQueryIP_Mock;
    procedure TestQueryIP_IPv6;
    procedure TestQueryIP_InvalidIP;
    procedure TestQueryIP_UsesBootstrapBaseURL;
    procedure TestQueryAutNum;
    procedure TestQueryAutNum_NoBaseURL;
    procedure TestQueryEntity;
    procedure TestQueryEntity_EncodesPath;
    procedure TestGetObjectTitle_PrefersHandle;
    procedure TestGetObjectTitle_FallsBackToName;
    procedure TestGetObjectType;
    procedure TestLastStatusNotFound;
    procedure TestNotFound_KeepsErrorBody;
    procedure TestRateLimited;
    procedure TestErrorStatusCodes_KeepErrorObject;
    procedure TestErrorStatus_NonJSONBody;
    procedure TestRetryAfter_Seconds;
    procedure TestRetryAfter_HTTPDate;
    procedure TestRetryAfter_AbsentAndNotCarriedOver;
    procedure TestErrorTitle_UTF8;
    procedure TestParseBoundary_NonUtf8DefaultCodepage;
    procedure TestUnexpectedStatus_Raises;
    procedure TestNetworkError_Wrapped;
    procedure TestMalformed200JSON;
    procedure TestMockRecordsRequests;
  end;

  { SOCKS5 loopback stub for the proxy-path tests: a thread with a Synapse
    TTCPBlockSocket listening on 127.0.0.1:<ephemeral port>. No network and
    no DNS are ever touched - the stub serves each connection with the SOCKS5
    handshake (no-auth, or RFC 1929 user/pass when AuthUser is set), a CONNECT
    reply (success, or a configured non-zero failure code) and the next canned
    raw HTTP response from Responses (the last one repeats), independently of
    the CONNECT target. 'Connection: close' in the canned responses makes the
    client reconnect per pass, so the redirect test can count connections. }

  TSOCKS5Stub = class;

  TSOCKS5StubThread = class(TThread)
  private
    FStub: TSOCKS5Stub;
  protected
    procedure Execute; override;
    // Full SOCKS5 dialogue of one accepted client connection.
    procedure ServeClient(ASock: TTCPBlockSocket);
  public
    constructor Create(AStub: TSOCKS5Stub);
  end;

  TSOCKS5Stub = class
  private
    FThread: TSOCKS5StubThread;
    FReady: TEvent;         // signaled when the port is bound
    FPort: Word;
    FResponses: TStringList; // canned raw HTTP responses, last repeats
    FAuthUser: string;       // AuthUser <> '' = user/pass required
    FAuthPass: string;
    FAuthSeenUser: string;   // credentials presented by the last handshake
    FAuthSeenPass: string;
    FConnectReply: Byte;     // CONNECT REP code, 0 = success
    FConnections: Integer;  // accepted connections
    FServed: Integer;        // canned responses handed out
    FLastTarget: string;     // "host:port" requested by the last CONNECT
  public
    constructor Create;
    destructor Destroy; override;
    property Responses: TStringList read FResponses;
    property AuthUser: string read FAuthUser write FAuthUser;
    property AuthPass: string read FAuthPass write FAuthPass;
    property AuthSeenUser: string read FAuthSeenUser;
    property AuthSeenPass: string read FAuthSeenPass;
    property ConnectReply: Byte read FConnectReply write FConnectReply;
    property Port: Word read FPort;
    property Connections: Integer read FConnections;
    property LastTarget: string read FLastTarget;
  end;

  { TTestProxyClient - the SOCKS5-proxy transport (Synapse path) against the
    loopback stub: both the proxy and the request targets are loopback names,
    so no DNS and no external network are involved. }

  TTestProxyClient = class(TRDAPTestCase)
  private
    FStub: TSOCKS5Stub;
    FClient: TRDAPClient;
    function HTTPResponse(ACode: Integer; const AReason, ABody: string;
      const AExtra: array of string): string;
    procedure ConfigureProxy;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestProxyDefaults;
    procedure TestProxy_200JSON;
    procedure TestProxy_429RetryAfter;
    procedure TestProxy_ConnectRefused;
    procedure TestProxy_Redirect302;
    procedure TestProxy_RedirectRelativeLocation_Raises;
    procedure TestProxy_UserPassAuth;
    procedure TestProxy_AuthRejected;
  end;

implementation

var
  GFileCounter: Integer = 0;

{ TRDAPTestCase }

procedure TRDAPTestCase.SetUp;
begin
  inherited SetUp;
  FFiles := TStringList.Create;
end;

procedure TRDAPTestCase.TearDown;
var
  I: Integer;
begin
  for I := 0 to FFiles.Count - 1 do
    DeleteFile(FFiles[I]);
  FFiles.Free;
  inherited TearDown;
end;

function TRDAPTestCase.MakeFile(const AContent: string; AEncoding: TEncoding): string;
begin
  Inc(GFileCounter);
  Result := GetTempDir(False) + Format('rdap-test-%d.json', [GFileCounter]);
  FFiles.Add(Result);
  with TStringList.Create do
  try
    Text := AContent;
    if AEncoding <> nil then
      SaveToFile(Result, AEncoding)
    else
      SaveToFile(Result);
  finally
    Free;
  end;
end;

{ TTestIPUtils }

procedure TTestIPUtils.TestStrToIPv4_OK;
var
  IP: Cardinal;
begin
  AssertTrue('parse 8.8.8.8', TryStrToIPv4('8.8.8.8', IP));
  AssertEquals(Int64($08080808), Int64(IP));
  AssertTrue('parse 192.0.2.1', TryStrToIPv4('192.0.2.1', IP));
  AssertEquals(Int64($C0000201), Int64(IP));
  AssertTrue('parse 0.0.0.0', TryStrToIPv4('0.0.0.0', IP));
  AssertEquals(0, Int64(IP));
  AssertTrue('parse 255.255.255.255', TryStrToIPv4('255.255.255.255', IP));
  AssertEquals(Int64($FFFFFFFF), Int64(IP));
end;

procedure TTestIPUtils.TestStrToIPv4_Invalid;
var
  IP: Cardinal;
begin
  AssertFalse('"256.1.1.1"', TryStrToIPv4('256.1.1.1', IP));
  AssertFalse('"1.2.3"', TryStrToIPv4('1.2.3', IP));
  AssertFalse('"1.2.3.4.5"', TryStrToIPv4('1.2.3.4.5', IP));
  AssertFalse('"a.b.c.d"', TryStrToIPv4('a.b.c.d', IP));
  AssertFalse('empty', TryStrToIPv4('', IP));
  AssertFalse('"1..2.3"', TryStrToIPv4('1..2.3', IP));
  AssertFalse('".1.2.3"', TryStrToIPv4('.1.2.3', IP));
  AssertFalse('"1.2.3.4."', TryStrToIPv4('1.2.3.4.', IP));
  AssertFalse('"-1.2.3.4"', TryStrToIPv4('-1.2.3.4', IP));
  AssertFalse('"+1.2.3.4"', TryStrToIPv4('+1.2.3.4', IP));
end;

procedure TTestIPUtils.TestStrToIPv6_OK;
var
  IP: TIPv6Bytes;
begin
  AssertTrue('parse "::"', TryStrToIPv6('::', IP));
  AssertEquals('all zero', 0, Integer(IP[15]));

  AssertTrue('parse "::1"', TryStrToIPv6('::1', IP));
  AssertEquals('byte 14 zero', 0, Integer(IP[14]));
  AssertEquals('byte 15 one', 1, Integer(IP[15]));

  AssertTrue('parse "2001:db8::1"', TryStrToIPv6('2001:db8::1', IP));
  AssertEquals('byte 0', $20, Integer(IP[0]));
  AssertEquals('byte 1', $01, Integer(IP[1]));
  AssertEquals('byte 2', $0D, Integer(IP[2]));
  AssertEquals('byte 3', $B8, Integer(IP[3]));
  AssertEquals('byte 15', $01, Integer(IP[15]));

  AssertTrue('parse full form', TryStrToIPv6('2001:db8:0:1:2:3:4:5', IP));
  AssertEquals('byte 8', 0, Integer(IP[8]));
  AssertEquals('byte 9', $02, Integer(IP[9]));
  AssertEquals('byte 15', $05, Integer(IP[15]));

  AssertTrue('parse embedded IPv4', TryStrToIPv6('::ffff:192.0.2.1', IP));
  AssertEquals('byte 10', $FF, Integer(IP[10]));
  AssertEquals('byte 11', $FF, Integer(IP[11]));
  AssertEquals('byte 12', $C0, Integer(IP[12]));
  AssertEquals('byte 15', $01, Integer(IP[15]));

  AssertTrue('parse "fe80::"', TryStrToIPv6('fe80::', IP));
  AssertEquals('byte 0', $FE, Integer(IP[0]));
  AssertEquals('byte 1', $80, Integer(IP[1]));

  AssertTrue('parse "1::"', TryStrToIPv6('1::', IP));
  AssertEquals('byte 1', $01, Integer(IP[1]));
  AssertEquals('byte 2', 0, Integer(IP[2]));
end;

procedure TTestIPUtils.TestStrToIPv6_Invalid;
var
  IP: TIPv6Bytes;
begin
  AssertFalse('empty', TryStrToIPv6('', IP));
  AssertFalse('IPv4 string', TryStrToIPv6('1.2.3.4', IP));
  AssertFalse('7 groups', TryStrToIPv6('1:2:3:4:5:6:7', IP));
  AssertFalse('9 groups', TryStrToIPv6('1:2:3:4:5:6:7:8:9', IP));
  AssertFalse('two "::"', TryStrToIPv6('1::2::3', IP));
  AssertFalse('group too long', TryStrToIPv6('12345::', IP));
  AssertFalse('bad hex', TryStrToIPv6('g::1', IP));
  AssertFalse('leading single colon', TryStrToIPv6(':1:2:3:4:5:6:7', IP));
  AssertFalse('trailing single colon', TryStrToIPv6('1:2:3:4:5:6:7:', IP));
  AssertFalse('zone id', TryStrToIPv6('fe80::1%eth0', IP));
  AssertFalse('8 groups plus "::"', TryStrToIPv6('1:2:3:4:5:6:7:8::', IP));
end;

procedure TTestIPUtils.TestIPv4InNetwork;
begin
  AssertTrue('8.8.8.8 in 8.0.0.0/8',
    IPv4InNetwork($08080808, $08000000, 8));
  AssertFalse('9.0.0.1 in 8.0.0.0/8',
    IPv4InNetwork($09000001, $08000000, 8));
  AssertTrue('192.0.2.130 in 192.0.2.0/24',
    IPv4InNetwork($C0000282, $C0000200, 24));
  AssertFalse('192.0.3.1 in 192.0.2.0/24',
    IPv4InNetwork($C0000301, $C0000200, 24));
  AssertTrue('203.0.113.200 in 203.0.113.128/25',
    IPv4InNetwork($CB0071C8, $CB007180, 25));
  AssertFalse('203.0.113.5 in 203.0.113.128/25',
    IPv4InNetwork($CB007105, $CB007180, 25));
end;

procedure TTestIPUtils.TestIPv4InNetwork_EdgePrefixes;
begin
  AssertTrue('/0 matches anything', IPv4InNetwork($01020304, 0, 0));
  AssertTrue('/32 exact match', IPv4InNetwork($08080808, $08080808, 32));
  AssertFalse('/32 different', IPv4InNetwork($08080809, $08080808, 32));
  AssertFalse('negative prefix', IPv4InNetwork($08080808, $08000000, -1));
  AssertFalse('prefix > 32', IPv4InNetwork($08080808, $08000000, 33));
end;

procedure TTestIPUtils.TestIPv6InNetwork;
var
  IP, Net: TIPv6Bytes;
begin
  AssertTrue('parse IP', TryStrToIPv6('2001:db8::1', IP));

  AssertTrue('parse net', TryStrToIPv6('2001:db8::', Net));
  AssertTrue('2001:db8::1 in 2001:db8::/32', IPv6InNetwork(IP, Net, 32));

  AssertTrue('parse net 2', TryStrToIPv6('2001:db9::', Net));
  AssertFalse('2001:db8::1 in 2001:db9::/32', IPv6InNetwork(IP, Net, 32));

  AssertTrue('parse net 3', TryStrToIPv6('2620:0:2d0::', Net));
  AssertFalse('/48 no match', IPv6InNetwork(IP, Net, 48));

  AssertTrue('parse net 4', TryStrToIPv6('2a00::', Net));
  AssertTrue('parse IP 2', TryStrToIPv6('2a01:4f8::1', IP));
  AssertTrue('2a01:: in 2a00::/12', IPv6InNetwork(IP, Net, 12));

  AssertTrue('/0 matches all', IPv6InNetwork(IP, Net, 0));
  AssertFalse('prefix > 128', IPv6InNetwork(IP, Net, 129));
end;

procedure TTestIPUtils.TestDomainMatchesKey;
begin
  AssertEquals('single label', 1, DomainMatchesKey('example.com', 'com'));
  AssertEquals('multi-label key', 2, DomainMatchesKey('a.b.example.co.uk', 'co.uk'));
  AssertEquals('exact match', 2, DomainMatchesKey('co.uk', 'co.uk'));
  AssertEquals('no match', 0, DomainMatchesKey('example.com', 'net'));
  AssertEquals('partial label does not match', 0, DomainMatchesKey('example.com', 'ample.com'));
  AssertEquals('longer domain than key', 1, DomainMatchesKey('example.com', 'com'));
end;

// U-label -> A-label conversion (RFC 3492 punycode + fp-idn IDNA mapping).
// Raw byte escapes keep the test independent of the system codepage (stage 1
// notes); the expected A-labels are the well-known punycode forms of these
// names, probed against fp-idn 1.1.0.0.
procedure TTestIPUtils.TestDomainToASCII;
const
  Prm = #$D0#$BF#$D1#$80#$D0#$B8#$D0#$BC#$D0#$B5#$D1#$80; // "пример"
  ULabelRF = Prm + '.' + #$D1#$80#$D1#$84;                // "пример.рф"
  ULabelRFUpper = #$D0#$9F#$D0#$A0#$D0#$98#$D0#$9C#$D0#$95#$D0#$A0 + '.' +
    #$D0#$A0#$D0#$A4;                                     // "ПРИМЕР.РФ"
  BUCHER = 'b' + #$C3#$BC + 'cher';                       // "bücher"
var
  Raised: Boolean;
begin
  // Lowercase LDH and already-converted names pass through byte-identical.
  AssertEquals('ASCII passthrough', 'example.com', DomainToASCII('example.com'));
  AssertEquals('A-label passthrough', 'xn--e1afmkfd.xn--p1ai',
    DomainToASCII('xn--e1afmkfd.xn--p1ai'));
  AssertEquals('empty', '', DomainToASCII(''));
  // fp-idn 1.1.0.0 folds ASCII/Cyrillic/Greek uppercase to lowercase, so
  // uppercase names reach the registered (lowercase) A-label.
  AssertEquals('ASCII uppercase folds to lowercase', 'example.com',
    DomainToASCII('Example.COM'));
  AssertEquals('uppercase U-label folds to registered A-label',
    'xn--e1afmkfd.xn--p1ai', DomainToASCII(ULabelRFUpper));
  // Each non-ASCII label becomes "xn--" + punycode.
  AssertEquals('full U-label name', 'xn--e1afmkfd.xn--p1ai', DomainToASCII(ULabelRF));
  AssertEquals('mixed LDH + U-label', 'xn--e1afmkfd.com', DomainToASCII(Prm + '.com'));
  AssertEquals('RFC 3492 vector', 'xn--bcher-kva.example',
    DomainToASCII(BUCHER + '.example'));
  // fp-idn validation rejects forbidden label characters (space, control
  // bytes); DomainToASCII raises instead of the plain wrapper's silent empty
  // result.
  Raised := False;
  try
    DomainToASCII('two words.example');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('message mentions the domain', Pos('two words.example', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected for a domain with a space', Raised);
end;

procedure TTestIPUtils.TestEncodePathSegment;
begin
  AssertEquals('plain kept', 'example.com', EncodePathSegment('example.com'));
  AssertEquals('space encoded', 'a%20b', EncodePathSegment('a b'));
  AssertEquals('slash encoded', 'a%2Fb', EncodePathSegment('a/b'));
  AssertEquals('unreserved kept', 'ABC-123_~.x', EncodePathSegment('ABC-123_~.x'));
  AssertEquals('empty', '', EncodePathSegment(''));
end;

procedure TTestIPUtils.TestParseRetryAfter;
var
  S: Integer;
begin
  // Delay-seconds form
  AssertTrue('seconds', TryParseRetryAfter('120', S));
  AssertEquals('seconds value', 120, S);
  AssertTrue('padded seconds', TryParseRetryAfter(' 7 ', S));
  AssertEquals('padded seconds value', 7, S);
  AssertTrue('zero seconds', TryParseRetryAfter('0', S));
  AssertEquals('zero seconds value', 0, S);
  // Absent or unparseable: False and 0
  AssertFalse('empty', TryParseRetryAfter('', S));
  AssertEquals('empty value', 0, S);
  AssertFalse('whitespace only', TryParseRetryAfter('  ', S));
  AssertFalse('garbage', TryParseRetryAfter('soon', S));
  AssertFalse('negative seconds', TryParseRetryAfter('-5', S));
  AssertFalse('fractional seconds', TryParseRetryAfter('1.5', S));
  AssertFalse('overflow seconds', TryParseRetryAfter('99999999999999999999', S));
  // HTTP-date form: past date yields 0, future date yields positive seconds
  AssertTrue('past date', TryParseRetryAfter('Sat, 01 Jan 2000 00:00:00 GMT', S));
  AssertEquals('past date value', 0, S);
  AssertTrue('future date', TryParseRetryAfter('Sat, 01 Jan 2050 00:00:00 GMT', S));
  // Upper bound is guaranteed by the API (out Integer, values clamped internally).
  AssertTrue('future date value positive', S > 0);
  AssertFalse('date without GMT', TryParseRetryAfter('Sat, 01 Jan 2050 00:00:00 UTC', S));
  AssertFalse('obsolete RFC 850 date', TryParseRetryAfter('Sunday, 06-Nov-94 08:49:37 GMT', S));
  AssertFalse('bad month', TryParseRetryAfter('Sun, 06 Foo 1994 08:49:37 GMT', S));
end;

{ TTestBootstrap }

procedure TTestBootstrap.SetUp;
begin
  inherited SetUp;
  FBootstrap := TRDAPBootstrap.Create;
end;

procedure TTestBootstrap.TearDown;
begin
  FBootstrap.Free;
  inherited TearDown;
end;

procedure TTestBootstrap.LoadAll;
begin
  FBootstrap.LoadFromLocalFiles(MakeFile(BootstrapDNS), MakeFile(BootstrapIPv4),
    MakeFile(BootstrapIPv6));
end;

procedure TTestBootstrap.TestGetBaseURLForDomain;
begin
  LoadAll;
  AssertEquals('com', 'https://rdap.verisign.com/com/v1/',
    FBootstrap.GetBaseURLForDomain('example.com'));
  AssertEquals('net', 'https://rdap.verisign.com/com/v1/',
    FBootstrap.GetBaseURLForDomain('example.net'));
  AssertEquals('org', 'https://rdap.pir.org/',
    FBootstrap.GetBaseURLForDomain('example.org'));
  AssertEquals('ru', 'https://rdap.tcinet.ru/',
    FBootstrap.GetBaseURLForDomain('example.ru'));
end;

procedure TTestBootstrap.TestGetBaseURLForDomain_MultiLabelTLD;
begin
  LoadAll;
  AssertEquals('co.uk', 'https://rdap.nominet.uk/',
    FBootstrap.GetBaseURLForDomain('example.co.uk'));
  AssertEquals('org.uk', 'https://rdap.nominet.uk/',
    FBootstrap.GetBaseURLForDomain('foo.org.uk'));
  AssertEquals('deeper domain', 'https://rdap.nominet.uk/',
    FBootstrap.GetBaseURLForDomain('a.b.example.co.uk'));
  AssertEquals('plain uk still works', 'https://rdap.ukregistry.example/',
    FBootstrap.GetBaseURLForDomain('example.uk'));
end;

procedure TTestBootstrap.TestGetBaseURLForDomain_CaseInsensitive;
begin
  LoadAll;
  AssertEquals('COM', 'https://rdap.verisign.com/com/v1/',
    FBootstrap.GetBaseURLForDomain('Example.COM'));
  AssertEquals('CO.UK', 'https://rdap.nominet.uk/',
    FBootstrap.GetBaseURLForDomain('EXAMPLE.Co.UK'));
end;

procedure TTestBootstrap.TestGetBaseURLForDomain_NotFound;
var
  Raised: Boolean;
begin
  LoadAll;
  Raised := False;
  try
    FBootstrap.GetBaseURLForDomain('example.xyz');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('message mentions the domain', Pos('example.xyz', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
end;

procedure TTestBootstrap.TestGetBaseURLForDomain_Reload;
begin
  FBootstrap.LoadDNS(MakeFile(BootstrapDNS));
  FBootstrap.LoadDNS(MakeFile(BootstrapDNS));
  AssertEquals('works after reload', 'https://rdap.pir.org/',
    FBootstrap.GetBaseURLForDomain('example.org'));
end;

procedure TTestBootstrap.TestGetBaseURLForIP_IPv4;
begin
  LoadAll;
  AssertEquals('192.0.2.55', 'https://rdap.test.example/',
    FBootstrap.GetBaseURLForIP('192.0.2.55'));
  AssertEquals('198.51.100.7', 'https://rdap.test.example/',
    FBootstrap.GetBaseURLForIP('198.51.100.7'));
  AssertEquals('203.0.113.77', 'https://rdap.test2.example/',
    FBootstrap.GetBaseURLForIP('203.0.113.77'));
end;

procedure TTestBootstrap.TestGetBaseURLForIP_IPv4_LongestPrefixWins;
begin
  LoadAll;
  // matches both 8.0.0.0/8 (arin) and 8.8.8.0/24 (lucky): /24 must win
  AssertEquals('longest prefix', 'https://rdap.lucky.example/',
    FBootstrap.GetBaseURLForIP('8.8.8.8'));
  // only /8 matches
  AssertEquals('single match', 'https://rdap.arin.net/registry/',
    FBootstrap.GetBaseURLForIP('8.8.4.4'));
end;

procedure TTestBootstrap.TestGetBaseURLForIP_IPv6;
begin
  LoadAll;
  AssertEquals('2001:db8::1', 'https://rdap.db8.example/',
    FBootstrap.GetBaseURLForIP('2001:db8::1'));
  AssertEquals('2a01:4f8::1', 'https://rdap.ripe.example/',
    FBootstrap.GetBaseURLForIP('2a01:4f8::1'));
  AssertEquals('2620:0:2d0:200::1', 'https://rdap.v6nic.example/',
    FBootstrap.GetBaseURLForIP('2620:0:2d0:200::1'));
end;

procedure TTestBootstrap.TestGetBaseURLForIP_Invalid;
var
  Raised: Boolean;
begin
  LoadAll;
  Raised := False;
  try
    FBootstrap.GetBaseURLForIP('999.1.1.1');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('mentions "Invalid IP"', Pos('Invalid IP', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
end;

procedure TTestBootstrap.TestGetBaseURLForIP_NotFound;
var
  Raised: Boolean;
begin
  LoadAll;
  Raised := False;
  try
    FBootstrap.GetBaseURLForIP('9.9.9.9');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('mentions "No RDAP server"', Pos('No RDAP server', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);

  Raised := False;
  try
    FBootstrap.GetBaseURLForIP('::1');
  except
    on E: ERDAPError do
      Raised := True;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('IPv6 not covered either', Raised);
end;

procedure TTestBootstrap.TestNotLoaded;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    FBootstrap.GetBaseURLForDomain('example.com');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('DNS message', Pos('DNS bootstrap not loaded', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);

  Raised := False;
  try
    FBootstrap.GetBaseURLForIP('8.8.8.8');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('IPv4 message', Pos('IPv4 bootstrap not loaded', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);

  Raised := False;
  try
    FBootstrap.GetBaseURLForIP('::1');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('IPv6 message', Pos('IPv6 bootstrap not loaded', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
end;

procedure TTestBootstrap.TestLoadFromLocalFiles_SkipsEmptyNames;
var
  Raised: Boolean;
begin
  FBootstrap.LoadFromLocalFiles(MakeFile(BootstrapDNS), '', '');
  AssertEquals('DNS still works', 'https://rdap.pir.org/',
    FBootstrap.GetBaseURLForDomain('example.org'));

  Raised := False;
  try
    FBootstrap.GetBaseURLForIP('8.8.8.8');
  except
    on E: ERDAPError do
      Raised := True;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('IPv4 skipped', Raised);
end;

procedure TTestBootstrap.TestLoadFromLocalFiles_MissingFile;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    FBootstrap.LoadDNS('no-such-file.json');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('mentions "not found"', Pos('not found', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
end;

procedure TTestBootstrap.TestLoad_InvalidJSON;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    FBootstrap.LoadDNS(MakeFile('this is not json'));
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('mentions JSON parse', Pos('JSON parse', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
end;

// Bootstrap files are UTF-8 (RFC 9224/9225): a non-ASCII URL stored in a
// UTF-8 file must be read back byte-identical, not decoded as system ANSI.
procedure TTestBootstrap.TestLoadDNS_UTF8File;
const
  RawTest = #$D1#$82#$D0#$B5#$D1#$81#$D1#$82; // "тест" as raw UTF-8 bytes
begin
  FBootstrap.LoadDNS(MakeFile(
    '{"version":"1.0","publication":"2026-01-01T00:00:00Z","services":' +
    '[[["test"],["https://rdap.' + RawTest + '.example/v1/"]]]}', TEncoding.UTF8));
  AssertEquals('UTF-8 URL read back intact',
    'https://rdap.' + RawTest + '.example/v1/',
    FBootstrap.GetBaseURLForDomain('example.test'));
end;

procedure TTestBootstrap.TestLoadDNSFromString;
var
  Raised: Boolean;
begin
  FBootstrap.LoadDNSFromString(BootstrapDNS);
  AssertEquals('com via embedded string', 'https://rdap.verisign.com/com/v1/',
    FBootstrap.GetBaseURLForDomain('example.com'));
  AssertEquals('ru via embedded string', 'https://rdap.tcinet.ru/',
    FBootstrap.GetBaseURLForDomain('example.ru'));

  // Repeated load fully replaces the content.
  FBootstrap.LoadDNSFromString('{"services":[[["ru"],["https://rdap2.tcinet.ru/"]]]}');
  AssertEquals('content replaced by reload', 'https://rdap2.tcinet.ru/',
    FBootstrap.GetBaseURLForDomain('example.ru'));

  // ...and the keys of the previous load are gone.
  Raised := False;
  try
    FBootstrap.GetBaseURLForDomain('example.com');
  except
    on E: ERDAPError do
      Raised := True;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('old keys are gone after reload', Raised);
end;

procedure TTestBootstrap.TestLoadDNSFromString_InvalidJSON;
var
  Raised: Boolean;
begin
  Raised := False;
  try
    FBootstrap.LoadDNSFromString('not json at all');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('mentions JSON parse', Pos('JSON parse', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);

  Raised := False;
  try
    FBootstrap.LoadDNSFromString('');
  except
    on E: ERDAPError do
      Raised := True;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('empty string raises too', Raised);

  // Nothing was loaded, so lookups still report the bootstrap as unloaded.
  Raised := False;
  try
    FBootstrap.GetBaseURLForDomain('example.com');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('still "not loaded"', Pos('not loaded', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('bootstrap stays unloaded', Raised);
end;

// Parse-then-swap: a failed reload (garbage file, valid JSON without
// "services", missing file) must leave the previously loaded bootstrap
// fully operational.
procedure TTestBootstrap.TestFailedReload_KeepsPreviousData;
var
  Raised: Boolean;
begin
  FBootstrap.LoadDNS(MakeFile(BootstrapDNS));

  Raised := False;
  try
    FBootstrap.LoadDNS(MakeFile('this is not json'));
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('mentions JSON parse', Pos('JSON parse', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
  AssertEquals('old DNS data survives a broken reload', 'https://rdap.pir.org/',
    FBootstrap.GetBaseURLForDomain('example.org'));

  Raised := False;
  try
    FBootstrap.LoadDNS(MakeFile('{"version":"1.0"}'));
  except
    on E: ERDAPError do
      Raised := True;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
  AssertEquals('old DNS data survives a services-less reload',
    'https://rdap.verisign.com/com/v1/',
    FBootstrap.GetBaseURLForDomain('example.com'));

  Raised := False;
  try
    FBootstrap.LoadDNS('no-such-bootstrap-file.json');
  except
    on E: ERDAPError do
      Raised := True;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
  AssertEquals('old DNS data survives a missing file', 'https://rdap.tcinet.ru/',
    FBootstrap.GetBaseURLForDomain('example.ru'));
end;

procedure TTestBootstrap.TestServiceURL_MalformedURLs;
var
  Raised: Boolean;

  // Loads AJSON as the DNS bootstrap and expects the lookup of example.com
  // (key "com") to fail with ERDAPError whose message contains AFragment -
  // which includes the entry number, as every ServiceURL error must.
  procedure ExpectLookupError(const AJSON, AFragment: string);
  begin
    FBootstrap.LoadDNSFromString(AJSON);
    Raised := False;
    try
      FBootstrap.GetBaseURLForDomain('example.com');
    except
      on E: ERDAPError do
      begin
        Raised := True;
        AssertTrue('"' + AFragment + '" expected in "' + E.Message + '"',
          Pos(AFragment, E.Message) > 0);
      end;
      on E: Exception do
        Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
    end;
    AssertTrue('ERDAPError expected', Raised);
  end;

begin
  // URL element that is not a string (a number)
  ExpectLookupError('{"services":[[["com"],[123]]]}',
    'Service 0: URL 0 is not a string');
  // Empty URL string
  ExpectLookupError('{"services":[[["com"],[""]]]}',
    'Service 0 has an empty base URL');
  // Empty URL array
  ExpectLookupError('{"services":[[["com"],[]]]}',
    'Service 0 has an empty URL list');
  // URL part of a wrong type (neither array nor string)
  ExpectLookupError('{"services":[[["com"],{"url":"https://x/"}]]}',
    'Service 0: URL part is neither an array nor a string');
end;

// The string variants of the IP bootstraps work like LoadDNSFromString.
procedure TTestBootstrap.TestLoadIPv4IPv6FromString;
begin
  FBootstrap.LoadIPv4FromString(BootstrapIPv4);
  FBootstrap.LoadIPv6FromString(BootstrapIPv6);
  AssertEquals('IPv4 via string', 'https://rdap.lucky.example/',
    FBootstrap.GetBaseURLForIP('8.8.8.8'));
  AssertEquals('IPv6 via string', 'https://rdap.db8.example/',
    FBootstrap.GetBaseURLForIP('2001:db8::1'));
end;

{ TTestRDAPClient }

const
  // English short names exactly as an HTTP server sends them (RFC 7231 §7.1.1.1).
  HTTPDayNames: array[1..7] of string = ('Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat');
  HTTPMonthNames: array[1..12] of string = ('Jan', 'Feb', 'Mar', 'Apr', 'May',
    'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec');

// Formats D as an IMF-fixdate HTTP-date, e.g. 'Sun, 06 Nov 1994 08:49:37 GMT'.
function FormatHTTPDate(D: TDateTime): string;
var
  Y, M, Day, H, Min, S, MS: Word;
begin
  DecodeDate(D, Y, M, Day);
  DecodeTime(D, H, Min, S, MS);
  Result := Format('%s, %.2d %s %.4d %.2d:%.2d:%.2d GMT',
    [HTTPDayNames[DayOfWeek(D)], Day, HTTPMonthNames[M], Y, H, Min, S]);
end;

procedure TTestRDAPClient.SetUp;
begin
  inherited SetUp;
  FClient := TRDAPClientMock.Create;
  FMockJSON := '{"objectClassName":"domain","handle":"example.com","ldhName":"example.com"}';
  FMockJSONIP := '{"objectClassName":"ip network","handle":"8.8.8.8/32"}';
end;

procedure TTestRDAPClient.TearDown;
begin
  FClient.Free;
  inherited TearDown;
end;

function TTestRDAPClient.NewDNSBootstrap: TRDAPBootstrap;
begin
  Result := TRDAPBootstrap.Create;
  Result.LoadDNS(MakeFile(BootstrapDNS));
end;

procedure TTestRDAPClient.TestConstructor;
begin
  AssertEquals('default base URL is empty', '', FClient.BaseURL);
  AssertEquals('default user agent', 'fp-rdap-client/1.0', FClient.UserAgent);
  AssertTrue('initial status', FClient.LastStatus = rqsNone);
  AssertEquals('no requests yet', 0, FClient.MockRequestCount);
end;

// BaseURL is stored as given: the trailing '/' is appended by NormalizePath
// at query time, the property keeps the constructor value verbatim.
procedure TTestRDAPClient.TestConstructor_BaseURLStoredAsIs;
var
  C: TRDAPClientMock;
begin
  C := TRDAPClientMock.Create('https://rdap.example.org');
  try
    AssertEquals('stored as given', 'https://rdap.example.org', C.BaseURL);
    C.SetupMock(FMockJSON);
    C.QueryDomain('example.com');
    AssertEquals('query URL still normalized',
      'https://rdap.example.org/domain/example.com', C.LastURL);
  finally
    C.Free;
  end;
end;

procedure TTestRDAPClient.TestQueryDomain_Mock;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock(FMockJSON);
  AssertEquals('raw JSON returned', FMockJSON, FClient.QueryDomain('example.com'));
  AssertEquals('request URL', 'https://rdap.example.org/domain/example.com',
    FClient.LastURL);
  AssertTrue('status OK', FClient.LastStatus = rqsOK);
  AssertEquals('title', 'example.com', FClient.GetObjectTitle);
end;

procedure TTestRDAPClient.TestQueryDomain_BaseURLNormalized;
begin
  FClient.BaseURL := 'https://rdap.example.org/';
  FClient.SetupMock(FMockJSON);
  FClient.QueryDomain('example.com');
  AssertEquals('no double slash', 'https://rdap.example.org/domain/example.com',
    FClient.LastURL);
end;

procedure TTestRDAPClient.TestQueryDomain_BaseURLOverridesBootstrap;
var
  B: TRDAPBootstrap;
begin
  B := NewDNSBootstrap;
  try
    FClient.Bootstrap := B;
    FClient.BaseURL := 'https://rdap.example.org';
    FClient.SetupMock(FMockJSON);
    FClient.QueryDomain('example.com');
    AssertEquals('base URL wins over bootstrap',
      'https://rdap.example.org/domain/example.com', FClient.LastURL);
  finally
    B.Free;
  end;
end;

procedure TTestRDAPClient.TestQueryDomain_UsesBootstrapBaseURL;
var
  B: TRDAPBootstrap;
begin
  B := NewDNSBootstrap;
  try
    FClient.Bootstrap := B;
    FClient.SetupMock(FMockJSON);
    FClient.QueryDomain('example.com');
    AssertEquals('bootstrap URL is actually used',
      'https://rdap.verisign.com/com/v1/domain/example.com', FClient.LastURL);
  finally
    B.Free;
  end;
end;

procedure TTestRDAPClient.TestQueryDomain_NoBaseNoBootstrap;
var
  Raised: Boolean;
begin
  FClient.SetupMock(FMockJSON);
  Raised := False;
  try
    FClient.QueryDomain('example.com');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('message', Pos('No base URL', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
  AssertEquals('no request performed', 0, FClient.MockRequestCount);
end;

procedure TTestRDAPClient.TestQueryDomain_EmptyDomain;
var
  Raised: Boolean;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock(FMockJSON);
  Raised := False;
  try
    FClient.QueryDomain('   ');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('message', Pos('Domain is empty', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
  AssertEquals('no request performed', 0, FClient.MockRequestCount);
end;

// RFC 9082 expects A-labels (punycode) in the URL path: a U-label is converted
// to its A-label form instead of being rejected (the pre-backlog behavior).
// Raw byte escapes keep the test independent of the system codepage (stage 1
// notes).
procedure TTestRDAPClient.TestQueryDomain_ULabelToALabel;
const
  Prm = #$D0#$BF#$D1#$80#$D0#$B8#$D0#$BC#$D0#$B5#$D1#$80; // "пример"
  ULabelRF = Prm + '.' + #$D1#$80#$D1#$84;                // "пример.рф"
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock(FMockJSON);
  AssertEquals('raw JSON returned', FMockJSON, FClient.QueryDomain(ULabelRF));
  AssertEquals('U-label converted to A-label',
    'https://rdap.example.org/domain/xn--e1afmkfd.xn--p1ai', FClient.LastURL);
  // A mixed LDH + U-label name converts only the non-ASCII label.
  FClient.QueryDomain(Prm + '.com');
  AssertEquals('mixed name converted',
    'https://rdap.example.org/domain/xn--e1afmkfd.com', FClient.LastURL);
end;

procedure TTestRDAPClient.TestQueryDomain_ALabelPassThrough;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock(FMockJSON);
  FClient.QueryDomain('xn--e1afmkfd.xn--p1ai');
  AssertEquals('already-converted A-label unchanged',
    'https://rdap.example.org/domain/xn--e1afmkfd.xn--p1ai', FClient.LastURL);
end;

// The conversion runs before the bootstrap lookup: RFC 9224 files list IDN
// TLD keys in A-label form (the official dns.json is ASCII-only), so the
// U-label must be converted to hit the right service entry.
procedure TTestRDAPClient.TestQueryDomain_BootstrapWithULabel;
const
  BootstrapDNSIDN =
    '{' +
    '  "services": [' +
    '    [["xn--p1ai"], ["https://rdap.tld.rf/"]],' +
    '    [["com"], ["https://rdap.verisign.com/com/v1/"]]' +
    '  ]' +
    '}';
var
  B: TRDAPBootstrap;
begin
  B := TRDAPBootstrap.Create;
  try
    B.LoadDNSFromString(BootstrapDNSIDN);
    FClient.Bootstrap := B;
    FClient.SetupMock(FMockJSON);
    FClient.QueryDomain(
      #$D0#$BF#$D1#$80#$D0#$B8#$D0#$BC#$D0#$B5#$D1#$80 + '.' +
      #$D1#$80#$D1#$84); // "пример.рф"
    AssertEquals('bootstrap entry found via converted A-label',
      'https://rdap.tld.rf/domain/xn--e1afmkfd.xn--p1ai', FClient.LastURL);
  finally
    B.Free;
  end;
end;

// fp-idn 1.1.0.0 rejects forbidden label characters (here: a space) and
// DomainToASCII surfaces that as ERDAPError, so the query never reaches the
// network. Before fp-idn gained label validation this domain was silently
// percent-encoded into the URL path ("two%20words.example").
procedure TTestRDAPClient.TestQueryDomain_RejectsInvalidDomain;
var
  Raised: Boolean;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock(FMockJSON);
  Raised := False;
  try
    FClient.QueryDomain('two words.example');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('message mentions the domain', Pos('two words.example', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
  AssertEquals('no request URL built', '', FClient.LastURL);
end;

procedure TTestRDAPClient.TestQueryIP_Mock;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock(FMockJSONIP);
  AssertEquals('raw JSON returned', FMockJSONIP, FClient.QueryIP('8.8.8.8'));
  AssertEquals('request URL', 'https://rdap.example.org/ip/8.8.8.8', FClient.LastURL);
  AssertEquals('object type', 'ip network', FClient.GetObjectType);
end;

procedure TTestRDAPClient.TestQueryIP_IPv6;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock('{}');
  FClient.QueryIP('2001:db8::1');
  AssertEquals('request URL', 'https://rdap.example.org/ip/2001:db8::1', FClient.LastURL);
end;

procedure TTestRDAPClient.TestQueryIP_InvalidIP;
var
  Raised: Boolean;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock(FMockJSONIP);
  Raised := False;
  try
    FClient.QueryIP('999.1.2.3');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('message', Pos('Invalid IP', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
  AssertEquals('no request performed', 0, FClient.MockRequestCount);
end;

procedure TTestRDAPClient.TestQueryIP_UsesBootstrapBaseURL;
var
  B: TRDAPBootstrap;
begin
  B := TRDAPBootstrap.Create;
  try
    B.LoadIPv4(MakeFile(BootstrapIPv4));
    B.LoadIPv6(MakeFile(BootstrapIPv6));
    FClient.Bootstrap := B;
    FClient.SetupMock('{}');
    FClient.QueryIP('8.8.8.8');
    AssertEquals('IPv4 bootstrap URL used',
      'https://rdap.lucky.example/ip/8.8.8.8', FClient.LastURL);
    FClient.QueryIP('2001:db8::1');
    AssertEquals('IPv6 bootstrap URL used',
      'https://rdap.db8.example/ip/2001:db8::1', FClient.LastURL);
  finally
    B.Free;
  end;
end;

procedure TTestRDAPClient.TestQueryAutNum;
begin
  FClient.BaseURL := 'https://rdap.db.ripe.net';
  FClient.SetupMock('{"objectClassName":"autnum"}');
  FClient.QueryAutNum('AS3356');
  AssertEquals('request URL', 'https://rdap.db.ripe.net/autnum/AS3356', FClient.LastURL);
end;

procedure TTestRDAPClient.TestQueryAutNum_NoBaseURL;
var
  Raised: Boolean;
begin
  FClient.SetupMock('{}');
  Raised := False;
  try
    FClient.QueryAutNum('AS3356');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('message', Pos('Base URL not set', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
end;

procedure TTestRDAPClient.TestQueryEntity;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock('{"objectClassName":"entity","handle":"ABC-123"}');
  FClient.QueryEntity('ABC-123');
  AssertEquals('request URL', 'https://rdap.example.org/entity/ABC-123', FClient.LastURL);
end;

procedure TTestRDAPClient.TestQueryEntity_EncodesPath;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock('{}');
  FClient.QueryEntity('JOHN DOE');
  AssertTrue('space percent-encoded in ' + FClient.LastURL,
    Pos('JOHN%20DOE', FClient.LastURL) > 0);
end;

procedure TTestRDAPClient.TestGetObjectTitle_PrefersHandle;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock(FMockJSON);
  FClient.QueryDomain('example.com');
  AssertEquals('handle wins over ldhName', 'example.com', FClient.GetObjectTitle);
end;

procedure TTestRDAPClient.TestGetObjectTitle_FallsBackToName;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock('{"objectClassName":"entity","name":"Some Body"}');
  FClient.QueryEntity('XYZ');
  AssertEquals('name fallback', 'Some Body', FClient.GetObjectTitle);
end;

procedure TTestRDAPClient.TestGetObjectType;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock(FMockJSON);
  FClient.QueryDomain('example.com');
  AssertEquals('object type', 'domain', FClient.GetObjectType);
end;

procedure TTestRDAPClient.TestLastStatusNotFound;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock('', 404);
  FClient.QueryDomain('missing.com');
  AssertTrue('status is rqsNotFound', FClient.LastStatus = rqsNotFound);
  AssertEquals('empty title', '', FClient.GetObjectTitle);
  AssertEquals('empty type', '', FClient.GetObjectType);
end;

procedure TTestRDAPClient.TestNotFound_KeepsErrorBody;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock('{"errorCode":404,"title":"Object not found"}', 404);
  FClient.QueryDomain('missing.com');
  AssertTrue('status is rqsNotFound', FClient.LastStatus = rqsNotFound);
  AssertTrue('body kept', Pos('Object not found', FClient.LastRawJSON) > 0);
  AssertEquals('errorCode extracted', 404, FClient.LastErrorCode);
  AssertEquals('title extracted', 'Object not found', FClient.LastErrorTitle);
end;

procedure TTestRDAPClient.TestRateLimited;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock('{"errorCode":429,"title":"Too many requests"}', 429);
  FClient.QueryDomain('example.com');
  AssertTrue('status is rqsRateLimited', FClient.LastStatus = rqsRateLimited);
  AssertEquals('errorCode extracted', 429, FClient.LastErrorCode);
  AssertEquals('title extracted', 'Too many requests', FClient.LastErrorTitle);
end;

// RFC 9083 §6.2 error responses: 400/401/403/503 are reported as the rqsError
// status (not an exception), with errorCode/title extracted from the error
// object and the raw body kept in LastRawJSON.
procedure TTestRDAPClient.TestErrorStatusCodes_KeepErrorObject;
const
  Codes: array[0..3] of Integer = (400, 401, 403, 503);
var
  I: Integer;
  Title: string;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  for I := Low(Codes) to High(Codes) do
  begin
    Title := Format('Denied %d', [Codes[I]]);
    FClient.SetupMock(Format('{"errorCode":%d,"title":"%s"}', [Codes[I], Title]),
      Codes[I]);
    FClient.QueryDomain('example.com');
    AssertTrue(Format('%d: status is rqsError', [Codes[I]]),
      FClient.LastStatus = rqsError);
    AssertEquals(Format('%d: errorCode extracted', [Codes[I]]),
      Codes[I], FClient.LastErrorCode);
    AssertEquals(Format('%d: title extracted', [Codes[I]]),
      Title, FClient.LastErrorTitle);
    AssertTrue(Format('%d: body kept in LastRawJSON', [Codes[I]]),
      Pos(Format('"errorCode":%d', [Codes[I]]), FClient.LastRawJSON) > 0);
  end;

  // The next OK response must not inherit the error state.
  FClient.SetupMock(FMockJSON);
  FClient.QueryDomain('example.com');
  AssertTrue('status OK after an error', FClient.LastStatus = rqsOK);
  AssertEquals('errorCode not carried over', 0, FClient.LastErrorCode);
  AssertEquals('title not carried over', '', FClient.LastErrorTitle);
end;

// An error status whose body is not JSON at all must still be a quiet
// rqsError: nothing raises, no error object is extracted, the raw body stays.
procedure TTestRDAPClient.TestErrorStatus_NonJSONBody;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock('<html>service unavailable</html>', 403);
  FClient.QueryDomain('example.com');
  AssertTrue('status is rqsError', FClient.LastStatus = rqsError);
  AssertEquals('no errorCode', 0, FClient.LastErrorCode);
  AssertEquals('no title', '', FClient.LastErrorTitle);
  AssertTrue('no parsed JSON', FClient.LastJSON = nil);
  AssertTrue('raw body kept', Pos('service unavailable', FClient.LastRawJSON) > 0);
end;

// 429 with Retry-After in the delay-seconds form (RFC 7231 §7.1.3).
procedure TTestRDAPClient.TestRetryAfter_Seconds;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock('{"errorCode":429,"title":"Too many requests"}', 429,
    ['Retry-After: 120']);
  FClient.QueryDomain('example.com');
  AssertTrue('status is rqsRateLimited', FClient.LastStatus = rqsRateLimited);
  AssertEquals('seconds form', 120, FClient.RetryAfter);

  // Header names are case-insensitive (RFC 7230 §3.2).
  FClient.SetupMock('{"errorCode":429}', 429, ['retry-after: 30']);
  FClient.QueryDomain('example.com');
  AssertEquals('case-insensitive lookup', 30, FClient.RetryAfter);
end;

// 429 with Retry-After as an HTTP-date: whole seconds until the date,
// 0 when the date is already in the past.
procedure TTestRDAPClient.TestRetryAfter_HTTPDate;
var
  Target: TDateTime;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  // A date roughly an hour ahead: the exact value depends on "now", so only
  // the 1-hour ballpark is asserted.
  Target := Now + 3600 / SecsPerDay;
  FClient.SetupMock('{"errorCode":429}', 429,
    ['Retry-After: ' + FormatHTTPDate(Target)]);
  FClient.QueryDomain('example.com');
  AssertTrue('status is rqsRateLimited', FClient.LastStatus = rqsRateLimited);
  AssertTrue('seconds until the future date',
    (FClient.RetryAfter > 3540) and (FClient.RetryAfter <= 3600));

  // A past date means "no wait": 0.
  FClient.SetupMock('{"errorCode":429}', 429,
    ['Retry-After: Sat, 01 Jan 2000 00:00:00 GMT']);
  FClient.QueryDomain('example.com');
  AssertEquals('past date yields 0', 0, FClient.RetryAfter);
end;

// Without the header RetryAfter stays 0, and the value of an earlier response
// does not leak into a later one without the header.
procedure TTestRDAPClient.TestRetryAfter_AbsentAndNotCarriedOver;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  // First-ever request, no header at all.
  FClient.SetupMock('{"errorCode":429,"title":"Too many requests"}', 429);
  FClient.QueryDomain('example.com');
  AssertTrue('status is rqsRateLimited', FClient.LastStatus = rqsRateLimited);
  AssertEquals('absent header yields 0', 0, FClient.RetryAfter);

  // Then a response carrying the header...
  FClient.SetupMock('{"errorCode":429}', 429, ['Retry-After: 120']);
  FClient.QueryDomain('example.com');
  AssertEquals('seconds form', 120, FClient.RetryAfter);

  // ...and the next one without it: the value must not leak between requests.
  FClient.SetupMock('{"errorCode":429}', 429);
  FClient.QueryDomain('example.com');
  AssertEquals('not carried over', 0, FClient.RetryAfter);
end;

// RDAP payloads are UTF-8 (RFC 9083): a "title" that mixes JSON \uXXXX escapes
// with literal UTF-8 bytes must come back as valid UTF-8, with no '?'.
// ("привет" is escaped, "тест" is raw bytes; errorCode in a 200 body is
// nonstandard but exercises the extraction path the same way.)
procedure TTestRDAPClient.TestErrorTitle_UTF8;
const
  EscapedPart = '\u043f\u0440\u0438\u0432\u0435\u0442'; // "привет"
  RawPart = #$D1#$82#$D0#$B5#$D1#$81#$D1#$82;           // "тест"
  Expected = #$D0#$BF#$D1#$80#$D0#$B8#$D0#$B2#$D0#$B5#$D1#$82 // "привет"
    + ' ' + #$D1#$82#$D0#$B5#$D1#$81#$D1#$82;                // "тест"
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock('{"errorCode":200,"title":"' + EscapedPart + ' ' + RawPart + '"}', 200);
  FClient.QueryDomain('example.com');
  AssertTrue('status OK', FClient.LastStatus = rqsOK);
  AssertEquals('errorCode extracted', 200, FClient.LastErrorCode);
  AssertEquals('title keeps UTF-8 bytes', Expected, FClient.LastErrorTitle);
  AssertTrue('no question marks', Pos('?', FClient.LastErrorTitle) = 0);
end;

// The parse boundary must not depend on the process default codepage: this
// payload reaches ParseJSONSafe with a cp1251 codepage label, as it would on a
// Windows host with a non-UTF-8 ANSI codepage (or under FPC 3.3+ once the
// global DefaultSystemCodePage := CP_UTF8 init is re-evaluated). Utf8JSONArg
// relabels the body to CP_UTF8 without conversion, so the parse keeps the
// bytes byte-exact. The extracted title then crosses the AsString -> String
// boundary, which converts into the current default codepage - hence the
// cp1251 expectation below, pinned via a hex dump so that no codepage
// conversion can touch the expected bytes either.
procedure TTestRDAPClient.TestParseBoundary_NonUtf8DefaultCodepage;
const
  TestUtf8: packed array[0..7] of Byte = ($D1, $82, $D0, $B5, $D1, $81, $D1, $82);
    // "тест" as raw UTF-8 bytes, built via SetString so the string keeps these
    // bytes under any default codepage
  ExpectedHex = 'EF F0 E8 E2 E5 F2 20 F2 E5 F1 F2'; // "привет тест" in cp1251
var
  RawPart, Body: string;
  SavedCP: TSystemCodePage;

  function HexBytes(const S: RawByteString): string;
  var
    I: Integer;
  begin
    Result := '';
    for I := 1 to Length(S) do
    begin
      if I > 1 then
        Result := Result + ' ';
      Result := Result + IntToHex(Ord(S[I]), 2);
    end;
  end;

begin
  SavedCP := DefaultSystemCodePage;
  DefaultSystemCodePage := TSystemCodePage(1251);
  try
    SetString(RawPart, PAnsiChar(@TestUtf8[0]), Length(TestUtf8));
    FClient.BaseURL := 'https://rdap.example.org';
    Body := '{"errorCode":200,"title":"\u043f\u0440\u0438\u0432\u0435\u0442 '
      + RawPart + '"}';
    FClient.SetupMock(Body, 200);
    FClient.QueryDomain('example.com');
    AssertTrue('status OK', FClient.LastStatus = rqsOK);
    AssertEquals('errorCode extracted', 200, FClient.LastErrorCode);
    AssertEquals('title parsed from cp1251-labeled body', ExpectedHex,
      HexBytes(FClient.LastErrorTitle));
  finally
    DefaultSystemCodePage := SavedCP;
  end;
end;

// 500 is outside the accepted code list: through the mock it reaches the
// "Unexpected HTTP status" branch of ProcessLastResponse and raises, which
// keeps that branch alive for non-standard codes.
procedure TTestRDAPClient.TestUnexpectedStatus_Raises;
var
  Raised: Boolean;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock('oops', 500);
  Raised := False;
  try
    FClient.QueryDomain('example.com');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('message mentions status', Pos('500', E.Message) > 0);
      AssertTrue('message mentions "Unexpected HTTP status"',
        Pos('Unexpected HTTP status', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
  AssertTrue('status is rqsError', FClient.LastStatus = rqsError);
end;

procedure TTestRDAPClient.TestNetworkError_Wrapped;
var
  Raised: Boolean;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMockError('connection refused');
  Raised := False;
  try
    FClient.QueryDomain('example.com');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('message kept', Pos('connection refused', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
  AssertTrue('status is rqsError', FClient.LastStatus = rqsError);
end;

procedure TTestRDAPClient.TestMalformed200JSON;
var
  Raised: Boolean;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock('this is not json', 200);
  Raised := False;
  try
    FClient.QueryDomain('example.com');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('message mentions JSON parse', Pos('JSON parse', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
end;

// MaxResponseSize is part of ExecuteQuery's contract (applied to whatever
// DoHTTPGetJSON returns), so the mock path exercises it exactly like the wire
// path - no network needed.
procedure TTestRDAPClient.TestMaxResponseSize_Default;
begin
  AssertEquals('default limit is 10 MB', Int64(10 * 1024 * 1024),
    FClient.MaxResponseSize);
end;

// A body over the limit fails the query with ERDAPError naming the limit;
// the oversized body must not leak into LastRawJSON, the status is rqsError.
procedure TTestRDAPClient.TestMaxResponseSize_Exceeded;
var
  Raised: Boolean;
  Body: string;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  Body := StringOfChar('x', 64);
  FClient.SetupMock(Body);
  FClient.MaxResponseSize := 16;
  Raised := False;
  try
    FClient.QueryDomain('example.com');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('message mentions the limit', Pos('size limit', E.Message) > 0);
      AssertTrue('message mentions the URL', Pos('rdap.example.org', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
  AssertTrue('status is rqsError', FClient.LastStatus = rqsError);
  AssertEquals('oversized body not kept in LastRawJSON', 0,
    Length(FClient.LastRawJSON));
  AssertEquals('request still recorded', 1, FClient.MockRequestCount);
end;

// The limit is inclusive: a body of exactly MaxResponseSize bytes passes,
// one byte more fails. The bodies are valid JSON so they parse cleanly once
// they pass the size check.
procedure TTestRDAPClient.TestMaxResponseSize_Boundary;
var
  Raised: Boolean;
  Body: string;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  Body := '{"pad":"' + StringOfChar('x', 20) + '"}';
  FClient.SetupMock(Body);
  FClient.MaxResponseSize := Length(Body);
  FClient.QueryDomain('example.com');
  AssertTrue('body of exactly the limit passes', FClient.LastStatus = rqsOK);
  AssertEquals('body stored in full', Length(Body), Length(FClient.LastRawJSON));

  FClient.SetupMock(Body);
  FClient.MaxResponseSize := Length(Body) - 1;
  Raised := False;
  try
    FClient.QueryDomain('example.com');
  except
    on E: ERDAPError do
      Raised := True;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('one byte over the limit must raise', Raised);
  AssertTrue('status is rqsError', FClient.LastStatus = rqsError);
end;

// MaxResponseSize = 0 disables the limit: any body size is accepted.
procedure TTestRDAPClient.TestMaxResponseSize_Unlimited;
var
  Body: string;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  Body := '{"pad":"' + StringOfChar('x', 4090) + '"}';
  FClient.SetupMock(Body);
  FClient.MaxResponseSize := 0;
  FClient.QueryDomain('example.com');
  AssertTrue('no limit, status OK', FClient.LastStatus = rqsOK);
  AssertEquals('body stored in full', Length(Body), Length(FClient.LastRawJSON));
end;

procedure TTestRDAPClient.TestMockRecordsRequests;
begin
  FClient.BaseURL := 'https://rdap.example.org';
  FClient.SetupMock(FMockJSON);
  FClient.QueryDomain('a.com');
  FClient.QueryDomain('b.com');
  AssertEquals('two requests recorded', 2, FClient.MockRequestCount);
  AssertEquals('first URL', 'https://rdap.example.org/domain/a.com',
    FClient.MockRequestURL(0));
  AssertEquals('second URL', 'https://rdap.example.org/domain/b.com',
    FClient.MockRequestURL(1));
end;

{ TSOCKS5Stub }

const
  StubHandshakeTimeoutMs = 3000;
  StubAcceptPollMs = 50;

constructor TSOCKS5Stub.Create;
begin
  inherited Create;
  FResponses := TStringList.Create;
  FConnectReply := 0;
  FReady := TEvent.Create(nil, False, False, '');
  // The thread binds the port and signals FReady; the constructor waits, so
  // Port is valid as soon as Create returns.
  FThread := TSOCKS5StubThread.Create(Self);
  if FReady.WaitFor(5000) <> wrSignaled then
    raise Exception.Create('SOCKS5 stub failed to bind its port');
end;

destructor TSOCKS5Stub.Destroy;
begin
  FThread.Terminate;
  FThread.WaitFor;
  FThread.Free;
  FReady.Free;
  FResponses.Free;
  inherited Destroy;
end;

constructor TSOCKS5StubThread.Create(AStub: TSOCKS5Stub);
begin
  FStub := AStub;
  inherited Create(False);
end;

procedure TSOCKS5StubThread.Execute;
var
  LS: TTCPBlockSocket;
  CS: TTCPBlockSocket;
begin
  LS := TTCPBlockSocket.Create;
  try
    LS.Bind('127.0.0.1', '0'); // ephemeral port, loopback only
    LS.Listen;
    FStub.FPort := Word(LS.GetLocalSinPort);
    FStub.FReady.SetEvent;
    // One client at a time: the canned 'Connection: close' responses make the
    // client reconnect per pass, so a sequential accept loop is enough.
    while not Terminated do
      if LS.CanRead(StubAcceptPollMs) then
      begin
        CS := TTCPBlockSocket.Create;
        try
          CS.Socket := LS.Accept;
          ServeClient(CS);
        finally
          CS.Free;
        end;
      end;
  finally
    LS.Free;
  end;
end;

procedure TSOCKS5StubThread.ServeClient(ASock: TTCPBlockSocket);
var
  Buf: AnsiString;
  NMethods, I, Method, ULen, PLen, AddrLen: Integer;
  Offered: Boolean;
  ATyp: Byte;
  PortWord: Word;
begin
  // 1) Greeting: VER, NMETHODS, METHODS.
  Buf := ASock.RecvBufferStr(2, StubHandshakeTimeoutMs);
  if (ASock.LastError <> 0) or (Length(Buf) < 2) or (Buf[1] <> #5) then
    Exit;
  NMethods := Ord(Buf[2]);
  if NMethods = 0 then
    Exit;
  Buf := ASock.RecvBufferStr(NMethods, StubHandshakeTimeoutMs);
  if (ASock.LastError <> 0) or (Length(Buf) < NMethods) then
    Exit;
  // Method choice mirrors the client configuration: user/pass when the stub
  // expects credentials, no-auth otherwise.
  if FStub.FAuthUser <> '' then
    Method := 2
  else
    Method := 0;
  Offered := False;
  for I := 1 to NMethods do
    if Ord(Buf[I]) = Method then
      Offered := True;
  if not Offered then
  begin
    ASock.SendString(#5 + AnsiChar($FF)); // no acceptable method
    Exit;
  end;
  ASock.SendString(#5 + AnsiChar(Method));
  // 2) RFC 1929 user/pass subnegotiation (VER, ULEN, UNAME, PLEN, PASSWD).
  if Method = 2 then
  begin
    Buf := ASock.RecvBufferStr(2, StubHandshakeTimeoutMs);
    if (ASock.LastError <> 0) or (Length(Buf) < 2) then
      Exit;
    ULen := Ord(Buf[2]);
    Buf := ASock.RecvBufferStr(ULen, StubHandshakeTimeoutMs);
    if ASock.LastError <> 0 then
      Exit;
    FStub.FAuthSeenUser := Buf;
    Buf := ASock.RecvBufferStr(1, StubHandshakeTimeoutMs);
    if ASock.LastError <> 0 then
      Exit;
    PLen := Ord(Buf[1]);
    Buf := ASock.RecvBufferStr(PLen, StubHandshakeTimeoutMs);
    if ASock.LastError <> 0 then
      Exit;
    FStub.FAuthSeenPass := Buf;
    if (FStub.FAuthSeenUser <> FStub.FAuthUser) or
       (FStub.FAuthSeenPass <> FStub.FAuthPass) then
    begin
      ASock.SendString(#1 + #1); // auth failure
      Exit;
    end;
    ASock.SendString(#1 + #0);
  end;
  // 3) CONNECT: VER, CMD, RSV, ATYP, ADDR, PORT - the target is recorded but
  // otherwise ignored.
  Buf := ASock.RecvBufferStr(4, StubHandshakeTimeoutMs);
  if (ASock.LastError <> 0) or (Length(Buf) < 4) or (Buf[1] <> #5) then
    Exit;
  ATyp := Ord(Buf[4]);
  case ATyp of
    1: AddrLen := 4;
    4: AddrLen := 16;
    3:
      begin
        Buf := ASock.RecvBufferStr(1, StubHandshakeTimeoutMs);
        if (ASock.LastError <> 0) or (Length(Buf) < 1) then
          Exit;
        AddrLen := Ord(Buf[1]);
      end;
  else
    Exit;
  end;
  Buf := ASock.RecvBufferStr(AddrLen + 2, StubHandshakeTimeoutMs);
  if (ASock.LastError <> 0) or (Length(Buf) < AddrLen + 2) then
    Exit;
  PortWord := Word(Ord(Buf[AddrLen + 1]) shl 8) or Ord(Buf[AddrLen + 2]);
  if ATyp = 1 then
    FStub.FLastTarget := Format('%d.%d.%d.%d:%d',
      [Ord(Buf[1]), Ord(Buf[2]), Ord(Buf[3]), Ord(Buf[4]), PortWord])
  else if ATyp = 3 then
    FStub.FLastTarget := Copy(Buf, 1, AddrLen) + ':' + IntToStr(PortWord)
  else
    FStub.FLastTarget := '<ipv6>';
  Inc(FStub.FConnections);
  // 4) CONNECT reply: VER, REP, RSV, ATYP=IPv4, BND.ADDR=0.0.0.0, BND.PORT=0.
  ASock.SendString(#5 + AnsiChar(FStub.FConnectReply) + #0 + #1 + #0#0#0#0 + #0#0);
  if FStub.FConnectReply <> 0 then
    Exit;
  // 5) The next canned HTTP response, regardless of the requested target.
  if FStub.FResponses.Count > 0 then
  begin
    if FStub.FServed >= FStub.FResponses.Count then
      Buf := FStub.FResponses[FStub.FResponses.Count - 1] // last repeats
    else
      Buf := FStub.FResponses[FStub.FServed];
    Inc(FStub.FServed);
    ASock.SendString(Buf);
  end;
  ASock.CloseSocket;
end;

{ TTestProxyClient }

procedure TTestProxyClient.SetUp;
begin
  inherited SetUp;
  FStub := TSOCKS5Stub.Create;
  FClient := TRDAPClient.Create;
  // Loopback only: the target host is 127.0.0.1 and the stub answers
  // independently of the CONNECT target, so no DNS and no external network
  // are involved; port 1 is not really connected to (the proxy intercepts).
  FClient.BaseURL := 'http://127.0.0.1:1';
  // Short timeouts: a misbehaving stub must fail the test fast, not hang it.
  FClient.ConnectTimeout := 2000;
  FClient.IOTimeout := 3000;
end;

procedure TTestProxyClient.TearDown;
begin
  FClient.Free;
  FStub.Free;
  inherited TearDown;
end;

// Builds a canned raw HTTP response with a correct Content-Length; the
// Connection: close header makes Synapse drop the tunnel after the response.
function TTestProxyClient.HTTPResponse(ACode: Integer; const AReason,
  ABody: string; const AExtra: array of string): string;
var
  I: Integer;
begin
  Result := Format('HTTP/1.1 %d %s'#13#10, [ACode, AReason]) +
    'Server: socks5-stub'#13#10 +
    Format('Content-Length: %d'#13#10, [Length(ABody)]) +
    'Connection: close'#13#10;
  for I := 0 to High(AExtra) do
    Result := Result + AExtra[I] + #13#10;
  Result := Result + #13#10 + ABody;
end;

procedure TTestProxyClient.ConfigureProxy;
begin
  FClient.ProxyHost := '127.0.0.1';
  FClient.ProxyPort := FStub.Port;
end;

procedure TTestProxyClient.TestProxyDefaults;
var
  C: TRDAPClient;
begin
  C := TRDAPClient.Create;
  try
    AssertEquals('no proxy host by default', '', C.ProxyHost);
    AssertEquals('no proxy port by default', 0, C.ProxyPort);
    AssertEquals('no proxy user by default', '', C.ProxyUser);
    AssertEquals('no proxy pass by default', '', C.ProxyPass);
  finally
    C.Free;
  end;
end;

procedure TTestProxyClient.TestProxy_200JSON;
var
  Body: string;
begin
  Body := '{"objectClassName":"ip","handle":"TEST-IP","name":"example"}';
  FStub.Responses.Add(HTTPResponse(200, 'OK', Body, []));
  ConfigureProxy;
  FClient.QueryIP('192.0.2.1');
  AssertTrue('status is rqsOK', FClient.LastStatus = rqsOK);
  AssertEquals('HTTP code through the proxy', 200, FClient.LastHTTPCode);
  AssertEquals('raw body through the proxy', Body, FClient.LastRawJSON);
  AssertEquals('object parsed', 'ip', FClient.GetObjectType);
  AssertEquals('one connection used', 1, FStub.Connections);
  AssertTrue('CONNECT target is the request host',
    Pos('127.0.0.1:1', FStub.LastTarget) > 0);
end;

procedure TTestProxyClient.TestProxy_429RetryAfter;
begin
  FStub.Responses.Add(HTTPResponse(429, 'Too Many Requests', '{"errorCode":429}',
    ['Retry-After: 120']));
  ConfigureProxy;
  FClient.QueryIP('192.0.2.1');
  AssertTrue('status is rqsRateLimited', FClient.LastStatus = rqsRateLimited);
  AssertEquals('Retry-After seen through the proxy path', 120,
    FClient.RetryAfter);
end;

procedure TTestProxyClient.TestProxy_ConnectRefused;
var
  Raised: Boolean;
begin
  FStub.Responses.Add(HTTPResponse(200, 'OK', '{}', []));
  FStub.ConnectReply := 1; // general SOCKS server failure
  ConfigureProxy;
  Raised := False;
  try
    FClient.QueryIP('192.0.2.1');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('message mentions the proxy host', Pos('127.0.0.1', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
  AssertTrue('status is rqsError', FClient.LastStatus = rqsError);
  AssertEquals('no HTTP code on a failed CONNECT', 0, FClient.LastHTTPCode);
  AssertEquals('only one connection attempted', 1, FStub.Connections);
end;

procedure TTestProxyClient.TestProxy_Redirect302;
var
  Body: string;
begin
  Body := '{"objectClassName":"ip","handle":"MOVED","name":"example"}';
  FStub.Responses.Add(HTTPResponse(302, 'Found', '',
    ['Location: http://rdap.moved.example/registry/ip/192.0.2.1']));
  FStub.Responses.Add(HTTPResponse(200, 'OK', Body, []));
  ConfigureProxy;
  FClient.QueryIP('192.0.2.1');
  AssertTrue('status is rqsOK after the redirect', FClient.LastStatus = rqsOK);
  AssertEquals('HTTP code of the final response', 200, FClient.LastHTTPCode);
  AssertEquals('body of the final response', Body, FClient.LastRawJSON);
  AssertEquals('redirect was a second pass over the wire', 2, FStub.Connections);
  AssertTrue('second pass connects to the redirect target',
    Pos('rdap.moved.example', FStub.LastTarget) > 0);
  AssertEquals('LastURL stays the requested URL',
    'http://127.0.0.1:1/ip/192.0.2.1', FClient.LastURL);
end;

procedure TTestProxyClient.TestProxy_RedirectRelativeLocation_Raises;
var
  Raised: Boolean;
begin
  FStub.Responses.Add(HTTPResponse(302, 'Found', '', ['Location: /ip/192.0.2.1']));
  ConfigureProxy;
  Raised := False;
  try
    FClient.QueryIP('192.0.2.1');
  except
    on E: ERDAPError do
    begin
      Raised := True;
      AssertTrue('message mentions relative Location',
        Pos('relative Location', E.Message) > 0);
    end;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
  AssertTrue('status is rqsError', FClient.LastStatus = rqsError);
  AssertEquals('no second pass after a relative Location', 1, FStub.Connections);
end;

procedure TTestProxyClient.TestProxy_UserPassAuth;
var
  Body: string;
begin
  Body := '{"objectClassName":"ip","handle":"AUTH","name":"example"}';
  FStub.Responses.Add(HTTPResponse(200, 'OK', Body, []));
  FStub.AuthUser := 'alice';
  FStub.AuthPass := 'secret';
  ConfigureProxy;
  FClient.ProxyUser := 'alice';
  FClient.ProxyPass := 'secret';
  FClient.QueryIP('192.0.2.1');
  AssertTrue('status is rqsOK with user/pass auth', FClient.LastStatus = rqsOK);
  AssertEquals('username reached the proxy', 'alice', FStub.AuthSeenUser);
  AssertEquals('password reached the proxy', 'secret', FStub.AuthSeenPass);
end;

procedure TTestProxyClient.TestProxy_AuthRejected;
var
  Raised: Boolean;
begin
  FStub.Responses.Add(HTTPResponse(200, 'OK', '{}', []));
  FStub.AuthUser := 'alice';
  FStub.AuthPass := 'secret';
  ConfigureProxy;
  FClient.ProxyUser := 'alice';
  FClient.ProxyPass := 'wrong';
  Raised := False;
  try
    FClient.QueryIP('192.0.2.1');
  except
    on E: ERDAPError do
      Raised := True;
    on E: Exception do
      Fail('unexpected exception ' + E.ClassName + ': ' + E.Message);
  end;
  AssertTrue('ERDAPError expected', Raised);
  AssertTrue('status is rqsError', FClient.LastStatus = rqsError);
  AssertEquals('credentials were presented once', 'alice', FStub.AuthSeenUser);
  AssertEquals('no HTTP code on a failed handshake', 0, FClient.LastHTTPCode);
end;

initialization
  RegisterTest(TTestIPUtils);
  RegisterTest(TTestBootstrap);
  RegisterTest(TTestRDAPClient);
  RegisterTest(TTestProxyClient);

end.
