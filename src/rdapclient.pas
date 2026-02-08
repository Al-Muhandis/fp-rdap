unit rdapclient;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, fphttpclient, fpjson, jsonparser;

type
  ERDAPError = class(Exception);

  TRDAPQueryStatus = (
    rqsNone,
    rqsOK,
    rqsNotFound,
    rqsError
  );

  { TRDAPClient }

  TRDAPClient = class
  private
    FBaseURL: string;
    FUserAgent: string;
    FLastRawJSON: string;
    FLastJSON: TJSONData;
    FLastHTTPCode: Integer;
    FLastStatus: TRDAPQueryStatus;
    procedure ClearLastJSON;
    procedure InitSSL;
    procedure ProcessLastResponse;
  protected
    function DoHTTPGetJSON(const AURL, AUserAgent: string): string; virtual;
  public
    constructor Create(const ABaseURL: string = 'https://rdap.org/'); virtual;
    destructor Destroy; override;

    property BaseURL: string read FBaseURL write FBaseURL;
    property UserAgent: string read FUserAgent write FUserAgent;

    property LastRawJSON: string read FLastRawJSON;
    property LastJSON: TJSONData read FLastJSON;

    property LastHTTPCode: Integer read FLastHTTPCode;
    property LastStatus: TRDAPQueryStatus read FLastStatus;

    function QueryDomain(const ADomain: string): string;
    function QueryIP(const AIP: string): string;
    function QueryAutNum(const AAutNum: string): string;
    function QueryEntity(const AHandle: string): string;

    function GetObjectTitle: string;
    function GetObjectType: string;
  end;

  { TRDAPClientMock - for unit tests }

  TRDAPClientMock = class(TRDAPClient)                                   
  private
    FMockResponse: string;
    FMockEnabled: Boolean;
  protected
    function DoHTTPGetJSON(const AURL, AUserAgent: string): string; override;
  public
    procedure MockDoHTTPGetJSON(const AMockResponse: string; aHTTPCode: Integer=200);
    property MockResponse: string read FMockResponse write FMockResponse;
  end;

implementation

uses
  opensslsockets, openssl
  ;


function NormalizePath(const Base, Path: string): string;
begin
  if (Base <> '') and (Base[Length(Base)] <> '/') then
    Result := Base + '/' + Path
  else
    Result := Base + Path;
end;

procedure ParseJSONSafe(const AJSON: string; out AData: TJSONData);
begin
  AData := nil;
  if AJSON = '' then
    Exit;
  try
    AData := GetJSON(AJSON, False);
  except
    on E: Exception do
      raise ERDAPError.CreateFmt('JSON parse error: %s', [E.Message]);
  end;
end;

  { TRDAPClient }

procedure TRDAPClient.ClearLastJSON;
begin
  FreeAndNil(FLastJSON);
  FLastRawJSON := '';
end;

procedure TRDAPClient.InitSSL;
begin
  if not InitSSLInterface then
    raise Exception.Create('SSL init failed');
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
        FLastStatus := rqsNotFound;
        FLastJSON := nil;
        FLastRawJSON := '';
      end;

  else
    FLastStatus := rqsError;
    raise ERDAPError.CreateFmt('Unexpected HTTP status: %d', [FLastHTTPCode]);
  end;
end;

function TRDAPClient.DoHTTPGetJSON(const AURL, AUserAgent: string): string;
var
  C: TFPHttpClient;
  SS: TRawByteStringStream;
begin
  InitSSL;

  C := TFPHttpClient.Create(nil);
  try
    C.AllowRedirect := True;
    C.MaxRedirects := 5;
    C.ConnectTimeout := 15000;

    C.AddHeader('User-Agent', AUserAgent);
    C.AddHeader('Accept', 'application/rdap+json,*/*');

    SS:=TRawByteStringStream.Create;
    try
      C.HTTPMethod('GET',AURL,SS,[200, 404]);
      Result:=SS.Datastring;
    finally
      FLastHTTPCode:=C.ResponseStatusCode;
      SS.Free;
    end;
  finally
    C.Free;
  end;
end;

constructor TRDAPClient.Create(const ABaseURL: string);
begin
  inherited Create;
  FBaseURL := ABaseURL;
  if (FBaseURL <> '') and (FBaseURL[Length(FBaseURL)] <> '/') then
    FBaseURL := FBaseURL + '/';
  FUserAgent := 'fp-rdap-client/1.0';
  FLastJSON := nil;
  FLastRawJSON := '';
end;

destructor TRDAPClient.Destroy;
begin
  ClearLastJSON;
  inherited Destroy;
end;

function TRDAPClient.QueryDomain(const ADomain: string): string;
var
  URL: string;
begin
  ClearLastJSON;
  URL := NormalizePath(FBaseURL, 'domain/' + ADomain);
  FLastRawJSON := DoHTTPGetJSON(URL, FUserAgent);
  ProcessLastResponse;
  Result := FLastRawJSON;
end;

function TRDAPClient.QueryIP(const AIP: string): string;
var
  URL: string;
begin
  ClearLastJSON;
  URL := NormalizePath(FBaseURL, 'ip/' + AIP);
  FLastRawJSON := DoHTTPGetJSON(URL, FUserAgent);
  ProcessLastResponse;
  Result := FLastRawJSON;
end;

function TRDAPClient.QueryAutNum(const AAutNum: string): string;
var
  URL: string;
begin
  ClearLastJSON;
  URL := NormalizePath(FBaseURL, 'autnum/' + AAutNum);
  FLastRawJSON := DoHTTPGetJSON(URL, FUserAgent);
  ProcessLastResponse;
  Result := FLastRawJSON;
end;

function TRDAPClient.QueryEntity(const AHandle: string): string;
var
  URL: string;
begin
  ClearLastJSON;
  URL := NormalizePath(FBaseURL, 'entity/' + AHandle);
  FLastRawJSON := DoHTTPGetJSON(URL, FUserAgent);
  ProcessLastResponse;
  Result := FLastRawJSON;
end;

function TRDAPClient.GetObjectTitle: string;
var
  J: TJSONData;
begin
  Result := '';
  J := FLastJSON;
  if (J <> nil) and (J.JSONType = jtObject) then
  begin
    if (J.FindPath('handle') <> nil) then
      Result := J.FindPath('handle').AsString
    else
    if (J.FindPath('ldhName') <> nil) then
      Result := J.FindPath('ldhName').AsString
    else
    if (J.FindPath('name') <> nil) then
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
    if (J.FindPath('objectClassName') <> nil) then
      Result := J.FindPath('objectClassName').AsString;
  end;
end;

{ TRDAPClientMock }

function TRDAPClientMock.DoHTTPGetJSON(const AURL, AUserAgent: string): string;
begin
  if FMockEnabled then
    Result := FMockResponse
  else
    inherited DoHTTPGetJSON(AURL, AUserAgent);
end;

procedure TRDAPClientMock.MockDoHTTPGetJSON(const AMockResponse: string; aHTTPCode: Integer = 200);
begin
  FLastHTTPCode:=aHTTPCode;
  FMockResponse:=AMockResponse;
  FMockEnabled :=True;
end;

end.
