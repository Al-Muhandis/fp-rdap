unit test_rdapclient;

{$mode objfpc}{$H+}

interface

uses
  Classes, SysUtils, fpcunit, testregistry, fpjson, jsonparser, rdapclient
  ;

type

  { TTestRDAPClient }

  TTestRDAPClient = class(TTestCase)
  private
    FClient: TRDAPClientMock;
    FMockJSON: string;
    FMockJSONIP: String;
  protected
    procedure SetUp; override;
    procedure TearDown; override;
  published
    procedure TestConstructor;
    procedure TestQueryDomain;
    procedure TestQueryIP;
    procedure TestGetObjectTitle;
    procedure TestGetObjectType;
    procedure TestLastStatusNotFound;  
    procedure TestGetTitleNotFound;
  end;

implementation

procedure TTestRDAPClient.SetUp;
begin
  FClient := TRDAPClientMock.Create;
  FMockJSON := '{"objectClassName":"domain","handle":"example.com","ldhName":"example.com"}';
  FMockJSONIP := '{"objectClassName":"ip network","handle":"8.8.8.8/32"}';
end;

procedure TTestRDAPClient.TearDown;
begin
  FClient.Free;
end;

procedure TTestRDAPClient.TestConstructor;
begin
  AssertNotNull('Client created', FClient);
  AssertEquals('Default base URL', 'https://rdap.org/', FClient.BaseURL);
end;

procedure TTestRDAPClient.TestQueryDomain;
begin
  FClient.MockDoHTTPGetJSON(FMockJSON);
  FClient.QueryDomain('example.com');
  AssertEquals('Mock JSON returned', FMockJSON, FClient.LastRawJSON);
  AssertEquals('Title from mock', 'example.com', FClient.GetObjectTitle);
end;

procedure TTestRDAPClient.TestQueryIP;
begin
  FClient.MockDoHTTPGetJSON(FMockJSONIP);
  FClient.QueryIP('8.8.8.8');
  AssertEquals('IP mock JSON', FMockJSONIP, FClient.LastRawJSON);
  AssertEquals('IP object type', 'ip network', FClient.GetObjectType);
end;

procedure TTestRDAPClient.TestGetObjectTitle;
begin              
  FClient.MockDoHTTPGetJSON(FMockJSON);
  FClient.QueryDomain('example.com'); // Fill LastJSON mock-data
  AssertEquals('Object title from handle/ldhName', 'example.com', FClient.GetObjectTitle);
end;

procedure TTestRDAPClient.TestGetObjectType;
begin
  FClient.MockDoHTTPGetJSON(FMockJSON);
  FClient.QueryDomain('example.com');
  AssertEquals('Object type', 'domain', FClient.GetObjectType);
end;

procedure TTestRDAPClient.TestLastStatusNotFound;
begin
  FClient.MockDoHTTPGetJSON('', 404);
  FClient.QueryDomain('missing');
  AssertFalse('IsFound=False', FClient.LastStatus = rqsOK);
end;

procedure TTestRDAPClient.TestGetTitleNotFound;
begin
  FClient.MockDoHTTPGetJSON('', 404);
  FClient.QueryDomain('404.com');
  AssertEquals('Empty title', '', FClient.GetObjectTitle);
  AssertEquals('Empty type', '', FClient.GetObjectType);
end;

initialization
  RegisterTest(TTestRDAPClient);

end.
