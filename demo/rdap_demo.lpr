program rdap_demo;

{$mode objfpc}{$H+}

uses
  SysUtils, Classes, rdapclient
  {$IFDEF MSWINDOWS}, Windows{$ENDIF};

{$IFDEF MSWINDOWS}
var
  OldOutputCP: Cardinal;
{$ENDIF}

// Replaces characters that are not allowed in Windows file names (and control
// characters) with '_', so any query string can serve as a file name base
// (e.g. an IPv6 query contains ':').
function SanitizeFileName(const S: string): string;
const
  Forbidden = '<>:"/\|?*';
var
  I: Integer;
begin
  Result := S;
  for I := 1 to Length(Result) do
    if (Pos(Result[I], Forbidden) > 0) or (Ord(Result[I]) < 32) then
      Result[I] := '_';
end;

procedure PrintResult(C: TRDAPClient; const aQuery, aCaption: string);
begin
  Writeln('Queried ', Format(aCaption, [aQuery]));
  Writeln('  URL:    ', C.LastURL);
  if C.LastStatus = rqsNotFound then
    WriteLn('  Object not found')
  else if C.LastStatus = rqsOK then
  begin
    Writeln('  Title: ', C.GetObjectTitle);
    Writeln('  Type:  ', C.GetObjectType);
    Writeln('  Size:  ', Length(C.LastRawJSON));
  end
  else if C.LastStatus = rqsError then
  begin
    // 400/401/403/503 arrive as a status (not an exception) since RFC 9083
    // error handling; network failures and unexpected codes land here too,
    // without an HTTP status.
    if C.LastHTTPCode > 0 then
      WriteLn('  HTTP ', C.LastHTTPCode, ' error')
    else
      WriteLn('  Request failed');
  end;
  WriteLn('  Status: ', C.LastStatus);
  if C.LastErrorCode <> 0 then
    WriteLn('  Error ', C.LastErrorCode, ': ', C.LastErrorTitle);
  if Length(C.LastRawJSON) > 0 then
    Writeln('  Preview: ', Copy(C.LastRawJSON, 1, 200));
  Writeln;

  if C.LastRawJSON <> '' then
    with TStringList.Create do
    try
      Text := C.LastRawJSON;
      SaveToFile(Format('rdap_example_%s.json', [SanitizeFileName(aQuery)]));
    finally
      Free;
    end;
end;

procedure RunQuery(C: TRDAPClient; const aQuery, aCaption: string; aIsIP: Boolean);
begin
  try
    if aIsIP then
      C.QueryIP(aQuery)
    else
      C.QueryDomain(aQuery);
  except
    on E: ERDAPError do
      Writeln('  Query failed: ', E.Message);
  end;
  PrintResult(C, aQuery, aCaption);
end;

// Applies the proxy command line to the client: --proxy=host:port (mandatory
// host, optional port), --proxy-user=u, --proxy-pass=p. Manual live-SOCKS
// verification of the proxy transport; without --proxy the demo runs direct.
procedure ApplyProxyFromCommandLine(C: TRDAPClient);
var
  I, P: Integer;
  S: string;
begin
  for I := 1 to ParamCount do
  begin
    S := ParamStr(I);
    if Pos('--proxy=', S) = 1 then
    begin
      S := Copy(S, 9, MaxInt);
      P := Pos(':', S);
      if P > 0 then
      begin
        C.ProxyHost := Copy(S, 1, P - 1);
        C.ProxyPort := StrToIntDef(Copy(S, P + 1, MaxInt), 0);
      end
      else
        C.ProxyHost := S;
    end
    else if Pos('--proxy-user=', S) = 1 then
      C.ProxyUser := Copy(S, 14, MaxInt)
    else if Pos('--proxy-pass=', S) = 1 then
      C.ProxyPass := Copy(S, 14, MaxInt);
  end;
  if C.ProxyHost <> '' then
    Writeln('Using SOCKS5 proxy: ', C.ProxyHost, ':', C.ProxyPort);
end;

procedure RunDemos;
var
  C: TRDAPClient;
  B: TRDAPBootstrap;
  BootstrapOK: Boolean;
begin
  Writeln('RDAP DEMO');

  B := TRDAPBootstrap.Create;
  BootstrapOK := False;
  try
    try
      B.LoadFromLocalFiles('dns.json', 'ipv4.json', 'ipv6.json');
      BootstrapOK := True;
      Writeln('Bootstrap loaded from local files');
    except
      on E: ERDAPError do
      begin
        Writeln('Local bootstrap files unavailable: ', E.Message);
        Writeln('Get dns.json / ipv4.json / ipv6.json from https://data.iana.org/rdap/');
        Writeln('Falling back to https://rdap.org/');
      end;
    end;

    C := TRDAPClient.Create;
    try
      ApplyProxyFromCommandLine(C);
      if BootstrapOK then
        C.Bootstrap := B
      else
        C.BaseURL := 'https://rdap.org/';

      RunQuery(C, 'example.com', '1. %s (domain)', False);
      RunQuery(C, 'wikipedia.org', '2. %s (domain)', False);
      RunQuery(C, '8.8.8.8', '3. %s (IP)', True);
      RunQuery(C, 'nonexistent123456.com', '4. %s (domain)', False);

      Writeln('Saved to rdap_example_XXX.json');
    finally
      C.Free;
    end;
  finally
    B.Free;
  end;
end;

begin
  {$IFDEF MSWINDOWS}
  // Library strings are UTF-8 by contract, while a Windows console usually
  // starts in the OEM codepage (e.g. cp866), which would garble non-ASCII
  // titles, error messages and JSON previews into mojibake. Switch the console
  // output to UTF-8 for the run (needs a Unicode-capable console font, e.g.
  // Consolas) and restore the previous codepage on exit. UTF8ToConsole was
  // considered and rejected: cp866 cannot represent most non-Cyrillic
  // characters, RDAP data is international.
  OldOutputCP := GetConsoleOutputCP;
  SetConsoleOutputCP(CP_UTF8);
  {$ENDIF}
  try
    RunDemos;
  except
    on E: Exception do
      Writeln('ERROR: ', E.Message);
  end;
  Writeln('COMPLETE!');
  ReadLn;
  {$IFDEF MSWINDOWS}
  SetConsoleOutputCP(OldOutputCP);
  {$ENDIF}
end.
