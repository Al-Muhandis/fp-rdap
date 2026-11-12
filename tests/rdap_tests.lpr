program rdap_tests;

{$mode objfpc}{$H+}

uses
  Classes, SysUtils, consoletestrunner,
  test_rdapclient
  ;

var
  App: TTestRunner;

begin
  App := TTestRunner.Create(nil);
  try
    App.Initialize;
    App.Title := 'fp-rdap unit tests';
    App.Run;
  finally
    App.Free;
  end;
end.
