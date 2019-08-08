
-module(hotp_test).

-include_lib("eunit/include/eunit.hrl").

generate_test() ->
  % See RFC 4226 Appendix D
  Key = <<"12345678901234567890">>,
  Generate = fun (Count) -> hotp:generate(Key, <<Count:64>>, 6) end,
  ?assertEqual(755224, Generate(0)),
  ?assertEqual(287082, Generate(1)),
  ?assertEqual(359152, Generate(2)),
  ?assertEqual(969429, Generate(3)),
  ?assertEqual(338314, Generate(4)),
  ?assertEqual(254676, Generate(5)),
  ?assertEqual(287922, Generate(6)),
  ?assertEqual(162583, Generate(7)),
  ?assertEqual(399871, Generate(8)),
  ?assertEqual(520489, Generate(9)).
