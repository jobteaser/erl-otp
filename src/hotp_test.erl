%% Copyright 2019, JobTeaser
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

-module(hotp_test).

-include_lib("eunit/include/eunit.hrl").

generate_test() ->
  % See RFC 4226 Appendix D
  Key = <<"12345678901234567890">>,
  Generate = fun (Count) -> hotp:generate(Key, Count, 6) end,
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
