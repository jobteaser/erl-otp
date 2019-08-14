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

-module(totp_test).

-include_lib("eunit/include/eunit.hrl").

generate_test() ->
  % See RFC 6238 Appendix B.
  %
  % We only include HMAC-SHA1 tests since we do not support other key
  % derivation algorithms.
  Key = <<"12345678901234567890">>,
  Generate = fun (DateString) ->
                 Timestamp = calendar:rfc3339_to_system_time(DateString),
                 totp:generate(Key, 0, 30, Timestamp, 8)
             end,
  ?assertEqual(94287082, Generate("1970-01-01T00:00:59Z")),
  ?assertEqual(07081804, Generate("2005-03-18T01:58:29Z")),
  ?assertEqual(14050471, Generate("2005-03-18T01:58:31Z")),
  ?assertEqual(89005924, Generate("2009-02-13T23:31:30Z")),
  ?assertEqual(69279037, Generate("2033-05-18T03:33:20Z")),
  ?assertEqual(65353130, Generate("2603-10-11T11:33:20Z")).
