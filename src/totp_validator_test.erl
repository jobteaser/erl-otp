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

-module(totp_validator_test).

-include_lib("eunit/include/eunit.hrl").

authenticate_test() ->
  Key = <<"12345678901234567890">>,
  Validator = totp_validator:init(Key, [{time_step, 10},
                                        {look_ahead, 1}, {look_behind, 1}]),
  % All timestamps in [50, 59[ are in period 5; since we use a look ahead and
  % behind of one, the password for period 5 should be valid for all
  % timestamps in [40, 69[.
  %
  % We do not reuse the validator so that we skip the test on the last period.
  {_, Valid1} = totp_validator:authenticate(Validator, 254676, 50),
  ?assertEqual(valid, Valid1),
  {_, Valid2} = totp_validator:authenticate(Validator, 254676, 59),
  ?assertEqual(valid, Valid2),
  {_, Valid3} = totp_validator:authenticate(Validator, 254676, 40),
  ?assertEqual(valid, Valid3),
  {_, Valid4} = totp_validator:authenticate(Validator, 254676, 69),
  ?assertEqual(valid, Valid4),
  {_, Valid5} = totp_validator:authenticate(Validator, 254676, 39),
  ?assertEqual(invalid, Valid5),
  {_, Valid6} = totp_validator:authenticate(Validator, 254676, 70),
  ?assertEqual(invalid, Valid6).

same_time_period_test() ->
  Key = <<"12345678901234567890">>,
  Validator = totp_validator:init(Key, [{time_step, 10}]),
  % Authenticating with a timestamp in the same time period than the previous
  % authentication attempt is invalid.
  {Validator1, Valid1} = totp_validator:authenticate(Validator, 254676, 50),
  ?assertEqual(valid, Valid1),
  {_, Valid2} = totp_validator:authenticate(Validator1, 254676, 55),
  ?assertEqual(invalid, Valid2).
