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

-module(hotp_validator_test).

-include_lib("eunit/include/eunit.hrl").

authenticate_test() ->
  Key = <<"12345678901234567890">>,
  Validator = hotp_validator:init(Key, [{look_ahead, 2}]),
  % Counter 0. Start with an invalid password
  {Validator1, Valid1} = hotp_validator:authenticate(Validator, 123456),
  ?assertEqual(invalid, Valid1),
  % Counter 0. Use the right password
  {Validator2, Valid2} = hotp_validator:authenticate(Validator1, 287082),
  ?assertEqual(valid, Valid2),
  % Counter 1. Since the counter has been incremented by 1, the same password
  % should not be valid anymore.
  {Validator3, Valid3} = hotp_validator:authenticate(Validator2, 287082),
  ?assertEqual(invalid, Valid3),
  % Counter 1. The password for counter 2 should be valid.
  {Validator4, Valid4} = hotp_validator:authenticate(Validator3, 359152),
  ?assertEqual(valid, Valid4),
  % Counter 2. Since the look ahead parameter is set to 2, the password for
  % counter 5 should be valid.
  {Validator5, Valid5} = hotp_validator:authenticate(Validator4, 254676),
  ?assertEqual(valid, Valid5),
  % Counter 5. Passwords for counters 4, 5 and 9 should be invalid.
  {Validator6, Valid6} = hotp_validator:authenticate(Validator5, 338314),
  ?assertEqual(invalid, Valid6),
  {Validator7, Valid7} = hotp_validator:authenticate(Validator6, 254676),
  ?assertEqual(invalid, Valid7),
  {_, Valid8} = hotp_validator:authenticate(Validator7, 520489),
  ?assertEqual(invalid, Valid8).

otpauth_uri_test() ->
  Key = <<"12345">>,
  Validator = hotp_validator:init(Key, [{nb_digits, 8}]),
  Issuer = <<"JobTeaser"/utf8>>,
  AccountName = <<"bob@example.com"/utf8>>,
  URI = hotp_validator:otpauth_uri(Validator, Issuer, AccountName),
  ?assertEqual(<<"otpauth://hotp/JobTeaser:bob@example.com?secret=GEZDGNBV&issuer=JobTeaser&algorithm=SHA1&digits=8&counter=0">>, URI).
