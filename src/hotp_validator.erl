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

-module(hotp_validator).

-export([init/1, init/2, authenticate/2,
         otpauth_uri/3]).

-export_type([validator_options/0, validator_option/0]).

-record(validator, {key :: binary(),
                    counter :: hotp:counter(),
                    nb_digits :: pos_integer(),
                    look_ahead :: non_neg_integer()}).
-type validator() :: #validator{}.

-type validator_options() :: [validator_option()].
-type validator_option() :: {initial_counter, hotp:counter()}
                          | {nb_digits, pos_integer()}
                          | {look_ahead, non_neg_integer()}.

%% @doc Initialize and return a new HOTP validator using default settings.
%%
%% @see init/2
-spec init(Key :: binary()) -> validator().
init(Key) ->
  init(Key, []).

%% @doc Initialize and return a new HOTP validator.
-spec init(Key :: binary(), Options :: validator_options()) -> validator().
init(Key, Options) ->
  Counter = proplists:get_value(initial_counter, Options, 0),
  NbDigits = proplists:get_value(nb_digits, Options, 6),
  LookAhead = proplists:get_value(look_ahead, Options, 5),
  #validator{key = Key,
             counter = Counter,
             nb_digits = NbDigits,
             look_ahead = LookAhead}.

%% @doc Authenticate a client password.
%%
%% See <a href="https://tools.ietf.org/html/rfc4226#section-7.2">RFC 4226
%% 7.2</a>.
-spec authenticate(validator(), Password) ->
                      {validator(), valid | invalid} when
    Password :: pos_integer().
authenticate(Validator, Password) ->
  Counter = Validator#validator.counter,
  LookAhead = Validator#validator.look_ahead,
  NextCounters = lists:seq(Counter + 1, Counter + 1 + LookAhead),
  IsPasswordValid = fun (C) -> is_password_valid(Validator, Password, C) end,
  case lists:search(IsPasswordValid, NextCounters) of
    {value, MatchingCounter} ->
      Validator2 = Validator#validator{counter = MatchingCounter},
      {Validator2, valid};
    false ->
      {Validator, invalid}
  end.

%% @doc Return whether a password is valid for a specific counter or not.
-spec is_password_valid(validator(), Password, Counter) ->
                           boolean() when
    Password :: pos_integer(),
    Counter :: hotp:counter().
is_password_valid(Validator, Password, Counter) ->
  Key = Validator#validator.key,
  NbDigits = Validator#validator.nb_digits,
  ServerPassword = hotp:generate(Key, Counter, NbDigits),
  Password == ServerPassword.

%% @doc Return an URI representing a validator that can be used to
%% automatically configure a client (or at least a Google authenticator). See
%% <a
%% href="https://github.com/google/google-authenticator/wiki/Key-Uri-Format">the
%% Google authenticator documentation</a>.
-spec otpauth_uri(validator(), Issuer, AccountName) -> URI when
    Issuer :: binary(),
    AccountName :: binary(),
    URI :: binary().
otpauth_uri(Validator, Issuer, AccountName) ->
  Key = Validator#validator.key,
  NbDigits = Validator#validator.nb_digits,
  Counter = Validator#validator.counter,
  Parameters = [{<<"counter">>, integer_to_list(Counter)}],
  otpauth_uri:generate(hotp, Key, NbDigits, Issuer, AccountName, Parameters).
