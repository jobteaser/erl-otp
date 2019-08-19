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

-module(totp_validator).

-export([init/1, init/2, authenticate/2, authenticate/3, otpauth_uri/3]).

-record(validator, {key :: binary(),
                    nb_digits :: pos_integer(),
                    initial_time :: totp:timestamp(),
                    time_step :: pos_integer(),
                    look_behind :: non_neg_integer(),
                    look_ahead :: non_neg_integer(),
                    last_auth_time_period :: totp:time_period() | undefined}).
-type validator() :: #validator{}.

-type validator_options() :: [validator_option()].
-type validator_option() :: {nb_digits, pos_integer()}
                          | {initial_time, totp:timestamp()}
                          | {time_step, pos_integer()}
                          | {look_behind, non_neg_integer()}
                          | {look_ahead, non_neg_integer()}.

%% @doc Initialize and return a new TOTP validator using default settings.
%%
%% @see init/2
-spec init(Key :: binary()) -> validator().
init(Key) ->
  init(Key, []).

%% @doc Initialize and return a new TOTP validator.
-spec init(Key :: binary(), Options :: validator_options()) -> validator().
init(Key, Options) ->
  InitialTime = proplists:get_value(initial_time, Options, 0),
  TimeStep = proplists:get_value(time_step, Options, 30),
  NbDigits = proplists:get_value(nb_digits, Options, 6),
  LookBehind = proplists:get_value(look_behind, Options, 1),
  LookAhead = proplists:get_value(look_ahead, Options, 1),
  #validator{key = Key,
             initial_time = InitialTime,
             time_step = TimeStep,
             nb_digits = NbDigits,
             look_behind = LookBehind,
             look_ahead = LookAhead}.

%% @doc Authenticate a password using the current system timestamp.
%%
%% @see authenticate/3
-spec authenticate(validator(), Password) ->
                      {validator(), valid | invalid} when
    Password :: pos_integer().
authenticate(Validator, Password) ->
  authenticate(Validator, Password, totp:current_timestamp()).

%% @doc Authenticate a password, assuming a specific current timestamp.
-spec authenticate(validator(), Password, Time) ->
                      {validator(), valid | invalid} when
    Password :: pos_integer(),
    Time :: totp:timestamp().
authenticate(Validator, Password, Time) ->
  InitialTime = Validator#validator.initial_time,
  TimeStep = Validator#validator.time_step,
  TimePeriod = totp:time_period(InitialTime, TimeStep, Time),
  authenticate_with_time_period(Validator, Password, TimePeriod).

-spec authenticate_with_time_period(validator(), Password, TimePeriod) ->
                                       {validator(), valid | invalid} when
    Password :: pos_integer(),
    TimePeriod :: totp:time_period().
authenticate_with_time_period(Validator, _Password, TimePeriod) when
    TimePeriod == Validator#validator.last_auth_time_period ->
  {Validator, invalid};
authenticate_with_time_period(Validator, Password, TimePeriod) ->
  Key = Validator#validator.key,
  NbDigits = Validator#validator.nb_digits,
  LookBehind = Validator#validator.look_behind,
  LookAhead = Validator#validator.look_ahead,
  TimePeriodPasswords = [totp:generate_with_time_period(Key, TP, NbDigits) ||
                          TP <- lists:seq(TimePeriod - LookBehind,
                                          TimePeriod + LookAhead)],
  EqualToPassword = fun (TPPassword) -> Password == TPPassword end,
  Validator2 = Validator#validator{last_auth_time_period = TimePeriod},
  case lists:search(EqualToPassword, TimePeriodPasswords) of
    {value, _} ->
      {Validator2, valid};
    false ->
      {Validator2, invalid}
  end.

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
  TimeStep = Validator#validator.time_step,
  Parameters = [{<<"period">>, integer_to_list(TimeStep)}],
  otpauth_uri:generate(totp, Key, NbDigits, Issuer, AccountName, Parameters).
