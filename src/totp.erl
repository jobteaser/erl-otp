
-module(totp).

-export([generate/5, generate/3,
         current_timestamp/0]).

-export_type([]).

-type timestamp() :: integer().

%% @doc Generate a time-based one-time password.
%%
%% `InitialTime' and `TimeStep' are the algorithm parameters designated as
%% `T0' and `X' in <a
%% href="https://tools.ietf.org/html/rfc6238#section-4.1">RFC 6238 4.1</a>.
%%
%% We only support the HMAC-SHA1 key derivation algorithm: it is the only
%% mandatory one, it is the one everyone uses, and RFC 4226 (HOTP) only
%% specifies truncation for HMAC-SHA1.
%%
%% See <a href="https://tools.ietf.org/html/rfc6238#section-4.2">RFC 6238
%% 4.2</a>.
-spec generate(Key, InitialTime, TimeStep, CurrentTime, NbDigits)
              -> Password when
    Key :: iodata(),
    InitialTime :: timestamp(),
    TimeStep :: pos_integer(),
    CurrentTime :: timestamp(),
    NbDigits :: pos_integer(),
    Password :: pos_integer().
generate(Key, InitialTime, TimeStep, CurrentTime, NbDigits) ->
  T = trunc(math:floor((CurrentTime - InitialTime) / TimeStep)),
  Counter = <<T:64>>,
  hotp:generate(Key, Counter, NbDigits).

%% @doc Generate a time-based one-time password using the default parameters
%% specified in <a href="https://tools.ietf.org/html/rfc6238#section-4.1">RFC
%% 6238 4.1</a>.
%%
%% @see generate/5
-spec generate(Key, CurrentTime, NbDigits) -> Password when
    Key :: iodata(),
    CurrentTime :: timestamp(),
    NbDigits :: pos_integer(),
    Password :: pos_integer().
generate(Key, CurrentTime, NbDigits) ->
  generate(Key, 0, 30, CurrentTime, NbDigits).

%% @doc Return the current UNIX timestamp in seconds.
%%
%% The function is provided both as a convenience, and to make sure that the
%% right clock is used: RFC 6238 clearly specify that the algorithm is based
%% on UNIX timestamps (which has its importance, for example for leap
%% seconds).
-spec current_timestamp() -> timestamp().
current_timestamp() ->
  os:system_time(second).
