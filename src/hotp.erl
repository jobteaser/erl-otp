
-module(hotp).

-export([generate/3]).

-export_type([counter/0]).

-type counter() :: <<_:64>>.
%% A 8 byte binary counter used as moving factor.
%%
%% Defined in <a href="https://tools.ietf.org/html/rfc4226#section-5.1">RFC
%% 4226 5.1</a>.

-type sha1_hmac() :: <<_:160>>.
%% A HMAC-SHA1 binary value.

%% @doc Generate a HMAC-based one-time password.
%%
%% See <a href="https://tools.ietf.org/html/rfc4226#section-5.3">RFC 4226
%% 5.3</a>.
-spec generate(Key, Counter, NbDigits) -> Password when
    Key :: iodata(),
    Counter :: counter(),
    NbDigits :: non_neg_integer(),
    Password :: non_neg_integer().
generate(Key, Counter, NbDigits) ->
  truncate(crypto:hmac(sha, Key, Counter), NbDigits).

%% @doc Truncate a SHA1 HMAC and reduces it to a numeric password containing
%% `NbDigits' digits.
%%
%% See <a href="https://tools.ietf.org/html/rfc4226#section-5.3">RFC 4226
%% 5.3</a>.
-spec truncate(HMAC, NbDigits) -> Password when
    HMAC :: sha1_hmac(),
    NbDigits :: non_neg_integer(),
    Password :: non_neg_integer().
truncate(HMAC, NbDigits) when byte_size(HMAC) == 20 ->
  Offset = binary:at(HMAC, 19) band 16#0f,
  C0 = (binary:at(HMAC, Offset) band 16#7f) bsl 24,
  C1 = (binary:at(HMAC, Offset + 1) band 16#ff) bsl 16,
  C2 = (binary:at(HMAC, Offset + 2) band 16#ff) bsl 8,
  C3 = (binary:at(HMAC, Offset + 3) band 16#ff),
  P = C0 bor C1 bor C2 bor C3,
  P rem pow10(NbDigits).

%% @doc Compute 10 to the power of `N'.
%%
%% The function is only defined for positive integers.
%%
%% We do not use `math:pow' since it uses floating point numbers.
-spec pow10(non_neg_integer()) -> non_neg_integer().
pow10(N) when N > 0 ->
  pow10(N, 1).

pow10(0, Acc) ->
  Acc;
pow10(N, Acc) ->
  pow10(N - 1, Acc * 10).
