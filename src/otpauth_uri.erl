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

-module(otpauth_uri).

-export([generate/6]).

%% @doc Generate an otpauth URI as defined in <a
%% href="https://github.com/google/google-authenticator/wiki/Key-Uri-Format">the
%% Google authenticator documentation</a>.
-spec generate(Type, Key, NbDigits, Issuer, AccountName, ExtraParameters)
              -> URI when
    Type :: hotp | totp,
    Key :: binary(),
    NbDigits :: pos_integer(),
    Issuer :: binary(),
    AccountName :: binary(),
    ExtraParameters :: list({unicode:chardata(), unicode:chardata() | true}),
    URI :: binary().
generate(Type, Key, NbDigits, Issuer, AccountName, ExtraParameters) ->
  BaseParameters = [{<<"secret">>, base32:encode(Key, [nopad])},
                    {<<"issuer">>, Issuer},
                    {<<"algorithm">>, <<"SHA1">>},
                    {<<"digits">>, integer_to_list(NbDigits)}],
  Parameters = BaseParameters ++ ExtraParameters,
  Query = uri_string:compose_query(Parameters, [{encoding, utf8}]),
  URIData = #{scheme => <<"otpauth">>,
              host => atom_to_binary(Type, utf8),
              path => io_lib:format("/~s:~s", [Issuer, AccountName]),
              query => Query},
  list_to_binary(uri_string:recompose(URIData)).

