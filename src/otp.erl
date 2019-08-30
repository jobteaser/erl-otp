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

-module(otp).

-export([password_to_string/2, password_to_binary/2]).

%% @doc Convert a one-time password to a padded string.
%%
%% The result is undefined if the string representation of `Password' contains
%% more digits than `NbDigits'.
-spec password_to_string(Password, NbDigits) -> string() when
    Password :: non_neg_integer(),
    NbDigits :: pos_integer().
password_to_string(Password, NbDigits) ->
  io_lib:format("~*..0B", [NbDigits, Password]).

%% @doc Convert a one-time password to a padded binary string.
%%
%% @see password_to_string/2
-spec password_to_binary(Password, NbDigits) -> binary() when
    Password :: non_neg_integer(),
    NbDigits :: pos_integer().
password_to_binary(Password, NbDigits) ->
  list_to_binary(password_to_string(Password, NbDigits)).
