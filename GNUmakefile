
all: build doc

dialyzer:
	rebar3 dialyzer

build:
	rebar3 compile

test:
	rebar3 eunit

doc:
	rebar3 edoc

clean:
	$(RM) -r _build

.PHONY: all dialyzer build test doc clean
