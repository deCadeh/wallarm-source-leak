# FastDsl

FastDsl allows users to write theirs own custom vulnerability detects

Now we are using it into FAST, but later we will use it into scanner and attack-rechecker projects

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'test'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install test

## Usage

```ruby
reqiure 'fast_dsl'

# configure oob dns
FastDsl.oob_dns = OobDns

detect = FastDsl::Detect.new(YAML.load(data))

if detect.applicable?(baseline)
  ctx = detect.run(baseline)
  return ctx.vuln?
end
```

## Example of DSL syntax
```
# just meta-info
meta-info:
  type:   xss
  threat: 30
  # title
  # description
  # additional
  tags:
    - tag1

# for which baselines detect is applicable
match:
  'GET_a_value': 'abc'   # just point equals value condition
  'GET_b_value': '\d+'   # values could be regexps
  'GET_c_value': ''      # point is empty
  'GET_d_value': null    # point should not exist
  'HEADER_\w*_': '321'   # all points by regexp should fit value

# how we should modify baseline before send it
modify:
  'GET_a_value': 'abc'   # just set point value

# what should we send to server ad payload
generate:
  into: 'GET|POST'
  method:
    - postfix
    - prefix
    - random
    - replace
  payload:
    - '1 or sleep 5 -- <STR\_MARKER>; ping DNS\_MARKER; CALC\_MARKER'

# what should we search into server's response to find vuln
detect:
  # any oob marker
  - oob

  # only oob dns marker
  - oob:
    - dns

  # any marker in response
  - response

  - response:
    # precise match
    - status: 500

    # regexp /\A40.*/
    - status: '40'

    # any marker in headers
    - headers

    # regexp (with marker)
    - headers: "http:\/\/DNS_MARKER"

    # check specific headers
    - headers:
      # keys and values are regexps
      - 'X-': 'CALC_MARKER'

    # any marker into body
    - body

    # regexp on body
    - body: "SQL error"

    # regexp on body with desired marker
    - body: "CALC\_MARKER"

    - body:
      # STR_MARKER parsed as any html entity
      - html

      - html:
        # STR_MARKER parsed as html tag
        - tag

        # STR_MARKER is found into attribute
        - attribute

        # STR_MARKER is found into attribute (same as attribute)
        - attr

        # STR_MARKER is found as token into java script
        - js

        # STR_MARKER is found into href
        - href

        # regexp on tag value
        - tag: 'STR_MARKER'

        # regexp on js tokens
        - js: 'abc'

        # regexp on href
        - href: 'DNS_MARKER'

        # regexp on attribute
        - attribute: '(abc|CALC_MARKER)'

        # regexp on attribute (same as attribute)
        - attr: '\d+'

```
