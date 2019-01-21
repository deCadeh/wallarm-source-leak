require_relative './helpers/curl'
require_relative './helpers/addr'

module VulnTemplates
  module Helpers
    extend Curl
    extend Addr
  end
end

