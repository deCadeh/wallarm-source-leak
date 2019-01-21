require_relative './rules'

module FastDsl
  module Blocks
    # extend detect class
    class Detect
      # convert flat parsed struct to array or rules
      module RuleMaker
        ANY_MARKERS = 'DNS_MARKER|CALC_MARKER|STR_MARKER'.freeze
        ANY_TAGS    = %w[tag js href attr].freeze

        def init_flat_rules
          @headers_any_marker = false
          @body_any_marker    = false
          @body_any_html      = false
          @oob_dns            = false

          @status_regexp       = []
          @body_regexp         = []
          @full_headers_regexp = []
          @headers_regexp      = []

          @body_html        = []
          @body_html_regexp = []
        end

        def rules
          res = []

          @body_regexp.each { |r| res << Rules::BodyMarker.new(r) }
          res << Rules::BodyMarker.new(ANY_MARKERS) if @body_any_marker

          @headers_regexp.each do |hash|
            hash.each { |k, v| res << Rules::HeadersMarker.new(k, v) }
          end

          @full_headers_regexp.each { |r| res << Rules::HeadersFullscanMarker.new(r) }

          res << Rules::HeadersFullscanMarker.new(ANY_MARKERS) if @headers_any_marker

          @status_regexp.each { |s| res << Rules::Status.new(s) }

          if @body_any_html
            ANY_TAGS.each do |tag|
              res << Rules::BodyHtml.new(tag, '\ASTR_MARKER\z')
            end
          end

          @body_html_regexp.each do |hash|
            hash.each { |k, v| res << Rules::BodyHtml.new(k, v) }
          end

          @body_html.each { |tag| res << Rules::BodyHtml.new(tag, '\ASTR_MARKER\z') }

          res << Rules::OobDns.new if @oob_dns

          res
        end
      end
    end
  end
end
