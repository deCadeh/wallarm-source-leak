require 'cgi'

module FastDsl
  module Blocks
    # just additional params
    class MetaInfo
      class << self
        def schema
          Dry::Validation.Schema do
            configure { predicates(Schema::Predicates) }

            required('type').value(
              :str?,
              included_in?: %w[anomaly ldapi nosqli csrf idor ssti ssrf auth info rce sqli xss xxe ptrav redir]
            )

            optional('threat').value(type?: Integer, gt?: 0, lteq?: 100)

            optional('tags').each(:str?, :filled?)

            optional('title').value(:str?, :filled?)
            optional('description').value(:str?, :filled?)
            optional('additional').value(:str?, :filled?)
          end
        end
      end

      attr_reader :type, :threat, :tags, :title, :description, :additional

      def to_h
        {
          type:        @type,
          threat:      @threat,
          title:       @title,
          description: @description,
          additional:  @additional
        }.to_a.select { |_k, v| v }.to_h
      end

      def initialize(params)
        @type   = params['type']
        @threat = params['threat'] || 50

        escaped = {}
        %w[title description additional].each do |k|
          escaped[k] = CGI.escapeHTML(params[k]) if params[k]
        end

        @title       = escaped['title']
        @description = escaped['description']
        @additional  = escaped['additional']
      end
    end
  end
end
