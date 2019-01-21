require_relative './params.rb'
require 'erb'

module VulnTemplates
  private

  module Filler
    class Binding
      def initialize(params, opt={})
        @params   = params
        @opt      = opt
        @params ||= {}
        Params::PARAMS.each do |name|
          eval (
            <<-fin
              def self.#{name}
                select(:#{name})
              end
            fin
          )
        end
        @params.each do |name,_|
          eval (
            <<-fin
              def self.#{name}
                select(:#{name})
              end
            fin
          )
        end
      end

      def fill(template, t_name=nil)
        @t_name = t_name
        ERB.new(template).result(Kernel.binding())
      end

      def method_missing(method, *args, &block)
        select(method)
      end

      private

      def select(name)
        if @t_name
          res = Params::DO_NOT_XSS_FILTER.include?(@t_name.to_sym)
          inside_do_not_xss_place = res
        else
          inside_do_not_xss_place = false
        end
        if @params[name]
          if @params[name].respond_to?(:force_escape_html)         &&
               !Params::DO_NOT_XSS_FILTER.include?(name.to_sym)    &&
               !@params[name].respond_to?(:skip_escape_html)       &&
               !inside_do_not_xss_place
            return @params[name].force_escape_html
          else
            return @params[name]
          end
        elsif Params::PARAMS.include?(name) || @opt[:force]
          if name==:threat
            return 50
          else
            VulnTemplates.force_param
          end
        else
          raise MissingParam, name
        end
      end
    end

    module_function

    def fill_view(str, params, opt)
      Binding.new(params, opt).fill(str)
    rescue NoMethodError => e
      raise VulnTemplates::InvalidParam
    end

    def fill(values, params, opt={})
      binding = Binding.new(params, opt)
      result  = {}
      current = nil
      values.each do |k,v|
        current   = k
        result[k] = binding.fill(v, k)
      end
      result
    rescue NoMethodError => e
      raise VulnTemplates::InvalidParam, current
    end
  end
end

