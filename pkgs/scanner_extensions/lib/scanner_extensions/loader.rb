module ScannerExtensions
  # Modue declaration
  module Extensions; end

  # Use this for autoloading extensions classes
  module Loader
    module_function

    def load_extensions(namespace = ScannerExtensions::Extensions)
      extensions = {}
      namespace.constants.each do |extension|
        item = namespace.const_get(extension).new
        next if item.class == BaseExtension
        msg  = "'#{item.class}' is not derived from BaseExtension"
        raise msg unless item.is_a? BaseExtension
        extensions[item.class.to_s] = item
      end
      extensions
    end

    def extensions
      @extensions ||= ScannerExtensions::Loader.load_extensions.values
    end

    def extensions_by_type(type)
      extensions.select { |ext| ext.type == type }
    end

    def extensions_by_detect_type(detect_type, opts = {})
      extensions.select do |ext|
        case ext.detect_type
        when Array
          ext.detect_type.include?(detect_type)
        when Symbol
          ext.detect_type == detect_type
        else
          raise 'Invalid extension detect_type'
        end
      end.select do |ext|
        components = [ext.components].flatten
        opts[:fast] ? components.include?(:fast) : components.include?(:rechecker)
      end
    end
  end
end
