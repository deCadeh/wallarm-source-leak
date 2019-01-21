#

class Wallarm
  class API
    class ServerError < RuntimeError
      attr_reader :response

      def initialize( msg, response)
        super msg

        @response = response
      end
    end

    class BadRequest < RuntimeError
      attr_reader :data, :response

      def initialize( msg, response)
        if msg.is_a? Hash
          super "Invalid params #{msg.keys.join ', '}"
        else
          super data
        end

        @response = response
      end
    end

    class LoginFailed   < RuntimeError; end
    class AccessDenied  < RuntimeError; end
    class AlreadyExists < RuntimeError; end
    class NotModified   < RuntimeError; end
  end
end
