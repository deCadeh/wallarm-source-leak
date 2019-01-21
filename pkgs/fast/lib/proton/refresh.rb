# -*- encoding: utf-8 -*-

require 'proton'

module Proton::RefreshRequestCache
  def refresh!
    @uri = nil
  end
end

class Proton::Request;               include Proton::RefreshRequestCache; end
class Proton::SerializedRequest::V1; include Proton::RefreshRequestCache; end
class Proton::SerializedRequest::V2; include Proton::RefreshRequestCache; end
class Proton::SerializedRequest::V3; include Proton::RefreshRequestCache; end
class Proton::SerializedRequest::V4; include Proton::RefreshRequestCache; end
