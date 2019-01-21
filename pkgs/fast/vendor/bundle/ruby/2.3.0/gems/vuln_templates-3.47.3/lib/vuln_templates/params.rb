module VulnTemplates
  module Params
    PARAMS = [
      :type,
      :target,
      :threat,
      :method,
      :parameter,
      :domain,
      :path,
      :title,
      :description,
      :additional,
      :exploit_example
    ]
    FILTER = [
      :method,
      :domain,
      :path,
      :parameter
    ]
    EXCLUDE = [
      :title,
      :description,
      :additional
    ]
    PREMIT = [
      :ip,
      :port
    ]
    FOOTER = [
      :additional,
      :exploit_example
    ]
    DO_NOT_XSS_FILTER = [
      :exploit_example,
      :html_rows,
      :html_baseline
    ]
  end
end

