class BaselineCheckJob
  # Extend BaselineCheckJob
  module RunExtensionsHelper
    def get_entries(req, policy)
      entries = []

      points_by_policy(req, policy).each do |point|
        req_dup = Marshal.load(Marshal.dump(req))

        objects = Proton2Scanner.get_objects_from(req_dup, point, true, false)
        next if objects.empty?

        objects.each { |object| object.init_test_run_policy(policy[:raw]) }

        entries << objects
      end

      entries
    end

    private

    def entries_by_req(req)
      all_entries = []

      # custom each without map
      req.each do |entry|
        all_entries << {
          point: entry.point,
          value: entry.value
        }
      end

      uri_point = Proton::Point.new('URI_value')

      all_entries << {
        point: uri_point,
        value: req[uri_point].value
      }

      all_entries
    end

    def points_by_policy(req, policy)
      p_include = policy[:parameter_include]
      p_exclude = policy[:parameter_exclude]

      points = []

      entries_by_req(req).each do |entry|
        point     = entry[:point]
        str_point = entry[:point].to_s.normalize_enconding

        # handle include points
        if p_include
          skip = true
          p_include.each { |r| skip = false if str_point =~ r }

          next if skip
        end

        # handle exclude points
        if p_exclude
          skip = false
          p_exclude.each { |r| skip = true if str_point =~ r }
          ['HEADER_X-WALLARM'].each { |r| skip = true if str_point.index(r) }
          next if skip
        end

        if str_point.end_with?('BASE64_value') && !p_include.to_s.include?('BASE64')
          next if entry[:value][-1] != '='
        end

        points << point
      end

      points.uniq
    end
  end
end
