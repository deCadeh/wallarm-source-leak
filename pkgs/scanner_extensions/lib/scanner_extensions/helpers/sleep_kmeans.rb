class SleepKmeans
  attr_accessor :object, :payloads, :params, :vuln_payload, :responces, :normal_response_time, :anomaly_response_time, :anomaly_detected, :base_time
  def initialize(object,  payloads, params)
    @object = object
    @payloads = payloads
    @params = params
    @base_time = params[:base_time]
  end

  def perform_detect
    init_times = get_usual_response_time
    return if init_times.flatten.compact.empty?
    init_centroid_kmeans = KMeansClusterer.run 1, init_times
    init_centroid_time = init_centroid_kmeans.centroids[0]
    init_dispersion = init_centroid_kmeans.distances.max.to_i
    @base_time += init_dispersion if init_dispersion >= 1

    init_response_times = [[init_centroid_time]]
    centroids = [[init_centroid_time], [init_centroid_time + @base_time]]

    @payloads.each do |payload|
      payload_time = get_time(payload, @base_time)
      init_response_times << [payload_time]
      kmeans = KMeansClusterer.run 2, init_response_times, init: centroids
      next unless kmeans.clusters[1].points.any? && payload_time > @base_time
      checks_response_times = 3.times.flat_map do
        [
          [get_time(payload, 0)],
          [get_time(payload, @base_time * 2)]
        ]
      end
      check_kmeans = KMeansClusterer.run 2, init_response_times + checks_response_times, init: [[init_centroid_time], [init_centroid_time + @base_time * 2]]
      normal_responses_are_normal = checks_response_times.values_at(*checks_response_times.each_index.select(&:even?)).map do |normal_response|
        check_kmeans.predict([normal_response]) == [0] && normal_response[0] < @base_time
      end.uniq == [true]
      sleep_responses_are_sleep = checks_response_times.values_at(*checks_response_times.each_index.select(&:odd?)).map do |sleep_response|
        check_kmeans.predict([sleep_response]) == [1] && sleep_response[0] > @base_time
      end.uniq == [true]

      if normal_responses_are_normal && sleep_responses_are_sleep
        @anomaly_detected = true
        @normal_response_time = init_centroid_time
        @anomaly_response_time = checks_response_times.last[0]
        @vuln_payload = payload
        return
      else
        single_cluster_kmeans = KMeansClusterer.run 1, init_response_times
        init_centroid_time = single_cluster_kmeans.centroids[0]
        init_centroid_distance = single_cluster_kmeans.distances.max
        @base_time += init_centroid_distance
        centroids = [[init_centroid_time], [init_centroid_time + @base_time]]
      end
    end
  end

  def get_usual_response_time
    Array.new(10) do
      [get_time(@payloads.sample, 0)]
    end
  end

  def detect_anomaly?
    @anomaly_detected
  end

  def get_injection_prefix
    case @object.point.to_a
    when [:header, 'X-FORWARDED-FOR']
      '127.0.0.1'
    when [:header, 'X-REAL-IP']
      '127.0.0.1'
    when [:header, 'FORWARDED']
      'for=127.0.0.1'
    when [:header, 'REFERRER']
      'https://wlrm.com'
    else
      '1'
    end
  end

  def get_time(vector, time)
    start    = Time.now.to_f
    max_time = 150
    time = time.to_i
    formatted_val = if @params[:with_prefix]
                      format(vector, time: time, prefix: get_injection_prefix)
                    else
                      format(vector, time: time)
                    end
    @object.http(
      value:        formatted_val,
      timeout:      max_time,
      open_timeout: max_time
    )
    endt = Time.now.to_f
    endt - start
  end
end
