require 'json'

mapping = {
  'template' => '*',
  'mappings' => {
    'log_record' => {
      'properties' => {
        'baseline_check_id' => { 'type' => 'long' },
        'time'              => { 'type' => 'long' },
        'id'                => { 'type' => 'keyword', 'index' => 'not_analyzed' }
      }
    }
  }
}

puts "curl -XPUT 'http://127.0.0.1:9200/_template/log_record' -d '#{mapping.to_json}'"
