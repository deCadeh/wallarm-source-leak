module RpsLimit
  module Chains
    # query testrun params
    class TestRunQuery
      def initialize(params)
        @params = params
      end

      def default_session_rps
        RpsLimit.wrap_etcd_errors do
          begin
            key = EtcdKeyNames.default_session_rps_for_testrun_key(@params[:testrun])
            RpsLimit.etcd.get(key).value.to_i
          rescue Etcd::KeyNotFound
            return nil
          end
        end
      end

      def default_session_rps=(limit)
        RpsLimit.check_testrun_rps!(limit)
        key = EtcdKeyNames.default_session_rps_for_testrun_key(@params[:testrun])
        RpsLimit.wrap_etcd_errors { RpsLimit.etcd.set(key, value: limit) }
        limit
      end

      def rps
        RpsLimit.wrap_etcd_errors do
          begin
            key = EtcdKeyNames.rps_for_testrun_key(@params[:testrun])
            RpsLimit.etcd.get(key).value.to_i
          rescue Etcd::KeyNotFound
            return nil
          end
        end
      end

      def rps=(limit)
        RpsLimit.check_testrun_rps!(limit)
        key = EtcdKeyNames.rps_for_testrun_key(@params[:testrun])
        RpsLimit.wrap_etcd_errors { RpsLimit.etcd.set(key, value: limit) }
        limit
      end
    end

    # query normal params
    # rubocop:disable Metrics/ClassLength
    class Query
      def initialize(params)
        @params = params
      end

      def rps
        check_clientid!
        %i[domain ip].each do |type|
          return get_rps(type, @params[type]) if @params[type]
        end
        raise ArgumentError, 'Missing object type'
      end

      def rps=(limit)
        check_clientid!
        %i[domain ip].each do |type|
          next unless @params[type]
          if limit
            set_rps(type, @params[type], limit)
          else
            del_rps(type, @params[type])
          end
          return nil
        end
        raise ArgumentError, 'Missing object type'
      end

      def rps_per_ip
        check_clientid!
        if @params[:domain]
          get_per_rps(:domain, @params[:domain])
        else
          get_default(:ip)
        end
      end

      def rps_per_ip=(limit)
        check_clientid!
        if @params[:domain]
          if limit
            set_per_rps(:domain, @params[:domain], limit)
          else
            del_per_rps(:domain, @params[:domain])
          end
        else
          set_default(:ip, limit)
        end
      end

      def rps_per_domain
        check_clientid!
        if @params[:ip]
          get_per_rps(:ip, @params[:ip])
        else
          get_default(:domain)
        end
      end

      def rps_per_domain=(limit)
        check_clientid!
        if @params[:ip]
          if limit
            set_per_rps(:ip, @params[:ip], limit)
          else
            del_per_rps(:ip, @params[:ip])
          end
        else
          set_default(:domain, limit)
        end
      end

      private

      def get_default(type)
        RpsLimit.wrap_etcd_errors do
          begin
            key = EtcdKeyNames.send("default_rps_for_#{type}_key", @params[:clientid])
            RpsLimit.etcd.get(key).value.to_i
          rescue Etcd::KeyNotFound
            RpsLimit.const_get("DEFAULT_RPS_FOR_#{type.upcase}")
          end
        end
      end

      def set_default(type, limit)
        RpsLimit.check_rps!(limit)
        key = EtcdKeyNames.send("default_rps_for_#{type}_key", @params[:clientid])
        RpsLimit.wrap_etcd_errors { RpsLimit.etcd.set(key, value: limit) }
        limit
      end

      def set_rps(type, item, limit)
        RpsLimit.check_rps!(limit)
        key = EtcdKeyNames.send("rps_for_#{type}_key", @params[:clientid], item)
        RpsLimit.wrap_etcd_errors { RpsLimit.etcd.set(key, value: limit) }
        limit
      end

      def del_rps(type, item)
        key = EtcdKeyNames.send("rps_for_#{type}_key", @params[:clientid], item)
        RpsLimit.skip_errors { RpsLimit.etcd.delete(key) }
        true
      end

      def get_rps(type, item)
        RpsLimit.wrap_etcd_errors do
          begin
            key = EtcdKeyNames.send("rps_for_#{type}_key", @params[:clientid], item)
            RpsLimit.etcd.get(key).value.to_i
          rescue Etcd::KeyNotFound
            get_default(type)
          end
        end
      end

      def get_per_rps(type, item)
        RpsLimit.wrap_etcd_errors do
          begin
            key = EtcdKeyNames.send(
              "rps_for_#{type}_per_#{RpsLimit.related_obj_by(type)}_key",
              @params[:clientid],
              item
            )
            RpsLimit.etcd.get(key).value.to_i
          rescue Etcd::KeyNotFound
            MAX_ALLOWED_RPS
          end
        end
      end

      def set_per_rps(type, item, limit)
        RpsLimit.check_rps!(limit)
        key = EtcdKeyNames.send(
          "rps_for_#{type}_per_#{RpsLimit.related_obj_by(type)}_key",
          @params[:clientid],
          item
        )
        RpsLimit.wrap_etcd_errors { RpsLimit.etcd.set(key, value: limit) }
        limit
      end

      def del_per_rps(type, item)
        key = EtcdKeyNames.send(
          "rps_for_#{type}_per_#{RpsLimit.related_obj_by(type)}_key",
          @params[:clientid],
          item
        )
        RpsLimit.skip_errors { RpsLimit.etcd.delete(key) }
        true
      end

      def check_clientid!
        raise ArgumentError, 'Missing client' unless @params[:clientid]
      end
    end
  end
end
