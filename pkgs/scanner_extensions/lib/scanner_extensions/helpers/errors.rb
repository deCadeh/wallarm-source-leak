module ScannerExtensions
  module Helpers
    module Errors
      module_function

      def errors
        [
          /(SQL syntax.*?MySQL)/,
          /(Warning.*?mysql_)/,
          /(valid MySQL result)/,
          /(MySqlClient\.)/,
          /(PostgreSQL.*?ERROR)/,
          /(Warning.*?pg_)/i,
          /(valid PostgreSQL result)/,
          /(Npgsql\.)/,
          /(Driver.*?SQL.*?Server)/,
          /(OLE DB.*?SQL Server)/,
          /(SQL Server.*?Driver)/i,
          /(Warning.*?mssql_)/,
          /(SQL Server.*?[0-9a-fA-F]{8})/i,
          /(Exception.*?System\.Data\.SqlClient\.)/i,
          /(Exception.*?Roadhouse\.Cms\.)/i,
          /(Microsoft Access Driver)/,
          /(JET Database Engine)/,
          /(Access Database Engine)/,
          /(ORA-[0-9]{4})/,
          /(Oracle error)/,
          /(Oracle.*?Driver)/,
          /(Warning.*?oci_)/i,
          /(Warning.*?ora_)/i,
          /(CLI Driver.*?DB2)/,
          /(DB2 SQL error)/,
          /(SQLite\/JDBCDriver)/,
          /(SQLite.*?Exception)/,
          /(System.*?Data.*?SQLite.*?SQLiteException)/,
          /(Warning.*?sqlite)/,
          /(Warning.*?SQLite3::)/,
          /(\[SQLITE_ERROR\])/,
          /(Warning.*?sybase)/i,
          /(Sybase message)/i,
          /(Sybase.*?Server message)/,
          /<b>Warning<\/b>: (.*)$/,
          /<b>Fatal Error<\/b>: (.*)$/,
          /<b>Notice<\/b>: (.*)$/,
          /^(.*)$<\/b> on line <b>(.*)$/
        ]
      end

      def find(data, addtitional = [])
        res = []
        (errors + addtitional).each do |e|
          res << Regexp.last_match[0] if data.index(e)
        end
        res
      end
    end
  end
end
