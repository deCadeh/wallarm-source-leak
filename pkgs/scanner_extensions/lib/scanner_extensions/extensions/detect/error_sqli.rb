module ScannerExtensions
  module Extensions
    # Detect sqli error messages into https responses
    class ErrorSqli < BaseExtension
      def initialize
        @type                = :detect
        @general_object_type = :param
        @extension_type      = :vuln
        @detect_type         = :sqli

        @defaults = {
          timeout: 15
        }

        @poison    = ["wlrm'),\");\\'(%c0%67--"]
        @errors    = [
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
          /(SybSQLException)/,
          /(com\.sybase\.jdbc)/i,
          /(Warning.*?ingres_\.jdbc)/,
          /(Ingres SQLSTATE)/,
          /(Ingres.*?Driver)/,
          /(Exception.*?Transaction rollback)/,
          /(org\.hsqldb\.jdbc)/,
          /(Unexpected end of command in statement \[)/,
          /(Unexpected token.*?in statement \[)/,
          /(Query failed: ERROR:)/,
          /(System\.Data\.OleDb\.OleDbException)/,
          /(\[SQL Server\])/,
          /(\[Microsoft\]\[ODBC SQL Server Driver\])/,
          /(\[SQLServer JDBC Driver\])/,
          /(\[SqlException)/,
          /(System\.Data\.SqlClient\.SqlException)/,
          /(Unclosed quotation mark after the character string)/,
          /('80040e14')/,
          /(mssql_query\(\))/,
          /(odbc_exec\(\))/,
          /(Microsoft OLE DB Provider for ODBC Drivers)/,
          /(Microsoft OLE DB Provider for SQL Server)/,
          /(Incorrect syntax near)/,
          /(Sintaxis incorrecta cerca de)/,
          /(Syntax error in string in query expression)/,
          /(ADODB\.Field \(0x800A0BCD\)<br>)/,
          /(Procedure.*?requires parameter.*?)/,
          /(ADODB\.Recordset)/,
          /(Unclosed quotation mark before the character string)/,
          /('80040e07')/,
          /(Microsoft SQL Native Client error)/,
          /(SQLCODE)/,
          /(DB2 SQL error:)/,
          /(SQLSTATE)/,
          /(\[CLI Driver\])/,
          /(\[DB2\/6000\])/,
          /(Sybase message:)/,
          /(Sybase Driver)/,
          /(\[SYBASE\])/,
          /(Syntax error in query expression)/,
          /(Data type mismatch in criteria expression)/,
          /(Microsoft JET Database Engine)/,
          /(\[Microsoft\]\[ODBC Microsoft Access Driver\])/,
          /((PLS|ORA)-[0-9][0-9][0-9][0-9])/,
          /(PostgreSQL query failed:)/,
          /(supplied argument is not a valid PostgreSQL result)/,
          /(pg_query\(\) \[:)/,
          /(pg_exec\(\) \[:)/,
          /(supplied argument is not a valid MySQL)/,
          /(Column count doesn't match value count at row)/,
          /(mysql_fetch_array\(\))/,
          /(mysql_)/,
          /(on MySQL result index)/,
          /(You have an error in your SQL syntax;)/,
          /(You have an error in your SQL syntax near)/,
          /(MySQL server version for the right syntax to use)/,
          /(\[MySQL\]\[ODBC)/,
          /(Column count doesn't match)/,
          /(the used select statements have different number of columns)/,
          /(Table.*?doesn't exist)/,
          /(DBD::mysql::st execute failed)/,
          /(DBD::mysql::db do failed)/,
          /(com\.informix\.jdbc)/,
          /(Dynamic Page Generation Error)/,
          /(An illegal character has been found in the statement)/,
          /(\[Informix\])/,
          /(\<b\>Warning\<\/b'\>:  ibase_)/,
          /(\[DM_QUERY_E_SYNTAX\])/,
          /(has occurred in the vicinity of)/,
          /(A Parser Error \(syntax error\))/,
          /(java\.sql\.SQLException)/,
          /(Unexpected end of command in statement)/,
          /(\[Macromedia\]\[SQLServer JDBC Driver\])/,
          /(SELECT .*? FROM .*?)/,
          /(UPDATE .*? SET .*?)/,
          /(INSERT INTO .*?)/,
          /(Unknown column)/,
          /(ERROR:\s*operator is not unique:)/
        ]
      end

      def run(object, params)
        params = @defaults.merge(params)

        @poison.each do |poison|
          resp = object.http(value: poison, timeout: params[:timeout], open_timeout: params[:open_timeout])
          next if resp.nil?
          next if resp.body.nil?
          body = resp.body.normalize_enconding
          @errors.each do |r|
            next unless r =~ body
            data = body.scan(r)
            data = data.flatten.join(' ... ')
            add_vuln(object, poison, "...\n" + data + "\n...")
            return
          end
        end
      end

      def add_vuln(object, value, data)
        curl = object.curl_helper(value: value, resp: data)
        object.vuln(
          extension: 'error_sqli',
          template: '/sqli/general',
          binding: :protocol,
          args: {
            exploit_example: curl
          }
        )
      end
    end
  end
end
