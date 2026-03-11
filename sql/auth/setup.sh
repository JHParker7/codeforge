psql -c 'CREATE DATABASE codeforge'

psql -d 'codeforge' -f docker-entrypoint-initdb.d/setup.sql_script
