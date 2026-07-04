import pytest
import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from modules.sqli_engine import _detect_db_errors

def test_detect_mysql_errors():
    text = "You have an error in your SQL syntax near 'foo'"
    matches = _detect_db_errors(text)
    assert len(matches) > 0
    assert any(db == "MySQL" for db, _ in matches)

def test_detect_postgresql_errors():
    text = "PostgreSQL ERROR: syntax error"
    matches = _detect_db_errors(text)
    assert len(matches) > 0
    assert any(db == "PostgreSQL" for db, _ in matches)

def test_detect_mssql_errors():
    text = "Microsoft SQL Native Client error '80040e14'"
    matches = _detect_db_errors(text)
    assert len(matches) > 0
    assert any(db == "MSSQL" for db, _ in matches)

def test_detect_oracle_errors():
    text = "ORA-01756: quoted string not properly terminated"
    matches = _detect_db_errors(text)
    assert len(matches) > 0
    assert any(db == "Oracle" for db, _ in matches)

def test_detect_sqlite_errors():
    text = "System.Data.SQLite.SQLiteException: unrecognized token"
    matches = _detect_db_errors(text)
    assert len(matches) > 0
    assert any(db == "SQLite" for db, _ in matches)

def test_detect_generic_errors():
    text = "UnhandledException: SQL logic error"
    matches = _detect_db_errors(text)
    assert len(matches) > 0
    assert any(db == "Generic" for db, _ in matches)

def test_multiple_errors():
    text = "Warning: mysql_query() and also PostgreSQL ERROR occurred"
    matches = _detect_db_errors(text)
    assert len(matches) >= 2
    dbs = [db for db, _ in matches]
    assert "MySQL" in dbs
    assert "PostgreSQL" in dbs

def test_no_errors():
    text = "<html><body>Welcome to the application. Everything is working fine.</body></html>"
    matches = _detect_db_errors(text)
    assert len(matches) == 0

def test_empty_string():
    matches = _detect_db_errors("")
    assert len(matches) == 0

def test_case_insensitivity():
    text = "you have an error in your sql syntax"
    matches = _detect_db_errors(text)
    assert len(matches) > 0
    assert any(db == "MySQL" for db, _ in matches)

def test_large_string_no_errors():
    text = "A" * 100000
    matches = _detect_db_errors(text)
    assert len(matches) == 0
