import json
import os
import time
try:
    from dataclasses import dataclass
except Exception:
    try:
        from ..symex.compat_dataclasses import dataclass
    except Exception:
        from symex.compat_dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional


@dataclass(frozen=True)
class DBQueryConfig:
    engine: str = "mysql"
    host: str = "127.0.0.1"
    port: int = 3306
    database: str = ""
    username: str = "root"
    password: str = ""
    connect_timeout_sec: int = 3
    query_timeout_sec: int = 5
    max_rows: int = 50


@dataclass(frozen=True)
class DBBackupState:
    enabled: bool
    config_path: str
    record_path: str
    source_database: str
    backup_database: str


def _as_int(v: Any, d: int) -> int:
    try:
        return int(v) if v is not None else int(d)
    except Exception:
        return int(d)


def load_db_query_config_from_raw(raw_cfg: Dict[str, Any]) -> DBQueryConfig:
    raw = raw_cfg if isinstance(raw_cfg, dict) else {}
    sec = raw.get("symbolic_db")
    if not isinstance(sec, dict):
        sec = {}
    engine = str(sec.get("engine") or "mysql").strip().lower() or "mysql"
    return DBQueryConfig(
        engine=engine,
        host=str(sec.get("host") or "127.0.0.1").strip() or "127.0.0.1",
        port=max(1, _as_int(sec.get("port"), 3306)),
        database=str(sec.get("database") or "").strip(),
        username=str(sec.get("username") or "root").strip() or "root",
        password=str(sec.get("password") or ""),
        connect_timeout_sec=max(1, _as_int(sec.get("connect_timeout_sec"), 3)),
        query_timeout_sec=max(1, _as_int(sec.get("query_timeout_sec"), 5)),
        max_rows=max(1, _as_int(sec.get("max_rows"), 50)),
    )


class DBBackupManager:
    def __init__(self, *, config_path: str, work_dir: str, logger=None, enabled: bool = True):
        self.config_path = os.path.realpath(config_path)
        self.config_dir = os.path.dirname(self.config_path)
        self.symex_config_path = os.path.join(self.config_dir, "symex_config.json")
        self.work_dir = os.path.realpath(work_dir)
        self.record_path = os.path.join(self.config_dir, "symex_db_backup_record.json")
        self.log_path = os.path.join(self.work_dir, "db_backup.log")
        self._logger = logger
        self._feature_enabled = bool(enabled)
        self._cfg = self._load_db_config()
        self.state = self._load_or_create_state()

    def _emit(self, level: str, message: str) -> None:
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [{level}] {message}"
        try:
            os.makedirs(self.work_dir, exist_ok=True)
            with open(self.log_path, "a", encoding="utf-8", errors="replace") as wf:
                wf.write(line + "\n")
        except Exception:
            pass
        try:
            if callable(self._logger):
                self._logger(line)
        except Exception:
            pass

    def _load_db_config_from_file(self, path: str) -> DBQueryConfig:
        self._emit("INFO", f"开始读取数据库配置: {path}")
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as rf:
                raw = json.load(rf)
        except FileNotFoundError:
            self._emit("WARN", f"配置文件不存在: {path}")
            return DBQueryConfig(database="")
        except Exception as ex:
            self._emit("ERROR", f"读取数据库配置失败: {path}: {ex}")
            raise

        if not isinstance(raw, dict):
            self._emit("WARN", f"配置文件根节点不是对象，实际类型={type(raw).__name__}")
            return DBQueryConfig(database="")

        if "symbolic_db" not in raw:
            self._emit("INFO", f"配置文件中不存在 symbolic_db 字段: {path}")
            return DBQueryConfig(database="")

        sec = raw.get("symbolic_db")
        if not isinstance(sec, dict):
            self._emit("WARN", f"symbolic_db 不是对象，实际类型={type(sec).__name__}")
            return DBQueryConfig(database="")

        cfg = load_db_query_config_from_raw(raw)
        self._emit(
            "INFO",
            "已解析 symbolic_db: "
            f"engine={cfg.engine}, host={cfg.host}, port={cfg.port}, "
            f"database={cfg.database or '<empty>'}, username={cfg.username}, "
            f"connect_timeout_sec={cfg.connect_timeout_sec}, query_timeout_sec={cfg.query_timeout_sec}, max_rows={cfg.max_rows}",
        )
        if not str(cfg.database or "").strip():
            self._emit("WARN", "symbolic_db 已存在，但 database 为空")
        return cfg

    def _load_db_config(self) -> DBQueryConfig:
        cfg = self._load_db_config_from_file(self.symex_config_path)
        if str(cfg.database or "").strip() or str(cfg.engine or "").strip().lower() != "mysql":
            return cfg
        self._emit("INFO", f"将回退检查 witcher_config.json: {self.config_path}")
        return self._load_db_config_from_file(self.config_path)

    def _load_record(self) -> Dict[str, Any]:
        try:
            with open(self.record_path, "r", encoding="utf-8", errors="replace") as rf:
                obj = json.load(rf)
                if isinstance(obj, dict):
                    return obj
        except FileNotFoundError:
            return {}
        except Exception as ex:
            self._emit("ERROR", f"读取数据库备份记录失败: {self.record_path}: {ex}")
        return {}

    def _write_record(self, backup_database: str) -> None:
        payload = {
            "engine": self._cfg.engine,
            "host": self._cfg.host,
            "port": int(self._cfg.port),
            "source_database": self._cfg.database,
            "backup_database": backup_database,
            "updated_at": int(time.time()),
        }
        with open(self.record_path, "w", encoding="utf-8") as wf:
            json.dump(payload, wf, ensure_ascii=False, indent=2)
            wf.write("\n")

    def _load_or_create_state(self) -> DBBackupState:
        db_name = str(self._cfg.database or "").strip()
        if not self._feature_enabled:
            self._emit("INFO", "witcher_db_backup_enabled=false，跳过数据库备份/恢复")
            return DBBackupState(
                enabled=False,
                config_path=self.config_path,
                record_path=self.record_path,
                source_database=db_name,
                backup_database="",
            )
        engine = str(self._cfg.engine or "").strip().lower()
        if engine != "mysql":
            self._emit("INFO", f"symbolic_db.engine={self._cfg.engine!r}，当前仅支持 mysql，跳过数据库备份/恢复")
            return DBBackupState(
                enabled=False,
                config_path=self.config_path,
                record_path=self.record_path,
                source_database=db_name,
                backup_database="",
            )
        if not db_name:
            self._emit("INFO", "symbolic_db 已解析，但 database 为空，跳过数据库备份/恢复")
            return DBBackupState(
                enabled=False,
                config_path=self.config_path,
                record_path=self.record_path,
                source_database=db_name,
                backup_database="",
            )

        record = self._load_record()
        backup_name = str(record.get("backup_database") or "").strip()
        if backup_name:
            try:
                if self.database_exists(backup_name):
                    self._emit("INFO", f"复用现有备份库: {backup_name}")
                    return DBBackupState(
                        enabled=True,
                        config_path=self.config_path,
                        record_path=self.record_path,
                        source_database=db_name,
                        backup_database=backup_name,
                    )
                self._emit("WARN", f"备份记录存在，但备份库不存在: {backup_name}，将重新备份")
            except Exception as ex:
                self._emit("WARN", f"检查备份库是否存在失败: {backup_name}: {ex}，将重新备份")

        if backup_name:
            self._emit("WARN", f"备份记录存在，但无法复用: {backup_name}，将重新备份")
        else:
            self._emit("INFO", "未找到可复用的数据库备份记录，将创建新备份")

        backup_name = self._create_backup_database_name(db_name)
        self._clone_database(source_database=db_name, backup_database=backup_name)
        self._write_record(backup_name)
        self._emit("INFO", f"已创建数据库备份: {db_name} -> {backup_name}")
        return DBBackupState(
            enabled=True,
            config_path=self.config_path,
            record_path=self.record_path,
            source_database=db_name,
            backup_database=backup_name,
        )

    def _create_backup_database_name(self, db_name: str) -> str:
        suffix = datetime.now().strftime("%Y%m%d_%H%M%S")
        return f"{db_name}_{suffix}"

    def _connect(self, database: Optional[str] = None):
        try:
            import pymysql  # type: ignore
        except Exception as ex:
            raise RuntimeError("pymysql_not_installed") from ex
        return pymysql.connect(
            host=self._cfg.host,
            port=int(self._cfg.port),
            user=self._cfg.username,
            password=self._cfg.password,
            database=database if database else None,
            connect_timeout=int(self._cfg.connect_timeout_sec),
            read_timeout=max(int(self._cfg.query_timeout_sec), 30),
            write_timeout=max(int(self._cfg.query_timeout_sec), 30),
            charset="utf8mb4",
            autocommit=True,
        )

    @staticmethod
    def _quote_ident(name: str) -> str:
        return "`" + str(name).replace("`", "``") + "`"

    def database_exists(self, db_name: str) -> bool:
        conn = None
        try:
            conn = self._connect(None)
            with conn.cursor() as cur:
                cur.execute("SHOW DATABASES LIKE %s", (db_name,))
                return cur.fetchone() is not None
        finally:
            if conn is not None:
                conn.close()

    def _list_base_tables(self, conn) -> list:
        with conn.cursor() as cur:
            cur.execute("SHOW FULL TABLES WHERE Table_type = 'BASE TABLE'")
            rows = cur.fetchall() or []
        return [str(row[0]) for row in rows if row and row[0]]

    def _list_views(self, conn) -> list:
        with conn.cursor() as cur:
            cur.execute("SHOW FULL TABLES WHERE Table_type = 'VIEW'")
            rows = cur.fetchall() or []
        return [str(row[0]) for row in rows if row and row[0]]

    def _drop_all_views(self, conn) -> None:
        views = self._list_views(conn)
        if not views:
            return
        with conn.cursor() as cur:
            for view in views:
                cur.execute(f"DROP VIEW IF EXISTS {self._quote_ident(view)}")

    def _drop_all_base_tables(self, conn) -> None:
        tables = self._list_base_tables(conn)
        if not tables:
            return
        with conn.cursor() as cur:
            cur.execute("SET FOREIGN_KEY_CHECKS=0")
            try:
                for table in tables:
                    cur.execute(f"DROP TABLE IF EXISTS {self._quote_ident(table)}")
            finally:
                cur.execute("SET FOREIGN_KEY_CHECKS=1")

    def _reset_database_contents(self, database: str) -> None:
        conn = self._connect(database)
        try:
            self._drop_all_views(conn)
            self._drop_all_base_tables(conn)
        finally:
            conn.close()

    def _clone_base_tables(self, source_db: str, target_db: str) -> None:
        src_conn = self._connect(source_db)
        try:
            tables = self._list_base_tables(src_conn)
            with src_conn.cursor() as src_cur:
                dst_conn = self._connect(target_db)
                try:
                    with dst_conn.cursor() as dst_cur:
                        dst_cur.execute("SET FOREIGN_KEY_CHECKS=0")
                        try:
                            for table in tables:
                                src_cur.execute(f"SHOW CREATE TABLE {self._quote_ident(table)}")
                                row = src_cur.fetchone()
                                if not row:
                                    continue
                                dst_cur.execute(str(row[1]))
                                dst_cur.execute(
                                    f"INSERT INTO {self._quote_ident(table)} SELECT * FROM {self._quote_ident(source_db)}.{self._quote_ident(table)}"
                                )
                        finally:
                            dst_cur.execute("SET FOREIGN_KEY_CHECKS=1")
                finally:
                    dst_conn.close()
        finally:
            src_conn.close()

    def _clone_views(self, source_db: str, target_db: str) -> None:
        src_conn = self._connect(source_db)
        try:
            views = self._list_views(src_conn)
            with src_conn.cursor() as src_cur:
                dst_conn = self._connect(target_db)
                try:
                    with dst_conn.cursor() as dst_cur:
                        for view in views:
                            src_cur.execute(f"SHOW CREATE VIEW {self._quote_ident(view)}")
                            row = src_cur.fetchone()
                            if not row:
                                continue
                            create_sql = str(row[1])
                            create_sql = create_sql.replace(
                                f"VIEW `{view}` AS",
                                f"VIEW {self._quote_ident(view)} AS",
                                1,
                            )
                            dst_cur.execute(create_sql)
                finally:
                    dst_conn.close()
        finally:
            src_conn.close()

    def _clone_database(self, *, source_database: str, backup_database: str) -> None:
        admin_conn = self._connect(None)
        try:
            with admin_conn.cursor() as cur:
                cur.execute(f"CREATE DATABASE {self._quote_ident(backup_database)}")
        finally:
            admin_conn.close()
        try:
            self._clone_base_tables(source_database, backup_database)
            self._clone_views(source_database, backup_database)
        except Exception:
            try:
                self.drop_database(backup_database)
            except Exception:
                pass
            raise

    def restore_from_backup(self) -> None:
        if not self.state.enabled:
            return
        try:
            self._restore_from_backup_impl()
        except Exception as ex:
            self._emit("ERROR", f"数据库恢复失败，已跳过本次恢复: {ex}")

    def _restore_from_backup_impl(self) -> None:
        backup_db = self.state.backup_database
        source_db = self.state.source_database
        if not self.database_exists(backup_db):
            self._emit("WARN", f"备份库不存在，重新创建备份: {backup_db}")
            backup_db = self._create_backup_database_name(source_db)
            self._clone_database(source_database=source_db, backup_database=backup_db)
            self._write_record(backup_db)
            self.state = DBBackupState(
                enabled=True,
                config_path=self.config_path,
                record_path=self.record_path,
                source_database=source_db,
                backup_database=backup_db,
            )
        self._reset_database_contents(source_db)
        self._clone_base_tables(backup_db, source_db)
        self._clone_views(backup_db, source_db)
        self._emit("INFO", f"已从备份恢复数据库: {backup_db} -> {source_db}")

    def cleanup_backup(self) -> None:
        if not self.state.enabled:
            return
        backup_db = self.state.backup_database
        try:
            self._restore_from_backup_impl()
        except Exception as ex:
            self._emit("ERROR", f"数据库恢复失败，继续执行清理: {ex}")
        try:
            self.drop_database(backup_db)
        except Exception as ex:
            self._emit("ERROR", f"删除备份数据库失败: {backup_db}: {ex}")
        try:
            if os.path.isfile(self.record_path):
                os.remove(self.record_path)
        except Exception as ex:
            self._emit("WARN", f"删除备份记录失败: {self.record_path}: {ex}")
        self._emit("INFO", f"已删除备份数据库: {backup_db}")

    def cleanup_on_interrupt(self) -> None:
        if not self.state.enabled:
            return
        try:
            self._restore_from_backup_impl()
        except Exception as ex:
            self._emit("ERROR", f"中断时数据库恢复失败，继续执行清理: {ex}")
        try:
            self.drop_database(self.state.backup_database)
        except Exception as ex:
            self._emit("ERROR", f"中断时删除备份数据库失败: {self.state.backup_database}: {ex}")
        try:
            if os.path.isfile(self.record_path):
                os.remove(self.record_path)
        except Exception as ex:
            self._emit("WARN", f"删除备份记录失败: {self.record_path}: {ex}")
        self._emit("INFO", f"已在中断时恢复并删除备份数据库: {self.state.backup_database}")

    def drop_database(self, db_name: str) -> None:
        conn = self._connect(None)
        try:
            with conn.cursor() as cur:
                cur.execute(f"DROP DATABASE IF EXISTS {self._quote_ident(db_name)}")
        finally:
            conn.close()
