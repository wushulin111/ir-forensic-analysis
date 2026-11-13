"""冒烟测试：验证派生解析注册表、14 维输出与旧布局兼容。

用标准库构造一个最小取证包，不依赖真实的 EVTX/Prefetch 样本。
运行：python -m unittest discover -s tests -v
"""

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"
sys.path.insert(0, str(SCRIPTS))

import parsers_registry  # noqa: E402


def build_package(base: Path) -> Path:
    ext = base / "IR_DEMO"
    (ext / "1_volatile").mkdir(parents=True)
    (ext / "3_persistence" / "tasks_xml").mkdir(parents=True)
    (ext / "browser_artifacts").mkdir(parents=True)

    (ext / "1_volatile" / "tasklist.csv").write_text(
        "ImageName,PID,Path\nsvch0st.exe,4568,C:\\Users\\Public\\svch0st.exe\n",
        encoding="utf-8")
    (ext / "1_volatile" / "netstat_anob.txt").write_text(
        "  TCP    10.0.0.8:5000   104.143.42.1:443   ESTABLISHED   4568\n",
        encoding="utf-8")
    (ext / "1_volatile" / "hosts.txt").write_text(
        "# comment\n127.0.0.1 localhost\n45.9.148.3 www.microsoft.com\n", encoding="utf-8")

    task_xml = """<?xml version="1.0" encoding="UTF-16"?>
<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><URI>\\EvilTask</URI></RegistrationInfo>
  <Actions><Exec><Command>powershell.exe</Command>
    <Arguments>-enc aQBlAHgA</Arguments></Exec></Actions>
  <Principals><Principal><UserId>TEST\\user</UserId></Principal></Principals>
</Task>"""
    (ext / "3_persistence" / "tasks_xml" / "EvilTask").write_bytes(task_xml.encode("utf-16"))

    history = ext / "browser_artifacts" / "tester_Chrome_Default_history.db"
    conn = sqlite3.connect(str(history))
    conn.executescript("""
        CREATE TABLE urls (id INTEGER PRIMARY KEY, url TEXT, title TEXT,
                           visit_count INTEGER, last_visit_time INTEGER);
        CREATE TABLE visits (id INTEGER PRIMARY KEY, url INTEGER, visit_time INTEGER);
        CREATE TABLE downloads (id INTEGER PRIMARY KEY, target_path TEXT, tab_url TEXT,
                                total_bytes INTEGER, state INTEGER, danger_type INTEGER,
                                start_time INTEGER);
    """)
    conn.execute("INSERT INTO urls VALUES (1, 'http://evil.example.com/a', 'x', 3, 13300000000000000)")
    conn.execute("INSERT INTO downloads VALUES (1, 'C:\\Users\\Public\\a.exe', "
                 "'http://evil.example.com/a.exe', 1024, 1, 1, 13300000000000000)")
    conn.commit()
    conn.close()
    return ext


class RegistryTest(unittest.TestCase):
    def test_list_and_deps(self):
        self.assertGreaterEqual(len(parsers_registry.PARSERS), 11)
        names = {p["name"] for p in parsers_registry.PARSERS}
        for expected in ("browser", "artifacts", "config", "accounts",
                         "persistence_exports", "filesystem", "srum",
                         "evtx", "prefetch", "jumplist", "amcache"):
            self.assertIn(expected, names)

    def test_empty_dir_no_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            manifest = parsers_registry.ensure(Path(tmp), quiet=True)
            for name, info in manifest["parsers"].items():
                self.assertEqual(info["status"], "no_input", f"{name} 应为 no_input")
            self.assertTrue((Path(tmp) / "_derived" / "manifest.json").is_file())

    def test_resolve_dir_legacy_fallback(self):
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            (base / "_evtx").mkdir()
            self.assertEqual(parsers_registry.resolve_dir(base, "evtx"), base / "_evtx")
            (base / "_derived" / "evtx").mkdir(parents=True)
            self.assertEqual(parsers_registry.resolve_dir(base, "evtx"),
                             base / "_derived" / "evtx")


class PipelineTest(unittest.TestCase):
    def test_parsers_run_on_synthetic_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            ext = build_package(Path(tmp))
            manifest = parsers_registry.ensure(ext, quiet=True)
            self.assertEqual(manifest["parsers"]["browser"]["status"], "ok")
            self.assertEqual(manifest["parsers"]["artifacts"]["status"], "ok")
            # 没有 evtx / pf，应是 no_input 而不是报错
            self.assertEqual(manifest["parsers"]["config"]["status"], "ok")
            self.assertEqual(manifest["parsers"]["evtx"]["status"], "no_input")
            self.assertEqual(manifest["parsers"]["prefetch"]["status"], "no_input")
            self.assertTrue((ext / "_derived" / "browser" / "browser_history.csv").is_file())
            self.assertTrue((ext / "_derived" / "artifacts" / "scheduled_tasks.csv").is_file())

    def test_full_analysis_dimensions(self):
        with tempfile.TemporaryDirectory() as tmp:
            ext = build_package(Path(tmp))
            out = Path(tmp) / "report"
            proc = subprocess.run(
                [sys.executable, str(SCRIPTS / "analyze_forensics.py"), str(ext),
                 "-r", str(ROOT / "rules"), "-o", str(out)],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=600)
            summary_path = out / "report_summary.json"
            self.assertTrue(summary_path.is_file(), proc.stderr[-800:])
            data = json.loads(summary_path.read_text(encoding="utf-8"))
            self.assertEqual(data["schema"], "ir-forensic-analysis-report-v2")
            dims = data["coverage"]["dimensions_complete"]
            self.assertGreaterEqual(len(set(dims)), 14, dims)
            self.assertIn("evtx", dims)
            self.assertIn("browser", dims)
            self.assertIn("artifact", dims)
            # 任务/浏览器应产生发现
            kinds = {f["dimension"] for f in data["findings"]}
            self.assertTrue(kinds & {"artifact", "browser"}, kinds)


if __name__ == "__main__":
    unittest.main()
