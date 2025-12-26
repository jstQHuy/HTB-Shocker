import sys
import os
import json
import logging
import subprocess
import re
import shutil
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timezone

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils.merge_scores import merge
from utils.version_limit import get_affected_cve
from utils.model_manager import model_manager
from utils.config_loader import load_config, get_runtime_section

logger = logging.getLogger(__name__)

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_PATH = os.path.join(PROJECT_ROOT, "configs", "config.yaml")

config = load_config(CONFIG_PATH)
planning_config = get_runtime_section(config, "planning")
if not planning_config:
    raise KeyError("Missing runtime.planning in configs/config.yaml")

cvemap_config = planning_config.get("cvemap", {})
if not isinstance(cvemap_config, dict):
    cvemap_config = {}

ECONOMIC_MODE = bool(planning_config.get("economic_mode", False))
if ECONOMIC_MODE:
    from utils.cve_info_ec import get_exp_info
else:
    from utils.cve_info import get_exp_info


def _safe_abs(base: str, p: str) -> str:
    if not p:
        return os.path.abspath(base)
    if os.path.isabs(p):
        return os.path.abspath(p)
    return os.path.abspath(os.path.join(base, p))


def _ensure_writable_dir(path: str, fallback_under_repo: str = "data/exp_info") -> str:
    """Ensure output directory is writable; fallback into repo if not."""
    try:
        os.makedirs(path, exist_ok=True)
        testfile = os.path.join(path, ".write_test")
        with open(testfile, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(testfile)
        return path
    except Exception:
        fb = _safe_abs(PROJECT_ROOT, fallback_under_repo)
        os.makedirs(fb, exist_ok=True)
        return fb


def _find_cvemap_bin() -> Optional[str]:
    p = shutil.which("cvemap")
    if p:
        return p
    home = os.path.expanduser("~")
    p2 = os.path.join(home, "go", "bin", "cvemap")
    if os.path.exists(p2) and os.access(p2, os.X_OK):
        return p2
    return None


def _slugify(text: str, default: str = "Unknown") -> str:
    s = (text or "").strip()
    s = re.sub(r"[^a-zA-Z0-9_.-]+", "-", s)
    s = s.strip("-._")
    return s or default


def _load_recon_artifact(topic: str, memory_dir: str) -> Optional[Dict[str, Any]]:
    if not topic or not memory_dir:
        return None
    if not os.path.isabs(memory_dir):
        memory_dir = os.path.join(PROJECT_ROOT, memory_dir)
    # Support both raw topic and slug topic
    candidates = [
        os.path.join(memory_dir, f"{topic}_artifact.json"),
        os.path.join(memory_dir, f"{_slugify(topic)}_artifact.json"),
    ]
    for p in candidates:
        if not os.path.exists(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return None
    return None


def _extract_cves_from_keywords(items: List[str]) -> List[str]:
    out: List[str] = []
    if not items:
        return out
    pat = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
    for s in items:
        if not s:
            continue
        for m in pat.findall(str(s)):
            cid = m.upper()
            if cid not in out:
                out.append(cid)
    return out


def _infer_from_artifact(artifact: Dict[str, Any]) -> Tuple[str, str, str, List[str], List[str]]:
    """Return (app, version, keyword, planning_keywords, seed_cves)."""
    app = ""
    version = ""
    keyword = ""
    planning_keywords: List[str] = []
    seed_cves: List[str] = []

    final = artifact.get("final_ai_message_json") or {}
    analysis = (final.get("analysis") or {}) if isinstance(final, dict) else {}

    # New schema: analysis.planning.{...}
    planning = analysis.get("planning") if isinstance(analysis, dict) else None
    if isinstance(planning, dict):
        keyword = str(planning.get("keyword") or "").strip()
        app = str(planning.get("app") or "").strip()
        version = str(planning.get("version") or "").strip()
        pk = planning.get("planning_keywords")
        if isinstance(pk, list):
            planning_keywords = [str(x) for x in pk if x]
        cids = planning.get("cve_ids")
        if isinstance(cids, list):
            seed_cves = [str(x).upper() for x in cids if x]

    # Backward compatibility: analysis.planning_keywords
    if not planning_keywords:
        pk2 = analysis.get("planning_keywords") if isinstance(analysis, dict) else None
        if isinstance(pk2, list):
            planning_keywords = [str(x) for x in pk2 if x]

    # Derive CVEs from planning keywords
    seed_from_pk = _extract_cves_from_keywords(planning_keywords)
    for cid in seed_from_pk:
        if cid not in seed_cves:
            seed_cves.append(cid)

    # Fallback to products list if planning.app missing
    if not app:
        products = analysis.get("products") if isinstance(analysis, dict) else None
        best = None
        if isinstance(products, list):
            for p in products:
                if not isinstance(p, dict):
                    continue
                conf = p.get("confidence")
                if not isinstance(conf, (int, float)):
                    conf = 0.0
                if best is None or conf > float(best.get("confidence") or 0.0):
                    best = p
        if isinstance(best, dict):
            app = (best.get("name") or "").strip()
            if not version:
                version = (best.get("version_candidate") or "").strip()

    if not keyword and app:
        keyword = app

    return app, version, keyword, planning_keywords, seed_cves


def cvemap_product(product: str, output_dir: str, cvemap_cfg: Dict) -> List[Dict]:
    os.makedirs(output_dir, exist_ok=True)
    cvemap_json_path = os.path.join(output_dir, "cvemap.json")

    lower_product = (product or "").lower().strip()
    if not lower_product:
        with open(cvemap_json_path, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2, ensure_ascii=False)
        return []

    cvemap_bin = _find_cvemap_bin()
    if not cvemap_bin:
        logger.warning("[CVEMAP] cvemap binary not found. Return empty list.")
        with open(cvemap_json_path, "w", encoding="utf-8") as f:
            json.dump([], f, indent=2, ensure_ascii=False)
        return []

    query_type = "-q" if cvemap_cfg.get("fuzzy_search", False) else "-p"
    all_results: List[Dict[str, Any]] = []
    limit = int(cvemap_cfg.get("page_limit", 50) or 50)
    offset = 0

    max_entry = cvemap_cfg.get("max_entry")
    min_year = cvemap_cfg.get("min_year")
    max_year = cvemap_cfg.get("max_year")

    while True:
        if max_entry and len(all_results) >= max_entry:
            break

        cmd = [cvemap_bin, query_type, lower_product, "-l", str(limit), "-offset", str(offset), "-j"]
        try:
            shell_result = subprocess.run(
                cmd,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=60,
            )
            try:
                batch = json.loads(shell_result.stdout)
            except json.JSONDecodeError:
                logger.warning("[CVEMAP] Failed to decode JSON. stderr=%s", shell_result.stderr[:500])
                break

            if not batch:
                break

            filtered: List[Dict[str, Any]] = []
            for item in batch:
                if not isinstance(item, dict):
                    continue
                cve_id = item.get("cve_id", "")
                if not cve_id or not isinstance(cve_id, str):
                    continue
                try:
                    year = int(cve_id.split("-")[1])
                except Exception:
                    continue
                if isinstance(max_year, int) and year > max_year:
                    continue
                if isinstance(min_year, int) and year < min_year:
                    continue
                filtered.append(item)
                if max_entry and (len(all_results) + len(filtered)) >= max_entry:
                    break

            all_results.extend(filtered)

            if len(batch) < limit:
                break
            if max_entry and len(all_results) >= max_entry:
                break
            offset += limit

        except subprocess.CalledProcessError as e:
            logger.warning(
                "[CVEMAP] cvemap failed (rc=%s). stderr=%s",
                getattr(e, "returncode", "?"),
                getattr(e, "stderr", "")[:500],
            )
            break
        except subprocess.TimeoutExpired:
            logger.warning("[CVEMAP] cvemap timed out.")
            break

    if max_entry:
        all_results = all_results[:max_entry]

    with open(cvemap_json_path, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2, ensure_ascii=False)

    return all_results


def main():
    logging.basicConfig(
        format="%(asctime)s %(levelname)-8s %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        filename="planning_agent.log",
        level=logging.INFO,
    )

    runtime = (config.get("runtime") or {})
    recon_cfg = (runtime.get("recon") or {})

    # Init model (keep existing behavior)
    model_name = planning_config.get("model", "openai")
    _ = model_manager.get_model(model_name)
    logger.info("Using model: %s", model_name)

    topic = (recon_cfg.get("current_topic") or planning_config.get("current_topic") or "default_topic").strip()
    memory_dir = (recon_cfg.get("memory_dir") or "recon_memory")

    keyword = (planning_config.get("keyword") or "").strip()
    app = (planning_config.get("app") or "").strip()
    version = (planning_config.get("version") or "").strip()
    vuln_type = (planning_config.get("vuln_type") or "").strip()

    output_dir_cfg = planning_config.get("output_dir", "data/exp_info")
    output_dir = _ensure_writable_dir(_safe_abs(PROJECT_ROOT, output_dir_cfg))

    safe_topic = _slugify(topic, default="default_topic")

    planning_keywords: List[str] = []
    seed_cves: List[str] = []

    artifact = _load_recon_artifact(topic=topic, memory_dir=memory_dir)
    if artifact:
        a_app, a_ver, a_kw, a_pks, a_seed = _infer_from_artifact(artifact)
        planning_keywords = a_pks or planning_keywords
        seed_cves = a_seed or seed_cves
        if not app and a_app:
            app = a_app
        if not version and a_ver:
            version = a_ver
        if not keyword and a_kw:
            keyword = a_kw

    product_name = (app or keyword or "Unknown").strip()
    safe_product = _slugify(product_name, default="Unknown")
    res_dir = os.path.join(output_dir, safe_product, safe_topic)
    os.makedirs(res_dir, exist_ok=True)

    if artifact:
        try:
            with open(os.path.join(res_dir, "recon_artifact.json"), "w", encoding="utf-8") as f:
                json.dump(artifact, f, indent=2, ensure_ascii=False)
        except Exception:
            pass

    logger.info("Planning input: product=%s keyword=%s version=%s topic=%s", product_name, keyword, version, topic)

    # -------------------------
    # Approach A: CVE-first.
    # - If recon gives us seed CVEs -> ONLY use them (no CVEMAP expansion, no noisy general search).
    # - If no seed CVEs -> use CVEMAP (+ optional version filter) to build CVE list.
    # -------------------------

    cve_lst: List[str] = []

    if seed_cves:
        # Deduplicate, preserve order
        for cid in seed_cves:
            if cid and cid not in cve_lst:
                cve_lst.append(cid)
        print("[A] Using seed CVEs from recon artifact (skip CVEMAP expansion):")
        print(cve_lst)
    else:
        cvemap_res_dir = os.path.join(res_dir, "CVEMAP")
        app_for_cvemap = (app or keyword or product_name).lower().replace(" ", "_")
        cvemap_res = cvemap_product(app_for_cvemap, cvemap_res_dir, cvemap_config)

        if version:
            print("Version constraint has been set; applying version filter (please double-check accuracy).")
            limited_lst = get_affected_cve(cvemap_res, version) or []
            cve_lst = [x.get("cve_id") for x in limited_lst if isinstance(x, dict) and x.get("cve_id")]
            if not cve_lst and cvemap_res:
                logger.warning("Version-filter returned 0 CVEs; falling back to unfiltered CVEs from CVEMAP.")
                cve_lst = [x.get("cve_id") for x in cvemap_res if isinstance(x, dict) and x.get("cve_id")]
        else:
            cve_lst = [x.get("cve_id") for x in cvemap_res if isinstance(x, dict) and x.get("cve_id")]

        print("The following CVEs will be searched:")
        print(cve_lst)

    # cap CVEs
    max_cves_to_search = int(planning_config.get("max_cves_to_search", 50) or 50)
    if max_cves_to_search > 0:
        cve_lst = cve_lst[:max_cves_to_search]

    # Control general search behavior:
    # - If we have any CVEs -> disable general keyword search completely (most stable for HTB/CTF).
    # - If no CVEs -> allow a *constrained* general query by app+version.
    app_for_expinfo = ""
    if not cve_lst:
        base = (app or keyword or product_name).strip()
        app_for_expinfo = f"{base} {version}".strip() if version else base

    times = get_exp_info(cve_lst, res_dir, app_for_expinfo)

    if not times or not isinstance(times, (list, tuple)) or len(times) != 2:
        exploit_searching_time, exploit_analysis_time = 0.0, 0.0
    else:
        exploit_searching_time, exploit_analysis_time = times

    plan_filename = "plan_ec.json" if ECONOMIC_MODE else "plan.json"
    merge(res_dir, os.path.join(res_dir, plan_filename), ECONOMIC_MODE)

    thread_root = os.path.join(PROJECT_ROOT, "data", "threads")
    os.makedirs(thread_root, exist_ok=True)
    thread_dir = os.path.join(thread_root, safe_topic)
    os.makedirs(thread_dir, exist_ok=True)

    src = os.path.join(res_dir, plan_filename)
    dst = os.path.join(thread_dir, plan_filename)
    with open(src, "rb") as rf, open(dst, "wb") as wf:
        wf.write(rf.read())

    meta = {
        "topic": topic,
        "safe_topic": safe_topic,
        "product": product_name,
        "keyword": keyword,
        "app": app,
        "version": version,
        "vuln_type": vuln_type,
        "planning_keywords": planning_keywords,
        "seed_cves": seed_cves,
        "final_cves": cve_lst,
        "source_plan_path": os.path.relpath(src, PROJECT_ROOT),
        "copied_to": os.path.relpath(dst, PROJECT_ROOT),
        "captured_at": datetime.now(timezone.utc).isoformat(),
    }
    with open(os.path.join(thread_dir, "planning_meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)

    print(f"Successfully saved results to {src}")
    print(f"Copied canonical plan to {dst}")
    if planning_keywords:
        print(f"Keywords used (from recon artifact): {planning_keywords}")
    print(f"Exploit searching time is {exploit_searching_time:.6f} seconds")
    print(f"Exploit analysis time is {exploit_analysis_time:.6f} seconds")
    print(f"Total exploit time is {(exploit_searching_time + exploit_analysis_time):.6f} seconds")


if __name__ == "__main__":
    main()


