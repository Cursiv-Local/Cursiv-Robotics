"""End-to-end demonstration (docs/ROBOTICS_SIMULATION_GUIDE.md).

    python -m cursiv_sim.demo [--steps 30] [--out runs/demo]

 1 start the headless evidence service       7 introduce a controlled integrity failure
 2 launch three simulated robots             8 detect it
 3 run a survey mission                      9 simulate lost communications (and a dropped transfer)
 4 collect observations                     10 reconnect and synchronize
 5 generate an evidence package             11 derived results and evidence-linked findings
 6 verify it independently                  12 final scientific evidence report
Everything produced is SYNTHETIC.
"""
from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path

from .identity import body_json, with_body
from .lab import Lab
from .robot import RobotAgent
from .rovers import ROVERS
from .world import Site


def say(n, text):
    print(f"\n[{n:>2}] {text}", flush=True)


def verdicts(report: dict) -> str:
    v = report["verification"]["verdicts"]
    return ", ".join(f"{k}={v[k].split(':')[0]}" for k in ("structure", "integrity", "authenticity", "completeness", "attachments"))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--steps", type=int, default=30)
    ap.add_argument("--out", default="runs/demo")
    a = ap.parse_args(argv)
    out = Path(a.out)
    if out.exists():
        shutil.rmtree(out)
    lab = Lab(out, list(ROVERS) + ["analyst-01", "ai-assist-01"])
    lab.enrol()
    summary = {"synthetic": True, "steps": {}}

    say(1, "Starting the headless evidence service (loopback only)")
    lab.start()
    print("     ", lab.client.get("/v1/health")[1])

    say(2, "Launching three simulated robots, each with its own Ed25519 identity")
    site = Site(seed=7)
    rovers = {rid: cls(RobotAgent(rid, lab.robot_state, lab.client, mission_id="willow-basin-survey"), site) for rid, cls in ROVERS.items()}
    for rid, r in rovers.items():
        print(f"      {rid}: {r.role:<26} key {r.agent.identity.key_id}")

    say(3, f"Running survey mission 'willow-basin-survey' ({a.steps} steps per robot)")
    half = a.steps // 2
    t0 = time.perf_counter()
    for i in range(half):
        for r in rovers.values():
            r.step(i, a.steps)
        if i % 5 == 4:
            for r in rovers.values():
                r.agent.sync()
    for r in rovers.values():
        r.agent.sync()
    say(4, "Observations collected")
    status = lab.client.get("/v1/status")[1]
    for rid, s in status["robots"].items():
        print(f"      {rid}: {s['records']} records")
    summary["steps"]["mission_part_1_s"] = round(time.perf_counter() - t0, 3)

    say(5, "Generating evidence package 'survey-part-1'")
    pkg1 = lab.export("survey-part-1")
    print("     ", pkg1)

    say(6, "Verifying it with the independent verifier (cursiv-verify; no service, no AI)")
    code, rep = lab.verify(pkg1)
    print("      exit", code, "|", verdicts(rep))
    summary["clean_package"] = {"exit": code, "verdicts": rep["verification"]["verdicts"]}

    say(7, "Introducing a controlled integrity failure: rover-02's air temperature at record 4 is edited in a copy")
    bad = lab.copy_package(pkg1, "survey-part-1-altered")
    from cursiv_integration.layout import record_files
    f = record_files(bad, "rover-02")[0]
    lines = f.read_text().splitlines()
    env = json.loads(lines[3])
    rec = body_json(env)
    old = rec["observation"]["measurement"]["value"]
    rec["observation"]["measurement"]["value"] = round(old + 2.5, 3)
    env = with_body(env, rec)          # keep the robot's signature: an in-place forgery
    lines[3] = json.dumps(env)
    f.write_text("\n".join(lines) + "\n")
    print(f"      changed {old} -> {rec['observation']['measurement']['value']} degC")

    say(8, "Detecting it")
    code, rep = lab.verify(bad)
    errs = [x for x in rep["verification"]["findings"] if x["severity"] == "error"]
    print("      exit", code, "|", verdicts(rep))
    for e in errs[:4]:
        print(f"      - {e['area']}/{e['code']}: {e['message']}")
    summary["altered_package"] = {"exit": code, "verdicts": rep["verification"]["verdicts"], "errors": [e["code"] for e in errs]}

    say(9, "Simulating lost communications: rover-01 keeps surveying offline; its first reconnect drops mid-transfer")
    rovers["rover-01"].agent.link_up = False
    rovers["rover-03"].bias["air_temperature"] = 4.0   # a sensor fault, for the science check (not an integrity fault)
    for i in range(half, a.steps):
        for r in rovers.values():
            r.step(i, a.steps)
        for rid in ("rover-02", "rover-03"):
            rovers[rid].agent.sync()
    g = rovers["rover-01"].agent
    print(f"      rover-01 offline: {len(g.envelopes) - g.acked} records waiting in its local log")
    g.link_up = True
    r = g.sync(batch=10, fail_after=12)
    head = lab.client.get("/v1/robots/rover-01/head")[1]
    print(f"      transfer dropped: link {r['link']}; bridge has {head['count']} of {len(g.envelopes)}")
    summary["partial_sync"] = {"bridge_count": head["count"], "robot_count": len(g.envelopes)}

    say(10, "Reconnecting and synchronizing (resumes from the bridge's head; repeats are idempotent)")
    g.link_up = True
    r = g.sync()
    head = lab.client.get("/v1/robots/rover-01/head")[1]
    print(f"      sent {r['sent']}; bridge has {head['count']} of {len(g.envelopes)}; checkpoint sent")
    summary["resync"] = {"sent": r["sent"], "bridge_count": head["count"], "robot_count": len(g.envelopes)}

    say(11, "Derived results and findings, each citing the signed observations they rest on")
    r2, r3 = rovers["rover-02"].agent, rovers["rover-03"].agent
    temps = lambda g: [e for e in g.envelopes if body_json(e)["observation"]["observation_type"] == "air_temperature"]
    t2, t3 = temps(r2), temps(r3)
    mean2 = r2.derive("mean", t2[half:])                     # computed on board, re-computed by the verifier
    mean3 = r3.derive("mean", t3[half:])
    kelvin = r2.derive("convert", [mean2], params={"to": "K"}, observation_type="air_temperature_mean")
    for g in (r2, r3):
        g.sync()
    analyst = RobotAgent("analyst-01", lab.robot_state, lab.client, mission_id="willow-basin-survey")
    a = analyst.finding("During the second half of the survey rover-03's air temperature reads about 4 degC above "
                        "rover-02's co-located sensor; one of the two sensors is likely biased.",
                        epistemic="inferred", supports=[mean2, mean3], contradicts=[], assumptions=["the two sensors observed the same air mass"])
    ai = RobotAgent("ai-assist-01", lab.robot_state, lab.client, mission_id="willow-basin-survey")
    b = ai.finding("Rover-02's reading is more plausible because its sensor is a calibrated PT100.", epistemic="inferred",
                   author_kind="ai_model", model="example-local-model-1", supports=[mean2],
                   assumptions=["calibration metadata is accurate"])
    for g in (analyst, ai):
        g.sync()
    v = body_json(mean2)["observation"]["measurement"]["value"]
    print(f"      rover-02 mean {v:.3f} degC ({body_json(kelvin)['observation']['measurement']['value']:.3f} K); "
          f"rover-03 mean {body_json(mean3)['observation']['measurement']['value']:.3f} degC")
    print("      findings recorded: 1 by a human analyst, 1 by an AI model (labelled inferred, model named)")

    say(12, "Final evidence package and report")
    pkg2 = lab.export("survey-final")
    report_md = out / "evidence-report.md"
    code, rep = lab.verify(pkg2, report_md=report_md)
    print("      exit", code, "|", verdicts(rep))
    sci = rep["science"]["counts"]
    print("      science flags (separate from integrity):", {k: sci[k] for k in sorted(sci) if k in ("contradiction", "out_of_range", "clock_drift", "out_of_order_time")})
    print("      report:", report_md)
    summary["final_package"] = {"exit": code, "verdicts": rep["verification"]["verdicts"], "science_counts": sci,
                                "records": {k: v["records"] for k, v in rep["verification"]["robots"].items()}}
    lab.stop()
    (out / "demo-summary.json").write_text(json.dumps(summary, indent=2))
    rsn = rep["reasoning"]
    print("      derived results recomputed:", rsn["derivations"])
    for f in rsn["findings"]:
        print(f"      finding by {f['author']} ({f['author_kind']}): {f['epistemic']}, {f['status']}")
    summary["reasoning"] = {"derivations": rsn["derivations"], "findings": [{k: f[k] for k in ("author", "author_kind", "epistemic", "status")} for f in rsn["findings"]]}
    ok = (summary["clean_package"]["exit"] == 0 and summary["altered_package"]["exit"] == 1
          and summary["final_package"]["exit"] == 0 and sci.get("contradiction", 0) > 0
          and rsn["derivations"]["verified"] == 3 and len(rsn["findings"]) == 2)
    print("\nDemo", "PASSED" if ok else "FAILED", "- all data above is SYNTHETIC.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
