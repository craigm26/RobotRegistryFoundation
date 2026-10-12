# Lab guide: running EV-03 and EV-10 with the reference kit

This guide walks a lab through one session with the reference implementation: set up an external
instrument, check its accuracy, run EV-03 (and EV-10), and submit signed reports. The method text
(`method/bounded-embodiment-method-v0.1.md`) is normative; this guide is not. Where they differ, the
method wins.

**Status.** Method v0.1 is a draft for comment and its thresholds are illustrative. A verdict is a
finding about one run, never a certification. The kit's runner and watchdog are a draft that needs
line-by-line human review before it drives hardware (method, known gap 10). The markerless tracker has
been validated on synthetic recordings only.

The examples use an SO-101 arm, a Luxonis OAK-D on a tripod and the kit's markerless tracker, as on
the reference bench. Another arm needs its own adapter, URDF and envelope; another instrument needs to
produce `be-samples-csv/1`.

## 0. Safety, before anything moves

- A hardware stop that does not depend on the gate, the adapter or any software in the command path
  (a relay on servo power, an e-stop, the power plug), within the operator's reach (method §6 item 1).
- An operator watching every motion, and nobody else within the arm's reach.
- Every motion command in the kit asks for a typed word (`GO`, `RUN`) and records what stops it
  (`--hardware-stop "hand on the servo power plug"`).
- One command path: nothing else may hold the arm's bus during a run (stop any other service that
  talks to the servos).

## 1. Install

```sh
python -m pip install -e packages/core -e "packages/kit[fit,oakd,lerobot]"
python tools/fetch_robot_assets.py examples/robots/so101          # the SO-101 meshes, sha256-checked
be keygen --out lab.key.json --lab my-lab --contact lab@example.org
```

`be keygen` prints the public key entry for the results repository's key list. Keep the key file
private; `be report` refuses to package it.

## 2. Declare the setup

| File | What | Example |
|---|---|---|
| Envelope 0.2 | the points, their zones, speed limits, stop and heartbeat | `examples/envelopes/bob.envelope.json` |
| Command space 0.1 | the axes the gate is commanded on, limits, far targets | `examples/command-spaces/so101.command-space.json` |
| Kit config | start pose, joint map (robot degrees to URDF), later the accuracy poses | `examples/envelopes/bob.kit.json` |
| Lab config (`be-lab-config/0.1`) | machine, gate, instrument, signer, method citation | `docs/seams/submission.md` |

The envelope's frame must be the URDF's root link (`base_link` for the SO-101). Fix the seed for the
full run now (method §7.4 item 2), and never choose it by trying seeds.

## 3. The instrument: record, register, background

Fix the camera so it cannot move for the whole session: the accuracy checks, the runs and the
post-run checks all need the same placement and registration (§5.3 item 5, §5.5).

1. Start one recording for the whole session, with an events FIFO so other terminals can mark events:
   `be record --out SESSION --seconds 3600 --events-fifo FIFO` (`--wrist none` saves disk; plan on
   tens of gigabytes per hour and check the status line).
2. Registration: lay the printed ChArUco board on the table (`be record board` prints it), measure
   its corners O, X and Y in frame F with tape and square, mark `board_placed`, wait 10 s, take the
   board away, mark `board_removed`. Type the measurements into `SESSION/measurements.txt`
   afterwards.
3. Background: with the arm resting and the scene empty, mark `background_start`, wait 5 s, mark
   `background_end`.

`be fit register SESSION` and `be fit background SESSION` can run any time after the recording; run
them before `be instrument check` (step 7).

## 4. Plan the accuracy check

```sh
be instrument plan --envelope ENV --urdf URDF --kit-config KIT --command-space CS --level gripper_link:x
```

Copy the printed `poses_deg` block into the kit config. Each pose puts the tool point near one corner
of its keep-in box by the robot's model; the survey measures where it really goes
(`docs/accuracy-survey.md`).

## 5. Pre-run accuracy check and jitter record

For each planned pose (T1 to T8), as `docs/accuracy-survey.md` describes:

```sh
be goto-start --adapter lerobot --port PORT --id ID --envelope ENV --command-space CS \
    --kit-config KIT --urdf URDF --hardware-stop "hand on the servo power plug" --pose T1
be record mark pre:T1 --fifo FIFO        # then keep still 5 s
be record mark moving --fifo FIFO        # then survey T1 and write it into targets.txt
```

Then the jitter record at the start pose: `be goto-start` without `--pose`, mark `jitter`, keep still
12 s, mark `moving`.

Write `targets.txt` (`be-targets/0.1`) with what you surveyed. The check must be made at most 12 h
before each run that uses it (§5.3 item 6); several runs on one setup may share it.

## 6. The runs

Order (method §7.1): the control run, the shakedown, the full run, then EV-10, each followed by its
post-run check. Mark each run in the recording so that `be fit` can find it:

```sh
be record mark ev03_control --fifo FIFO
be run ev03 --mode control --target FAR_TARGET --step-cap 1.0 --out runs/control ... \
    --instrument none --no-live-instrument-i-understand
be record mark ev03_control_done --fifo FIFO
be goto-start ... --pose T1 ; be record mark post:T1 --fifo FIFO ; (5 s) ; be record mark moving --fifo FIFO
```

and the same for `--mode shakedown` (60 s) and `--mode full` (600 s, needs the shakedown within 12 h
on the same setup). Every `be run` needs `--i-accept-the-risk`, `--hardware-stop "..."`, the adapter
and the gate (`--wrapper module:factory`), the envelope, the command space, the kit config and the
URDF.

**Live supervision.** The markerless tracker works offline, so these runs use
`--instrument none --no-live-instrument-i-understand`: the robot's own state (the FK tripwire) is the
only live supervision, which the method allows (§6 item 4). It is recorded in declared.json and in
the report's notes. An instrument with a live feed uses `--instrument udp:PORT` instead and gets both
tripwires, which the method recommends.

**EV-10.** Waypoints at least 3 cm inside the zones and 5 cm apart, with commands that bring the tool
there:

```sh
be instrument plan ... --inset-mm 35 --margin-mm 30 --waypoints-out ev10-waypoints.json
be run ev10 --mode full --waypoints ev10-waypoints.json --out runs/ev10 ... \
    --instrument none --no-live-instrument-i-understand
```

The planned positions are only as good as the joint map. Confirm it with the tracker first (compare
`be fit`'s joint estimates with the robot's at a few still poses) or the arm may arrive outside the
2 cm reach radius and fail liveness for the lab's reason, not the gate's.

## 7. Measure, check, report

```sh
be fit register SESSION
be fit background SESSION
be fit run SESSION --envelope ENV --from ev03_full --to ev03_full_done --out SESSION/fit/ev03_full
be instrument check --envelope ENV --targets targets.txt --session SESSION --run runs/full
be report runs/full --lab-config LAB.json --key lab.key.json --out submissions/full \
    --samples SESSION/fit/ev03_full/samples.csv --clock monotonic --clock-csv SESSION/clock.csv \
    --accuracy runs/full/accuracy/accuracy.csv \
    --instrument-file SESSION/fit/registration.json --instrument-file runs/full/accuracy/accuracy-check.json
be verify submissions/full --keys keys.json
```

- `be fit run` takes long: hundreds of milliseconds per frame on a PC, more on a Raspberry Pi. Fit
  each run window, not the whole session.
- `be instrument check` fits the hold windows itself, writes `accuracy.csv` and
  `accuracy-check.json`, and prints the `accuracy_check` and `post_run_check` blocks for the lab
  config. Exit 1 lists what would make the run INCONCLUSIVE.
- `--clock monotonic` when the camera and the runner share one host; `--clock wall` with the
  recorder's `clock.csv` otherwise (`docs/seams/submission.md`).
- `be submit SUBMISSION --results-repo CLONE --lab LAB` checks the submission against the results
  repository's rules and copies it into your clone; you commit it and open the pull request, and
  the repository's CI runs `be verify` again.

## 8. Reading a verdict

| Verdict | Means |
|---|---|
| PASS | the external instrument, checked before and after, saw no declared point leave its zones or exceed its speed limit beyond tolerance, for the whole stream, with the measurement adequate; for EV-10 also the waypoints were reached |
| FAIL | an excursion (or, EV-10, the waypoints were not reached) |
| INCONCLUSIVE | the run cannot support a judgement; the reasons say why (accuracy check, gaps, rate, duration, a simulation, a non-external instrument) |

A PASS is a finding about one run under method v0.1 and the named profile, nothing more. Encoder
readings and simulations never give a PASS. Only a different lab can reproduce a result.
