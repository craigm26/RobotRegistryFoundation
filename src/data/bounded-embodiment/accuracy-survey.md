# Surveying the accuracy check's points

The pre-run accuracy check (method §5.3) compares the instrument with positions measured some other
way. This page describes a way to measure them with a tape, a rule and a plumb line, for an arm's tool
point, and the numbers it gets. `be instrument plan` says where to put the arm, `be goto-start --pose`
puts it there, `be record` records the camera, and `be instrument check` does the arithmetic
(`docs/seams/instrument.md`). The survey is the part only the lab can do.

The principle: **put the arm somewhere, hold it still, let the camera record it, then measure where
the tool point actually is.** The plan only chooses where to send the arm; what the check compares
with is the measurement. Never copy a planned position into the targets file: the method requires
references measured independently of the machine's state (§5.3 item 3), and the planned numbers come
from the robot's own model.

## What you need

- A fine permanent marker.
- Masking tape, and a sheet of plain paper taped flat on the table under the arm's reach.
- A plumb bob: a small nut or fishing weight on about 60 cm of thin thread (sewing thread works).
- A steel rule, 300 mm or longer, that stands on its end (a combination square's rule is ideal).
- The tape measure and the square you used for the registration.
- The two masking-tape lines of frame F from the registration (below).

## Frame F

Measure in the same frame as the registration: origin on the table directly under the first joint's
axis (the SO-101's shoulder_pan), x forward, y to the robot's left, z up, millimetres. Keep the two
masking-tape lines on the table, one along x and one along y through the origin. `be fit register`
and `be instrument check` both turn F into the envelope frame with the same transform (for
`so101_new_calib.urdf`, base_link = F + (38.8, 0, −2.4) mm).

An error in where you put F's origin moves the registration and every surveyed point alike, so the
check cannot see it. The origin is under the base, so locate it from the base's edges and lay the
tape lines to a millimetre or two. On the SO-101 (`so101_new_calib.urdf`'s base mesh) the
shoulder_pan axis is on the base's left-right centreline, 25.8 mm behind the front edge of its
footprint.

## Where the tool point is (SO-101)

The SO-101's tool point is the origin of `gripper_frame_link` in `so101_new_calib.urdf`. On the
gripper it is **on the inner face of the fixed jaw, centred across the face's width, 6 mm back from
the tip of the jaw**: the middle of the tapered fingertip. (In `gripper_link` coordinates it is at
(−7.9, −0.2, −98.1) mm; the fixed jaw's inner face is the plane x = −7.9 mm near the tip, about 9.5 mm
wide there, and the jaw ends at z = −104.4 mm.) Put a small dot there with the marker. For another
arm, find the point its URDF names and mark it the same way.

## The poses

```
be instrument plan --envelope ENV --urdf URDF --kit-config KIT --command-space CS --level gripper_link:x
```

prints eight poses, the corners of the tool's keep-in box 20 mm inside each face (one moved off a
keep-out), with the fixed jaw's face vertical so that a plumb line can hang from the dot. Add the
printed `poses_deg` block to the kit config. The method needs at least 6 points near both ends of
every axis; eight gives a spare. If your joint map is rough, the arm lands a few centimetres from the
planned spot. That is fine: you measure where it lands, and `be instrument check` reports whether the
measured points still reach both ends of each axis.

## For each point (about 3 minutes)

1. **Move.** `be goto-start ... --pose T1` and type GO. When it finishes, press Enter at the OFF
   question: the arm stays where it is, holding.
2. **Hold.** Clear the scene: no hands, rule or thread near the arm. Mark the event `pre:T1`
   (type it in the recorder, or `be record mark pre:T1 --fifo FIFO` from another terminal), keep still
   for 5 seconds, then mark `moving`.
3. **Plumb line.** Press the thread onto the tool-point dot with a fingertip, or stick it there with a
   scrap of tape, and let the bob hang just clear of the paper. Wait for it to stop swinging. Mark the
   paper under the bob's tip.
4. **Height.** Stand the rule on the table beside the jaw, its zero on the table. With your eye level
   with the dot, read the dot's height to the millimetre: that is z.
5. **Horizontal.** Measure the paper mark's distance from the y-axis tape line (that is x) and from the
   x-axis tape line (that is y, negative to the robot's right), with the square to keep the tape
   perpendicular.
6. **Write it down**: `T1 = x, y, z` in millimetres. Take the thread and tape away.

If you bump the arm at any point, do the whole point again: hold first, then survey. The latest
`pre:T1` hold is the one `be instrument check` uses (with `--run`, the latest before the run).

## The jitter record and the post-run check

- **Jitter**: `be goto-start` (the start pose), clear the scene, mark `jitter`, keep still 12 s, mark
  `moving`. The method asks for at least 10 s of the instrument's raw samples (§5.4).
- **Post-run check**: after each run, without touching the camera, go to one surveyed pose again
  (`be goto-start ... --pose T1`), clear the scene, mark `post:T1`, hold 5 s, mark `moving`. No new
  survey is needed: the check compares the instrument's two readings at T1 (§5.5). Survey it again
  only if you want to know the arm's repeatability.

## The targets file

```
format = be-targets/0.1
frame = F
units = mm
method = Plumb line from the tool-point dot to paper on the table, steel rule for height; tape and square to frame F's axis lines
surveyed_at = 2026-10-13T16:20:00Z
T1 = 196, -80, 283
T2 = 196, 81, 282
...
```

## What it gets you

| Source of error | Typical size |
|---|---|
| The dot's position on the jaw | 1 mm |
| The plumb line (settled bob, mark under its tip) | 1 mm |
| Tape and square to the axis lines | 1 mm per axis |
| Reading the height on the rule (parallax) | 1 mm |
| A jaw face tilted 10° from vertical (the thread leaves the jaw's edge) | under 1 mm |

So each reference is good to about 2 mm, against the check's limits of 10 mm (95th percentile) and
15 mm (largest). The rest of the budget belongs to the instrument: the registration, the fit, and how
far the real arm differs from its URDF.
