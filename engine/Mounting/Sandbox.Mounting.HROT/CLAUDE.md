# HROT mount — working notes

A native s&box mount for HROT (Steam app 824600, retail 32-bit build). HROT
ships no map files: the levels are *code* in `HROT.exe`, so most of this project
is reverse engineering rather than parsing.

HROT is installed in D:\SteamLibrary\steamapps\common\HROT
Contents:
HROT.exe	exe	10.10 MiB
HROT.pak	pak	244.19 MiB
OpenAL32.dll	dll	434.59 KiB
steam_api.dll	dll	232.28 KiB
Anything else in HROT folder is previous RE efforts, dumps etc. They are not relevant


## Read first

`REVERSE_ENGINEERING.md` is the single reference: asset formats, texture
resolution, the map-data grid layout and cell fields (sections 8-10), the world
renderer decode (section 11 - per-cell traversal, boundary ownership, walls,
stairs, risers, water, panels), props, doors, signs, sounds and lighting
(section 12+). Section 14 is the shaders - HROT does its water and other effects
in GLSL compiled into the executable, not on the CPU, so a CPU-side search for
them turns up nothing however hard you look. Section 17 is what is still open.

## How to work on this

These are not style preferences — each one was learned by getting it wrong and
losing hours.

**Read the neighbouring mount before working around the engine.** The Quake,
GoldSrc, SE3 and NS2 mounts have hit most of these problems already. A runtime
`SoundEvent` serializes as its `ResourcePath` and a built-in-code one has none,
so emitters reload silent — the fix is one line, `EmbeddedResource`, and
`QuakeMap.Sounds.cs` had it. A whole component was written to avoid that before
anyone looked.

**An id from one table is not an id from another.** Sound ids run 1..427,
static-model ids 1..840, and every flag and count a constructor passes is a
small integer too. "This register holds a valid sound id" matches almost
anything: it produced four confident wrong answers in one sitting, and one of
them shipped 56 props playing the wrong sound. Check what the call *target* is
before believing a numeric match, and anchor on something outside the numbers —
the running game, or a name someone can read.

**Decode from the binary; do not infer rules from the data.** Every inferred
rule so far produced plausible-looking output that was wrong. The level-name
table was "corroborated" on two maps and wrong on thirty; the liquid pass was
blocked for weeks on the wrong cell field.

**Replay a rule in Python before touching engine code.** A rule that is wrong in
Python looks like a bug; the same rule wrong in C# looks like a broken renderer.

**Prefer the running game to more disassembly.** Reading process memory turned
multi-hour questions into single comparisons. Ask for a live dump rather than
speculating — the tools are already written.

**Never port a value that compensates for a host API convention.** These
produce self-consistent, entirely wrong output, and there have now been five:
OpenGL's bottom-left texture origin, HROT's axis order, the wall signs' UV V
flip, the sign quad's vertical axis, and the player-start yaw.

The pattern is sharp enough to use as a rule of thumb: **positions and sizes
port unchanged; orientations never do.** Coordinates, extents and pixel
rectangles have gone straight through every time. Anything describing a
*direction* - an angle, an axis sign, a texture origin, a winding - needs
checking against s&box before it is trusted. When something renders in the right
place at the right size but facing or flipped wrongly, look here first rather
than at the decode.

**One map is not a sample.** The player-start facing was read from the wrong
register and returned 0, which happens to be map 1's correct index - so a
broken decode looked like a working one, and a global yaw offset was then fitted
to that single observation. It survived until a second map was opened. Before
believing a constant that corrects a whole class of thing, check it against a
case that exercises a different value of whatever it corrects.

**A count is a claim too, in both directions.** `Image.sweep` decodes at four
alignments and repeats addresses, so failing to de-duplicate reported 332 signs
where there were 83 - and the number was plausible enough to survive being
believed. Empty results get suspected; inflated ones tend not to.

**An empty result is a claim, and needs checking like any other.** A scan that
finds nothing usually means the scan is broken. Confirmed false negatives so
far: comparing against the wrong `X86_OP_IMM`, `disasm` stopping at the first
undecodable byte, a 256-entry read past an 11-entry table, and a shader feature
that was never declared so `SetFeature` did nothing.

**A ruled-out list can be entirely true and still point away from the answer.**
Music sat undecoded behind four findings that were each correct: not an id in
the constructors, not a table, not a string, not named by any caller of the play
function. The store turned out to be a dword *through a pointer* in the
constructors — invisible to every search shaped around a register holding an id.
Worse, the fourth finding was the signpost read as a wall: of the nineteen
callers, the one that does not *name* a music id is the one that **loads** it,
and that is the music player. When a search for a constant comes back empty,
the next question is which call site takes that argument as a variable — the
absence is the evidence, not the dead end.

**A decoder that silently drops records produces no error and no geometry.**
Panels, doors and props each had call sites whose arguments were computed rather
than pushed as literals, and each was invisible until someone walked into the
missing object. When a decoder reports what it accepted, that number says
nothing about what exists.

**Decoded data does not belong in source - including in the tools.**
Transcribed tables drift from the thing they describe: the level names were
wrong on 30 maps, and the manual texture table was both unreachable and wrong.
`dump_signs.py` carried its own copy of the constructor table listing seven maps
while the mount had thirty-two, so every total it printed was a slice of the
game presented as all of it. Decode at mount time, and have the tools parse the
C# the way `hrot_world_ranges.py` does.

## Building

```powershell
dotnet build engine/Mounting/Sandbox.Mounting.HROT/Sandbox.Mounting.HROT.csproj -v q --nologo
```

Copies to `game/mount/hrot/hrot.dll`. **Close the s&box editor first** or the
copy fails on a file lock — and it fails quietly, so a change that seems to have
had no effect is often just this. Check the DLL's timestamp.

Only C# changes need a build. Documentation and Python changes do not.

### Shaders

The editor does **not** compile a newly added `.shader`. Build it explicitly:

```powershell
cd game
.\bin\managed\ShaderCompiler.exe -f "C:\dev\pub\sbox-public\game\mount\hrot\Assets\shaders\hrot_color.shader"
```

Arguments are matched against **absolute** paths. Watch the combo counts in the
output: a feature that is not declared in the shader's own `FEATURES` block
compiles "successfully" with fewer combos and silently does nothing.

## Tools

`Tools/` is Python. Start from **`hrot_re.py`**, which has the PE/disassembly/
Delphi-string/grid-replay helpers and three easily-repeated bugs designed out of
it. `python hrot_re.py` runs a self-test against known findings — run it after
changes here, and after any game update, since every address is build-specific.

| Script | Needs the game running? |
|---|---|
| `hrot_re.py` | no — shared library and self-test |
| `hrot_world_ranges.py` | no — parses the constructor table out of the C# |
| `dump_level_names.py` | no — ports `GetLevelName` |
| `dump_triggers.py` | no — all 376 trigger records from the constructors |
| `dump_signs.py` | no — wall decals and their subtitle boxes |
| `dump_player_spawns.py` | no — every map's player start, and a check on the C# that decodes it |
| `dump_strings.py` | no — the 1250-entry localisation table, both languages |
| `dump_sounds.py` | no — the sound id to filename table |
| `dump_model_sounds.py` | no — which models emit ambience, and its radius |
| `dump_music.py` | no — each map's music layers; `--check` and `--verify` are its controls |
| `dump_live_channels.py` | **yes** — what HROT is playing right now |
| `dump_live_watercolor.py` | **yes** — water vertex colour; blue is the scroll rate, and it is only in the live material |
| `hrot_lendec.py` | no — x86 length decoder; `--check` diffs every boundary against capstone |
| `dump_stack_args.py` | no — forward simulation; placement args the backward reader misses, and `--scales` for per-axis scale |
| `find_helpers.py` | no — what a map constructor calls; how new helpers get found |
| `dump_live_grid.py` | **yes** — the main regression oracle |
| `dump_live_volumes.py` | **yes** — moving-floor volumes, live vs static |
| `dump_live_triggers.py` | **yes** — per-prop trigger records |
| `poke_door_field.py` | **yes** — writes a byte, to test what a field controls |

## Cross-check a decoder against the disassembler

`HrotExecutableProps` walks raw bytes; the `Tools` scripts disassemble with
Capstone. Those are two independent readings of the same instructions, so
running both and diffing catches the class of bug that produces no error and no
geometry - which is most of them here.

It has paid for itself twice. The decal decoder walked backwards from the CALL
and landed mid-instruction, silently decoding nothing; and the player-start
facing was read from EDX when the helper takes it in EAX, which returns 0 - the
correct answer for map 1, the only map being tested, and wrong for the other
three. Both looked like working code.

`dump_player_spawns.py` is deliberately a near-copy of `ReadPlayerSpawn` for
this reason. When adding a decoder, write the tool version too and compare
counts and values before believing either.

## Constraints worth knowing

- **HROT crashes shortly after a debugger attaches**, so x64dbg/x32dbg is not
  usable. Reading and writing process memory from a script works fine and is how
  several fields were settled.
- **HROT's data lives entirely in PAKs and the executable.** The mount reads
  nothing else. The game directory also accumulates reverse-engineering dumps,
  and an earlier version overlaid those on top of the PAKs, which let them
  silently shadow real assets. Do not reintroduce loose-file reading.
- Addresses in the documents are for the retail build and are not portable.
- **Never give a runtime-built morphed model a bone.** See below.

## Morph targets

MD2 frames are vertex animation, which is what a morph target already is, so
frames map onto `Mesh.AddMorph` without conversion. `HrotModel` builds frame
zero as the mesh and every frame after it as a morph named for that frame.

Nothing else in sbox-public calls `AddMorph`, so none of the runtime path was
proven when this was written. What a scaffold of single-variable scenes
established, since it is cheaper to read here than to rediscover:

- Weights are per-instance. Many renderers share one `Model` and pose
  independently; sixteen instances behaved no differently from one.
- Deltas sum linearly, so interpolating between two frames is just weighting
  them `1-t` and `t`. No shader work is involved, and it is why `MorphAnimator`
  is as short as it is.
- Several morphed models render together without interfering.
- Morphs need a `SkinnedModelRenderer`. `ModelRenderer` cannot set a weight and
  draws the undeformed mesh.
- **A bone destroys them.** `SimpleVertex` has no blend indices or weights. With
  no skeleton the model skips skinning entirely and morphs are exact; add even
  one root bone and skinning reads bone bindings the vertices never had, and the
  mesh tears itself apart at high speed. Worse, one boned model corrupts the
  pass for every other morphed model drawn with it, so the symptom appears
  nowhere near the cause. `HrotModel` calls no `AddBone` deliberately.

That last one cost the most to find, and the reason is worth keeping: the first
scene varied four things at once, and it was unreadable enough to produce two
confident wrong diagnoses - the animation graph, then shared models - before
single-variable scenes made it obvious in one pass. Build the isolating scene
first; it is faster than the diagnosis it replaces.

Playback lives in `MorphAnimator`, in the base addon rather than here. It is not
HROT-specific - it plays any model whose morphs are named
`<sequence><number>` - and it has to be outside the mount regardless, because
component serialization resolves types through `TypeLibrary` and mount
assemblies are never registered with it.
