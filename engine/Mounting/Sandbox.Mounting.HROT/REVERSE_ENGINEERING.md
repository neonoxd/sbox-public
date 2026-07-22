# HROT mount reverse-engineering handoff

Last updated: 2026-07-21  
Target: retail 32-bit Steam build of HROT, App ID `824600`  
Implementation: `engine/Mounting/Sandbox.Mounting.HROT`

This is the single reference for the native s&box HROT mount: asset formats,
texture resolution, map data layout, the world renderer, props, doors, signs,
sounds and lighting. It is intended to be sufficient context to continue the
work without the original conversation.

**Section 11** documents the world renderer - the mount ports HROT's own
world-surface pass rather than inferring geometry from the grid.

## 1. Current result

The mount currently:

- locates the Steam installation and mounts every HROT PAK;
- loads JPG, JPEG, TGA, PNG, and PSD image assets from encoded bytes;
- loads every frame of animated MD2 models, frame zero as the mesh and the
  rest as morph targets named for their MD2 frame;
- loads static 3DS models, each registered twice: mesh collision for the level's
  own static props, and a convex-hull `(PROP) ` copy that can be dropped into a
  scene and simulated;
- recovers most model-to-texture relationships from `HROT.exe`;
- reconstructs the level grid and static props directly from `HROT.exe`;
- creates `maps/Map NN [Name].scene` resources for 32 map IDs, the name decoded
  from the executable at mount time;
- builds world geometry by a **port of HROT's own renderer** - floors, ceilings,
  wall bands, auxiliary bands, risers, stairs, transparent panels, the overlay
  quad and water surfaces - see section 11;
- spawns doors as individual entities with their decoded geometry and linkage;
- places static props with per-instance scale, and basic lighting;
- recovers the two common ceiling-light placement helpers;
- spawns **wall signs** as one GameObject each, tagged `hrot_sign`: those needing
  their own quad get one sampling the level's decal sheet, and those whose text
  is already scenery get the volume alone. Every sign with a translation carries
  a `BoxCollider` trigger sized to HROT's own activation box and named with its
  string id;
- tags **ladders** `ladder` and gives each a climb volume standing off its face,
  rotated with the ladder rather than axis-aligned;
- places a **`SpawnPoint`** where HROT starts the player, on all 32 maps;
- plays each map's **background music**, the first of HROT's three crossfaded
  layers, non-positionally on the `Music` mixer;
- renders every HROT surface with nearest-neighbour filtering, through the
  mount's own `hrot_color.shader`.

Not implemented:

- **conveyor belts** and the **moving-volume liquid clause** (elevators and water
  that rises when triggered) - both gated on runtime cell state, see section 11.9.
  Static water surfaces (`0x09`/`0x0C`) are decoded and rendered;
- **the other two music layers**. HROT crossfades three looping layers per map
  and the mount plays layer 1; the gains the other two fade in on have no
  equivalent here - see section 12;
- **showing** a sign's translation. The trigger volumes are spawned and carry
  their string ids, but nothing reacts to them and `GetString` has no C# port,
  so the text is reachable only through `Tools/dump_strings.py`;
- **playing** MD2 animation. The frames are all present as morph targets;
  `MorphAnimator`, in the base addon, drives them - but nothing in the mount
  decides which sequence an actor should be in, and no actors are spawned;
- enemies, pickups, triggers, scripts, sounds, or gameplay;
- exact original light parameters;
- a complete semantic decoder for every specialized executable helper;
- full 3DS material/object-transform support.

The implementation is pattern-based and tied to the retail executable. All
absolute virtual addresses below are build-specific.

## 2. Important files

| File | Responsibility |
|---|---|
| `HrotMount.cs` | Steam discovery, PAK overlay, resource registration, texture resolution and caches |
| `HrotPak.cs` | HROT PAK reader |
| `HrotTexture.cs` | Mounted texture resource |
| `HrotModel.cs` | MD2 loader; every frame becomes a morph target |
| `Hrot3dsModel.cs` | Static 3DS loader |
| `HrotExecutableTextureMap.cs` | Recovers MD2/static/weapon texture assignments from x86 patterns |
| `HrotExecutableStaticModels.cs` | Recovers numeric static-model registrations |
| `HrotExecutableMapData.cs` | Replays constant writes that construct the 101x101 map grid |
| `HrotExecutableProps.cs` | Recovers static prop and ceiling-fixture calls |
| `HrotMap.cs` | Scene assembly: lighting, static props, fixture lights, metadata |
| `HrotMap.World.cs` | World surfaces, ported from HROT's renderer; the load-time derive pass |
| `HrotMap.Doors.cs` | Door leaf geometry and the GameObjects carrying them |
| `HrotMap.Signs.cs` | Wall sign objects: decal quads and activation volumes |
| `Tools/dump_live_grid.py` | Checks the port's rules against the running game's grid |
| `Tools/dump_live_doors.py` | Dumps live door records |
| `Tools/poke_door_field.py` | Writes a byte into a live door record, to test a field |
| `Tools/find_liquid_cell.py` | Finds liquid cells, for breakpoints |
| `Tools/hrot_map_probe.py` | Optional Capstone/pefile/Pillow map-field visualization tool |
| `Tools/hrot_world_ranges.py` | The world-constructor ranges, parsed from `HrotExecutableMapData.cs` so the tools cannot drift from the mount |
| `Tools/dump_level_names.py` | Ports HROT's `GetLevelName`; regenerates `HrotMapNames` |
| `Tools/dump_triggers.py` | All 376 trigger records from the constructors |
| `Tools/dump_signs.py` | Wall decals and subtitle boxes; parses the constructor table out of `HrotExecutableProps.cs` |
| `Tools/dump_player_spawns.py` | Every map's player start, and a cross-check on the C# that decodes it |
| `Tools/dump_strings.py` | The 1250-entry localisation table, both languages |
| `Tools/dump_sounds.py` | The sound id to filename table |
| `Tools/dump_model_sounds.py` | Which models emit a looping sound, and its radius |
| `Tools/dump_music.py` | Each map's music layers; `--check` and `--verify` are its controls |
| `Tools/dump_live_channels.py` | **Live.** What HROT is playing right now |
| `Tools/find_helpers.py` | What a map constructor calls, and which targets are still unnamed |

`HrotMap` is one sealed partial class across the four `HrotMap*.cs` files.

Build with:

```powershell
dotnet build engine/Mounting/Sandbox.Mounting.HROT/Sandbox.Mounting.HROT.csproj --no-restore -m:1 -nodeReuse:false -v:minimal
```

The project copies its DLL to:

```text
game/mount/hrot/hrot.dll
```

## 3. HROT PAK format

All integers are little-endian.

### Header

| Offset | Size | Meaning |
|---:|---:|---|
| `0x00` | 4 | ASCII magic `HROT` |
| `0x04` | 4 | directory-table file offset |
| `0x08` | 4 | directory-table byte length |

The directory length must be divisible by 128.

### Directory entry

Each entry is exactly 128 bytes:

| Offset | Size | Meaning |
|---:|---:|---|
| `0x00` | 120 | null-terminated path |
| `0x78` | 4 | file-data offset |
| `0x7C` | 4 | file-data length |

Paths may contain backslashes. Normalize them to `/`, remove leading `/`, and
use case-insensitive lookup. Validate every offset/length against archive size.

The mount groups PAKs by their directory relative to the game root. PAK lists
are sorted by filename descending, and the first matching entry wins.

**PAKs and `HROT.exe` are the only things the mount reads.** HROT ships no
models or textures outside them, so there is nothing legitimate to find loose on
disk - and the game directory is exactly where reverse-engineering dumps
accumulate. An earlier version overlaid loose files on top of the PAKs, which
meant those dumps could silently shadow real game assets and change what the
mount produced. Do not reintroduce it.

Resources register under a type prefix: models as `models/<pakDir>/<file>`,
textures as `textures/<pakDir>/<file>`, scenes as `maps/Map NN [Name]`. The
prefix is part of the *registered* name, so anything resolving a resource
through `mount://` must include it - `HrotMount.ModelPrefix` exists so
`FindStaticModelPath` and the registration cannot drift apart. Loaders are
unaffected: they take PAK-internal paths, not registered ones.

Every 3DS is registered **twice**: once as itself, and again with a `(PROP) `
marker on the file name, carrying convex-hull collision instead of the concave
mesh. See section 6.

## 4. Texture decoding and lookup

Do not pass a physical Windows path to `Texture.LoadAsync`. s&box interprets it
as a virtual path and rejects the drive colon, for example:

```text
/d:/steamlibrary/... cannot contain ':'
```

The working path is:

```csharp
using var bitmap = Bitmap.CreateFromBytes( encodedBytes );
var texture = bitmap.ToTexture( true );
```

Textures are cached by normalized virtual path. Supported registered
extensions are `.jpg`, `.jpeg`, `.tga`, `.png`, and `.psd`.

### MD2 texture resolution order

`ResolveModelTexture` uses this order:

1. each embedded 64-byte MD2 skin path exactly as written;
2. the embedded skin basename beside the model;
3. the embedded skin stem with each supported image extension, both in its
   referenced directory and beside the model;
4. the MD2's own basename with each supported extension;
5. the assignment recovered from `HROT.exe`, with extension substitution;
6. the small manual fallback table below;
7. white texture and a warning.

This extension substitution is necessary because MD2/3DS files often retain a
development-time `.PSD` name while the shipped image is JPG or TGA.

### Executable texture assignments

`HrotExecutableTextureMap` parses the PE32 image and extracts three x86 forms:

```text
Static model:
mov ecx, texture_string
mov edx, model_string
mov ax, model_id
call RegisterModel

Weapon:
push texture_string
mov ecx, model_string
mov dl, slot              ; or xor edx,edx
mov eax, [ebp-4]
call RegisterWeapon

Actor:
mov edx, model_string
call LoadModel
...
mov edx, texture_string
call SetTexture
```

Actor assignments are applied last because an animated MD2 may share a
basename with a static model, as with `ryba`.

The actor scanner identifies the model-loader/texture-setter target pair by
frequency and proximity, not fixed addresses. It may report hundreds of
assignments because it sees repeated initialization sites; this does not mean
there are hundreds of unique textures. `HrotMount` filters the recovered map to
basenames of MD2 files that actually exist.

### Transparency: blendigo, blendigo2 and the shader

HROT's see-through surfaces - ladders, railings, grates, cables, cages - are
**not** colour-keyed. They are ordinary models whose registered texture is a
32-bit TGA whose alpha is the cutout:

| Texture | Models | Content |
|---|---:|---|
| `blendigo.tga` | 49 | ladders (`zebrik*`), cables, grills, lamps |
| `blendigo2.tga` | 26 | railings (`zabradli*`), grates (`mriz`), cages, cranes |
| `sklo.tga` | - | glass panels, the one with *graded* alpha rather than binary |

Both blendigo atlases are 512x512x32 with alpha that is almost entirely 0 or
255, so they want **alpha testing**, not blending. `sklo.tga` carries
intermediate values and is genuinely translucent.

`pack1_spec.jpg` is **not** an alpha mask - it is quarter-resolution and its
content does not follow the cutouts (the grate tile is solid green there).
Chasing it is a dead end.

**Transparency depends on the shader sampling alpha.** Texture alpha survives
everything else - `Bitmap.CreateFromBytes` decodes to `Rgba8888`/`Unpremul`, TGA
included, and `ToTexture` keeps it - so a shader that samples only `.rgb` and
hardcodes `m.Opacity = 1` (as the Quake mount's `simple_color` does) discards it
at the last step. `game/mount/hrot/Assets/shaders/hrot_color.shader` is
`simple_color` with the alpha sampled.

**The two alpha modes are mutually exclusive and must be chosen per texture.**
`sbox_pixel.fxc` turns `S_ALPHA_TEST` into alpha-to-coverage and `S_TRANSLUCENT`
into SRC_ALPHA blending with depth writes off, and the standard feature set
declares a rule forbidding both at once. Alpha-testing `sklo.tga` clips its
graded alpha into a hard cutout, which is why glass stayed solid after the
ladders were fixed.

The mode is classified from the pixels, not from a list of texture names:
sample the alpha bytes and count how many are strictly between 16 and 239.

| Texture | Intermediate | Mode |
|---|---:|---|
| `blendigo2.tga`, `chars`, `ghost`, `sliz` | 0% | alpha test |
| `blendigo.tga` | 1% | alpha test |
| `particles`, `krev` | 21-22% | blend |
| `sklo.tga`, `tvmask` | 24% | blend |

The gap between 1% and 21% is wide, so the 5% threshold is not delicately
placed. Results are cached per texture - the atlases are 1 MB each and would
otherwise be re-read for every model that uses them.

Water is left **opaque**: `voda1.jpg` has no alpha channel, so translucency
could not make it see-through and would only cost depth writes.

#### Compiling the shader

The editor does **not** compile a newly added `.shader` on its own; the mount
just gets a broken material. Build the `.shader_c` with the in-repo compiler:

```powershell
cd game
.in\managed\ShaderCompiler.exe -f "C:\dev\pub\sbox-public\game\mount\hrot\Assets\shaders\hrot_color.shader"
```

It enumerates `*.shader` under the working directory and matches arguments
against **absolute** paths, so pass the full path; with no arguments it rebuilds
everything it finds. `-f` forces a recompile. The `Exception when loading
...mount\*.dll` lines it prints on startup are unrelated and harmless.

Two things to check in its output, because both fail quietly:

- `F_ALPHA_TEST` must be declared in the shader's own `FEATURES` block.
  `common/features.hlsl` declares only `F_TEXTURE_FILTERING` and
  `F_ADDITIVE_BLEND`, so without a local `Feature( F_ALPHA_TEST, 0..1, ... )`
  the C# `SetFeature` call is a **silent no-op** and cutouts stay solid.
- The **PS combo count** is the tell. With alpha test declared it is 4; without
  it, 2. A shader that compiles "successfully" with 2 is the broken one.
  (`F_TRANSLUCENT` was added later; the count is 6 now.)
- **Sampler filter names are not validated.** `Filter( NOT_A_REAL_FILTER )`
  compiles as "successfully" as a real one, and the name reaches the
  `.shader_c` either way, so neither the compiler output nor a byte comparison
  tells you whether a filter is understood. Use one that another shader in the
  repo already uses. `Filter( Point )` gives HROT its nearest-neighbour
  texturing and is the same choice the Quake mount made.

### No manual assignments remain

`HrotMount` used to carry an `ExternalModelTextures` fallback table of 23 models
whose textures were said to be unrecoverable. Every one of them is in fact
recovered from the executable, so the table has been deleted:

- weapons, plus `nakladac` and `kosmonaut` - the static and weapon patterns;
- `gimp`, `kapic`, `kapic2`, `kapicmoto`, `holub` - the **actor** pattern;
- `granat2`, `minaoff`, `kulomet_0` - `.3ds`, not `.md2`, so they never used
  this code path at all and resolve through the static-model registrations.

Simulating the full resolution order against the PAK contents puts all 20 MD2
models at **step 5, the executable assignment** - the table sat at step 6 and
was unreachable for every one of them. It was also wrong (it claimed `pomlazka`
and `husitska` use `_sam_ruce.jpg`; both resolve to `dalsi11.jpg`), which is the
argument against keeping decoded data transcribed into source - the same lesson
as the level names.

`spawn.md2` is currently the only verified MD2 requiring vertically flipped V
coordinates.

## 5. MD2 models

HROT uses standard Quake II MD2:

```text
ident   = 844121161 = "IDP2"
version = 8
```

### Header

The 68-byte header is 17 little-endian signed 32-bit integers:

```text
ident, version,
skin_width, skin_height, frame_size,
num_skins, num_vertices, num_st, num_triangles,
num_gl_commands, num_frames,
ofs_skins, ofs_st, ofs_triangles, ofs_frames,
ofs_gl_commands, ofs_end
```

### Records

- Skin: 64-byte null-terminated ASCII path.
- Texture coordinate: two signed 16-bit integers `(s, t)`.
- Triangle: three unsigned 16-bit vertex indices followed by three unsigned
  16-bit texture-coordinate indices.
- Frame header: `scale[3]`, `translate[3]`, 16-byte frame name.
- Compressed frame vertex: four bytes `(x, y, z, normal_index)`.

Position decoding:

```text
position.axis = compressed_byte * scale.axis + translate.axis
```

The current loader:

- imports every frame: frame zero is the mesh, each later frame a morph
  target named for it, so `MorphAnimator` in the base addon can play them;
- regenerates normals per frame, because MD2 stores only a table index;
- reverses triangle order `(2, 1, 0)` for the s&box mesh convention;
- splits render vertices by `(position_index, texture_coordinate_index)`;
- uses the original position indices for the trace mesh;
- does not apply the map's `64` scale to MD2 assets.

UVs use a half-texel center:

```text
u = (s + 0.5) / skin_width
v = (t + 0.5) / skin_height
```

For verified bottom-left exports such as `spawn`, use:

```text
v = 1 - (t + 0.5) / skin_height
```

Future animation work should decode every frame using the same topology.
MD2 is vertex animation, not skeletal animation.

## 6. 3DS static models

Only the subset needed by shipped HROT assets is decoded.

### Parsed chunks

| Chunk | Meaning |
|---:|---|
| `0x4D4D` | main container |
| `0x3D3D` | editor container |
| `0x4000` | named object; skip null-terminated name then recurse |
| `0x4100` | triangular-mesh container |
| `0x4110` | vertex list |
| `0x4120` | face list |
| `0x4140` | UV list |
| `0xAFFF` | material container |
| `0xA200` | texture-map container |
| `0xA300` | texture filename |

Every chunk begins with:

```text
uint16 chunk_id
uint32 total_chunk_length
```

Vertex list:

```text
uint16 count
count * float32(x, y, z)
```

Face list:

```text
uint16 count
count * { uint16 a, b, c, flags }
```

UV list:

```text
uint16 count
count * float32(u, v)
```

3DS V is converted with `v = 1 - v`.

### Coordinate and winding result

HROT converts authored Z-up 3DS coordinates to runtime Y-up as:

```text
(x, y, z)3DS -> (x, z, -y)HROT
```

World conversion to s&box is:

```text
(x, y, z)HROT -> (x, -z, y)sbox
```

These transformations cancel for a static 3DS model, so preserve its authored
coordinates and winding and only multiply positions by `64`. Reflecting local
Y or reversing every face puts wall-mounted props on the wrong wall or makes
them inside-out.

Meshes whose smallest bounding-box dimension is at most `0.1`, with the other
two at least `0.5`, are emitted double-sided. This fixes thin signs, grates,
decals, and similar planar assets.

Texture resolution prefers the embedded `0xA300` filename, then falls back to
the runtime static-model registration. This is required for stale/truncated
names, for example `mriz.3ds` contains `lendigo2.psd`.

### Collision: two registrations per file

`ModelCollider.CreatePhysicsShapes` builds shapes from **every** physics part a
model has - it does not choose between a hull and a mesh - so a model cannot
carry both without the hull applying wherever the mesh does. The two uses want
different shapes, so each 3DS is registered twice. The marker sits in the file
name rather than in a directory of its own, so the pair sorts together and
`ResourceLoader` picks it up as part of `Model.Name`:

| Registered as | Collision | For |
|---|---|---|
| `models/<pakDir>/<file>` | `AddCollisionMesh`, concave | the level's own props, whose colliders `HrotMap` marks static |
| `models/<pakDir>/(PROP) <file>` | `AddCollisionHull`, one convex hull | dropping into a scene as a dynamic prop |

`ModelBuilder.AddCollisionMesh` is documented in the engine as *"This shape can
NOT be physically simulated"*. That is invisible in-map, where the collider is
static and the mesh is both exact and free, but `Prop.CreatePhysicsComponent`
sees one physics part on a dragged-in model and attaches a `Rigidbody` - whose
only shape then has no volume, so the prop falls through the world.

**MD2 models do not need the same treatment, and their apparent correctness is
misleading.** `HrotModel` calls only `AddTraceMesh`, so an MD2 has no physics
part at all and `Prop` returns before creating a body. They stay where they are
put because nothing simulates them, not because their collision works.

The hull is deliberately kept off the in-map models: HROT's openwork props -
ladders (`zebrik*`), railings (`zabradli*`), grates (`mriz`), cages - would each
gain a solid convex shape over their real geometry and seal openings the level
expects to be passable.

Current 3DS limitations:

- no local transformation matrix/pivot chunks;
- no smoothing groups;
- no per-face material groups or multiple materials;
- the first usable texture filename is treated as the model texture.

## 7. Static-model registration

HROT uses numeric IDs in level constructors. `HrotExecutableStaticModels`
recovers the table using:

```text
mov ecx, texture_string
mov edx, model_string
mov ax, numeric_id
call RegisterModel
```

The result is:

```text
numeric ID -> { model basename, texture basename }
```

Map props load `<model>.3DS`, and scene object names are:

```text
prop_<modelname> (model <id> #<per-model-instance>)
```

The instance counter intentionally restarts per model ID, so different model
types can both have instance `#1`.

## 8. Maps are compiled into HROT.exe

HROT does not ship conventional BSP/map files. Each level has:

1. a world constructor that performs constant writes into a global grid;
2. a following prop/gameplay constructor containing model placement calls.

The mount currently supports IDs:

```text
0, 1, 2, 4, 5, 6, 7, 8, 9, 10, 11,
12, 13, 14, 15, 16, 17,
20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
100, 101, 102, 103, 104
```

IDs 12, 13, and 16 currently share the same constructor range. Map 3, 18, 19,
and 99 do not have normal decoded ranges.

### Constructor ranges

Each row is `map: world_start-world_end / prop_start-prop_end`.

```text
0:   004F98CC-00542CAC / 00542CAC-0054595C
1:   0054595C-00596EF0 / 00596EF0-00599FD0
2:   00599FD0-005EC248 / 005EC248-005EF5B4
4:   005EF5B4-0064E0A8 / 0064E0A8-00651AF8
5:   00651AF8-006AA680 / 006AA680-006AD7A4
6:   006AD7A4-00700404 / 00700404-00704C30
7:   00704C30-0074E914 / 0074E914-007519A4
8:   007519A4-0079C6DC / 0079C6DC-0079FA18
9:   0079FA18-007D9F0C / 007D9F0C-007DCF50
10:  007DCF50-0082CFA0 / 0082CFA0-0083026C
11:  0083026C-00874CDC / 00874CDC-00877AE0
12:  00877AE0-008A55EC / 008A55EC-008A819C
13:  00877AE0-008A55EC / 008A55EC-008A819C
14:  008A819C-008F3690 / 008F3690-008F6A04
15:  008F6A04-0092A7C8 / 0092A7C8-0092BC60
16:  00877AE0-008A55EC / 008A55EC-008A819C
17:  0092BC60-009C058C / 009C058C-009C20B8
20:  009C20B8-00A09C48 / 00A09C48-00A0CD8C
21:  00A0CD8C-00A1F05C / 00A1F05C-00A1F8A4
22:  00A1F8A4-00A882F0 / 00A882F0-00A8AE44
23:  00A8AE44-00ACC354 / 00ACC354-00ACFC6C
24:  00ACFC6C-00AE20F4 / 00AE20F4-00AE2DC0
25:  00AE2DC0-00B9BA18 / 00B9BA18-00B9F338
26:  00B9F338-00BCDA08 / 00BCDA08-00BD0900
27:  00BD0900-00C03774 / 00C03774-00C061BC
28:  00C061BC-00C3727C / 00C3727C-00C39DB0
29:  00C39DB0-00C7D558 / 00C7D558-00C80770
100: 00C80770-00C83FD8 / 00C83FD8-00C841E8
101: 00C841E8-00C97A28 / 00C97A28-00C982F8
102: 00C982F8-00CAA088 / 00CAA088-00CAAC50
103: 00CAAC50-00CBD2C4 / 00CBD2C4-00CBE070
104: 00CBE070-00D40814 / 00D40814-00D5D388
```

### Level dispatch and names

The dispatch at `0x00D5DF39` reads the map id from the signed byte at
`0x017B9460` (the live "current map" variable), bounds it to `0..0x68`, indexes a
byte table at `0x00D5DF56`, and jumps through the table at `0x00D5DFBF` to each
arm's world then prop constructor. Replaying it reproduces the ranges above
exactly. Maps 12, 13 and 16 share one arm - identical world *and* prop data under
three names. A map 99 arm calls `0x00D9A40C` rather than a level constructor and
is not a shipped level.

Level names are decoded at mount time, not stored in the C#. Three structures
chain:

```text
GetLevelName        0x00DA4939   byte table 0x00DA4960, jump 0x00DA49C9
  each arm                       mov ax, <stringId>; call LoadString
LoadString          0x00DB9AA0   id in AX, dest in EDX; language off [[0xDE7E48]]
localisation switch  0x00DA9FD8   jump 0x00DAA004, 644 Delphi literals
```

The literals begin at file offset `0x009AF0F8` and are in **source order**, not
map-id order (map 0 is Vysehrad Castle, not Intro). `ReadMapNames` matches fixed
byte patterns rather than disassembling:

```text
GetLevelName arm   8B D6 66 B8 <imm16>            -> string id
localisation arm   8B 45 08 8B 40 F8 BA <imm32>   -> literal address
```

Two safeguards, since addresses are build-specific: if map 1 does not decode to
something starting "Kosmonaut" the whole result is discarded (`Map NN` fallback),
and each name is pattern-checked so a moved arm drops one name rather than
producing a plausible wrong one. Names are transliterated cp1250 -> ASCII. Maps
100-104 are the Endless arenas; map 100 resolves to the UI string "Press key",
which is what HROT returns. Map id is an internal identifier unrelated to play
order, which is not decoded.

| id | name | id | name | id | name |
|---:|---|---:|---|---:|---|
| 0 | Vysehrad Castle | 11 | George of Podiebrad | 23 | Uranium Mine |
| 1 | Kosmonautu Station | 12 | Rathaus | 24 | The Degustation |
| 2 | Luna | 13 | Orloj | 25 | The Granny's Valley |
| 4 | Hospital | 14 | Incinerator | 26 | Velhartice |
| 5 | Palace of Culture | 15 | Strahov Stadium | 27 | Kasperk Castle |
| 6 | Roztyly | 16 | Epilogue | 28 | Factory Farm |
| 7 | Mausoleum | 17 | Bubny | 29 | Dobrosov Fortress |
| 8 | Sokol Gym | 20 | Tocnik Castle | 100 | Press key |
| 9 | Sewage Treatment Plant | 21 | Tunnel | 101-104 | Endless |
| 10 | Underground stream | 22 | War with the Newts | | |

## 9. World-grid binary layout

The runtime grid is:

```text
101 x 101 cells
cell size = 0x1E0 bytes
cell address = grid + (row * 101 + column) * 0x1E0
```

Before replaying constructor writes, initialize every cell with:

```text
byte  +0x06 = 1
float +0x28 = 1.5625
float +0x14 = -2000.0
```

The current decoder replays these constant x86 write forms when the
displacement points into a recognized cell field:

```text
C6 80 disp32 imm8       mov byte ptr [eax+disp32], imm8
C7 80 disp32 imm32      mov dword ptr [eax+disp32], imm32
89 90 disp32            mov dword ptr [eax+disp32], edx
```

The last form is treated as zero because the relevant constructor writes are
preceded by `xor edx,edx`.

### Verified cell fields

| Offset | Type | Meaning |
|---:|---|---|
| `0x09` | byte | water type: `1` or `2`, `0` = none (11.7) |
| `0x0C` | float | water surface height, absolute (11.7) |
| `0x10` | byte | overlay-quad gate (11.3); maps 2, 4, 5, 6 |
| `0x1C` | int32 | ceiling atlas X |
| `0x20` | int32 | ceiling atlas Y |
| `0x24` | byte | ceiling active/present |
| `0x28` | float | ceiling height |
| `0x2C` | int32 | floor atlas X |
| `0x30` | int32 | floor atlas Y |
| `0x34` | byte | floor active/present |
| `0x38` | float | floor height |
| `0x3C/0x40/0x44` | X/Y/active | east wall |
| `0x4C/0x50/0x54` | X/Y/active | west wall |
| `0x5C/0x60/0x64` | X/Y/active | south wall |
| `0x6C/0x70/0x74` | X/Y/active | north wall |
| `0x1D5` | signed byte | wall baseline in units of `1.5625` |
| `0x1D6` | byte | stair direction: `0` or `1..4` |

Fields `0x48`, `0x58`, `0x68`, and `0x78` are also retained by the replay
filter, but their final semantics are not used by the renderer yet.

**This table is the map-data subset only.** Cells carry a further set of fields
that no constructor writes - they are computed at load time - which drive riser
emission, the moving-volume system and cell validity. Section 11 documents how
they are derived and which of them the mount reproduces:

| Offset | Role | Source |
|---:|---|---|
| `0x01`, `0x03` | whole-cell "real cell" / cull gates | runtime; `IsRealCell` substitutes for `0x01` (11.5) |
| `0x07` | needs a floor riser | derived by `0x00D42360` (11.5) |
| `0x08` | needs a ceiling riser | derived by `0x00D42360` (11.5) |
| `0x14` | overlay-quad height | derived (11.3); initialised to `-2000.0` |
| `0x19` | moving-volume index (elevators / rising water) | written at load, writer unlocated (11.9) |
| `0x1D4` | conveyor-belt gate | runtime; conveyors unported (11.9) |
| `0x1D7` | ceiling band count/type | derived by `0x00D424E9` (11.5) |

The derived fields the mount reproduces are verified against the running game
cell-by-cell on maps 1, 2 and 5 - see 11.5.

The floor/ceiling interpretation is easy to reverse accidentally:

```text
floor   = active +0x34, height +0x38
ceiling = active +0x24, height +0x28
```

### Directional auxiliary wall records

Each wall has an 84-byte (`0x54`) auxiliary record:

| Direction | Record offset |
|---|---:|
| east | `0x7C` |
| west | `0xD0` |
| south | `0x124` |
| north | `0x178` |

Layout:

```text
+0x00 signed byte: segment count, valid range 0..10
+0x01 signed byte: skipped/open segment number, valid range 1..10
+0x02..+0x03: not yet interpreted
+0x04: segment 1 atlas X (int32)
+0x08: segment 1 atlas Y (int32)
+0x0C: segment 2 atlas X
+0x10: segment 2 atlas Y
...
10 pairs total
```

Valid wall atlas coordinates are X `0..31`, Y `1..16`. Invalid auxiliary
material values fall back to the base directional wall material.

These records encode stacked wall textures, openings, windows, tall shafts,
and ladder exits. Supporting all ten entries is necessary; the barred opening
above the fourth map-1 ladder uses six.

`SkippedSegment` leaves the numbered auxiliary band open.

## 10. Map coordinates, scale, and atlases

### Coordinate conversion

HROT is right-handed and Y-up. s&box is Z-up. Use:

```text
(x, vertical_y, map_z)HROT -> (x, -map_z, vertical_y)sbox
```

Then multiply map/static-3DS positions by:

```text
UnitScale = 64
```

For grid rendering, `HrotMapGrid.Cell(column, row)` indexes:

```text
(row * 101 + column)
```

World placement is transposed and mirrored:

```text
sbox X = row * 64
sbox Y = -column * 64
sbox Z = HROT height * 64
```

Negating the column axis is essential. Omitting it mirrors the complete map
left-to-right and breaks prop relationships.

### Conventions that do not survive the port

Positions and sizes go across unchanged. **Orientations never have.** When
something renders in the right place at the right size but faces the wrong way,
is mirrored, or is upside down, it is one of these rather than a bad decode:

| What | HROT | s&box | Applied in |
|---|---|---|---|
| Axis order | right-handed Y-up | Z-up | the conversion above |
| Grid column | increasing | negated | `sbox Y = -column * 64` |
| Texture origin | bottom-left (GL) | top-left | atlas V, and the sign UV rect |
| Sign UV V | stores `1 - v/512` | use `v/512` | `HrotExecutableProps.ReadDecals` |
| Sign quad height | negative constant | larger value is the top edge | `HrotMap.BuildSignModel` |
| Player yaw | zero faces elsewhere | needs +90 | `HrotMap.PlayerStartYawOffset` |

Each of these was shipped wrong at least once, and each produced output that was
internally consistent - the sign showed real text from the right sheet, just the
wrong band of it; the player stood in exactly the right spot, facing 90 degrees
off. Nothing about the result suggests looking at a conversion, which is why
they are collected here.

The corrections belong at the point of use, not in the decoders. `ReadDecals`
and `ReadPlayerSpawn` report HROT's own values so a tool dump and a live memory
read still agree with them; `HrotMap` applies the host conventions where the
geometry is built.

### World texture atlas

The world uses `pack1.jpg`, a 2048x2048 atlas:

- atlas X is zero-based, `0..31`;
- atlas Y is one-based;
- floors/ceilings are 64x64: 32 columns x 32 rows;
- walls are 64x128: 32 columns x 16 rows;
- use a quarter-pixel inset: `0.25 / 2048`.

Walls and ceilings are rendered double-sided because HROT shares edge planes
between sectors and exposes either side in portals/outdoor transitions.

Vertical wall bands are `1.5625` HROT units high:

```text
WallSegmentHeight = 1.5625 * 64 s&box units
```

## 11. World geometry (ported from HROT's renderer)

The mount ports HROT's own world-surface pass rather than inferring geometry
from the grid. The port target is `0x00D8AC18` - the only function that walks
the whole 101x101 grid while reading both stair direction (`+0x1D6`) and wall
baseline (`+0x1D5`). Its per-cell body is `0x00D8B3A2-0x00D8C000`. Faithfulness
is the goal, quirks included; several are reproduced deliberately and called out
below.

**Off-by-one cell pointer.** The render loop holds the cell pointer at `base+1`
(Delphi folds the `+1` into a `lea`), so every field offset in a disassembly of
this function reads one less than the section 9 offset - read `[ebx+0x37]` as
cell field `0x38`. Re-deriving the whole field table through the `+1` reproduces
section 9 exactly.

The grid is **not** walked `0..100`. The render loop bounds itself with a
visible-window rectangle from globals at `0x17D5FF0..0x17D5FFC`; a static export
walks the full grid. Likewise the per-cell gates `0x01`/`0x03` and the call to
`0x00D42164` (a plain `row<101 && column<101` bounds check, not a visibility
test) are cull state and are ignored.

GL calls go through an indirect dispatch struct:

| Slot | Call |
|---|---|
| `[eax+0x020]` | `glTexCoord2f` |
| `[eax+0x5F8]` | `glVertex3f` |
| `[eax+0x228]` | `glColor3f` |
| `[eax+0x1FC]` | `glBegin(mode)` |
| `[eax+0x2C0]` | `glEnd` |

World surfaces use `glBegin(7)` = `GL_QUADS`: every surface is a four-vertex
quad.

### 11.1 Per-cell emission order

Per cell, in this exact order:

1. overlay quad, if `cell[0x10]` (11.3);
2. flat floor, if floor-active - emitted for stair cells too (11.3);
3. four floor risers (11.5);
4. stair dispatch on `cell[0x1D6]`, cases 1..4 (11.4);
5. ceiling and four ceiling risers, if ceiling-active (11.3, 11.5);
6. four base wall bands (11.2);
7. four auxiliary band walks (11.6).

Water (11.7) is a separate grid pass, and transparent panels (11.8) are not grid
cells at all.

### 11.2 Boundary ownership, and the wall emitter `0xD884E0`

Every vertical surface goes through one emitter, `0xD884E0(dirCode, atlasX,
atlasY, row, column, z0, z1, v0, v1)`, keyed by a `(cell, dirCode)` pair naming a
plane:

| dirCode | Face | Base wall record | Aux record |
|---:|---|---:|---:|
| 0 | west | `0x4C` | `0xD0` |
| 1 | east | `0x3C` | `0x7C` |
| 2 | south | `0x5C` | `0x124` |
| 3 | north | `0x6C` | `0x178` |

**One plane, one owner, decided by a single byte test.** A base wall band is
emitted where `cell[side].active != 0`; a riser is emitted where it is `0`, as
the *opposing* face of the *neighbour* cell, so the boundary plane has exactly
one owner:

| Side | Riser emitted as |
|---|---|
| west (`0x54`) | dirCode 1 at `(row, column-1)` |
| east (`0x44`) | dirCode 0 at `(row, column+1)` |
| north (`0x74`) | dirCode 2 at `(row-1, column)` |
| south (`0x64`) | dirCode 3 at `(row+1, column)` |

`v0`/`v1` are per-quad V offsets in atlas fractions applied at the bottom and top
edges. Whole tiles (base and auxiliary bands) pass `0, 0`; risers pass computed
fractions. Emitter constants: column step `0.03125` (1/32), row step `0.0625`
(1/16 - walls are 64x128), quarter-pixel inset `0.25/2048`. Quads are emitted
double-sided: each boundary is emitted once and seen from both sides.

The four branches emit these planes, texture coordinates `(right, top)`,
`(left, top)`, `(left, bottom)`, `(right, bottom)` in order:

| dirCode | Face | Plane | vertices |
|---:|---|---|---|
| 0 | west | `x=col` | `(col,z1,row+1) (col,z1,row) (col,z0,row) (col,z0,row+1)` |
| 1 | east | `x=col+1` | `(col+1,z1,row) (col+1,z1,row+1) (col+1,z0,row+1) (col+1,z0,row)` |
| 2 | south | `z=row+1` | `(col+1,z1,row+1) (col,z1,row+1) (col,z0,row+1) (col+1,z0,row+1)` |
| 3 | north | `z=row` | `(col,z1,row) (col+1,z1,row) (col+1,z0,row) (col,z0,row)` |

**V is mirrored.** HROT computes the atlas row as `1 - atlasY * step`, encoding
OpenGL's bottom-left origin; s&box samples top-left, so use `ty = (atlasY-1) *
step` with the top and bottom edge expressions exchanged (see the trap table in
section 10). Porting the expression literally selects atlas row `rows+1-y` - a
coherent but wrong tile.

**South-wall inset quirk, reproduced deliberately.** Branch 2's third vertex
omits the tile inset (`0x00D8887B` reads `fld TY; fadd v0` where every other
vertex reads `fld TY; fadd INSET; fadd v0`), bleeding a quarter pixel of the
neighbouring tile into one corner of every south-facing wall.

### 11.3 Floors, ceilings, and the overlay quad

Flat floor `0xD87DD0(row, column)` and ceiling `0xD87C28(row, column, atlasX,
atlasY, height)` share their constants (1/32 on both axes - 64x64 tiles - and the
same inset) and differ only in which corner they start at, giving them opposite
winding (`+Z` floors, `-Z` ceilings) and different texture orientation. Both are
preserved. The flat floor is emitted for every floor-active cell, stairs
included (its own `0x1D4` suppression gate is runtime state, so stair cells show
a harmless doubled floor).

The **overlay quad** `0xD87FC0`, gated on `cell[0x10]`, is a cell-sized
horizontal quad wound like the floor, at the derived height `cell[0x14]`. Its
atlas coordinates are global, not per-cell: from `0x17D3FCC`/`0x17D3FD0`, each a
constant `1`, so every such quad uses tile (1, 1). `0x14` is derived (11.5) and
only written for cells with a ceiling, so the port skips flagged cells without
one rather than drawing at the `-2000` initialiser. On maps 2, 4, 5, 6 only;
what it represents is unidentified.

### 11.4 Stairs (`0xD881AC`)

HROT's stairs are not ramps: `0xD881AC` emits a **flat** quad (height constant
across all four vertices) covering half the cell, raised one `0.15625` tread
above the stored floor height, textured with the whole floor tile (squashed 2:1).

| Dir | Raised half | Skirts `(dirCode, record, row, col)` |
|---:|---|---|
| 1 | `+column` | `1, 0x4C, row, col-0.5` · `3, 0x5C, row+0.995, col+0.5` · `2, 0x6C, row-0.995, col+0.5` |
| 2 | `-column` | `0, 0x3C, row, col+0.5` · `3, 0x5C, row+0.995, col-0.5` · `2, 0x6C, row-0.995, col-0.5` |
| 3 | `+row` | `2, 0x6C, row-0.5, col` · `0, 0x3C, row+0.5, col+0.995` · `1, 0x4C, row+0.5, col-0.995` |
| 4 | `-row` | `3, 0x5C, row+0.5, col` · `0, 0x3C, row-0.5, col+0.995` · `1, 0x4C, row-0.5, col-0.995` |

Cases 1/2 split on the column axis, 3/4 on the row axis, matching the mirror
transform at `0x00D85B4D`. Each case's first skirt is the step riser on the
boundary between the halves; the two side skirts use a `0.995` z-fighting nudge
and are emitted a full cell wide (the overhang buries inside the next step).
Skirts are one tread high with `v0=0, v1=0.05625`. Reproduced as-is.

### 11.5 Risers and the load-time derive pass (`0x00D42360`)

Two riser classes fill the boundary a wall record does not own. Their gates
`0x07` (floor) and `0x08` (ceiling) are **not** map data - they are computed once
at load by `0x00D42360`, driven by the grid walk ending at `0x00D4267F`. The
rule, per cell, ORed over the four orthogonal neighbours:

```text
for each neighbour B of A:
    if B is a real cell (0x01):
        if B.floorHeight < A.floorHeight:                 A[0x07] = 1
        if !B.hasCeiling or B.ceilingHeight > A.ceiling:  A[0x08] = 1
    if A or B is liquid (0x19):                           A[0x07] = A[0x08] = 1
```

So `0x07` = "some neighbour's floor is lower" and `0x08` = "some neighbour's
ceiling is higher, or open sky". The liquid clause needs `0x19` (11.9) and is
omitted; every residual difference from the running game is a liquid-adjacent
cell. `0x01` is itself never written by a constructor; `IsRealCell` (`HasFloor ||
HasCeiling || HasOverlay || any wall active || any aux band`) substitutes for it.

**Ceiling band classifier `0x1D7`**, computed in the same pass at `0x00D424E9`
from map data only (with `top = (baseline+1) * 1.5625`):

```text
0x1D7 = 0
if top - 0.02 > ceiling:                                0x1D7 = 1
elif top + 1.40625 > ceiling and top + 0.02 < ceiling:  0x1D7 = 2
```

`0` suppresses ceiling risers; `1` rises to the base band top, `2` to one band
above. Without it a port emits no ceiling risers - the missing doorway lintels.

Riser geometry (both express the quad as the opposing neighbour face, per 11.2):

```text
floor riser (0x07, floorHeight > baseline):
    v1 = (top - floorHeight) / 1.5625 * 0.0625
    z0 = baseline, z1 = floorHeight, v0 = 0

ceiling riser (0x08, 0x1D7 > 0):
    type 1:  z1 = top,          v0 = (ceil - baseline) / 1.5625 * 0.0625
    type 2:  z1 = top + 1.5625, v0 = (ceil - baseline - 1.5625) / 1.5625 * 0.0625
    z0 = ceilingHeight, v1 = 0
```

The derive pass, `0x1D7`, the `0x01` substitution and both riser rules match the
running game **10201/10201 cells on maps 1, 2 and 5** (`dump_live_grid.py`); the
only residual is the unreproduced liquid clause.

### 11.6 Auxiliary band walks

The four auxiliary records (section 9) stack extra wall bands above the base one.
Band `i` spans `[baseline + i*1.5625, baseline + (i+1)*1.5625]` from `i=1` (band
0 is the base wall). No wall-active gating and no neighbour offset - always the
cell's own coordinates. The skipped segment leaves its band open, which is how
windows, ladder exits and barred openings are cut.

### 11.7 Water (`0x00D8FFE5` / `0xD8F3CC`)

Water is a distinct surface class, map data through and through - cell fields
`0x09` (type: 1 or 2, 0 = none) and `0x0C` (absolute surface height, independent
of the floor below, which is what lets a prop stand on the bottom while partly
submerged). The pass walks the grid through a pointer pre-offset to `0x09`, binds
`voda1`, and calls `0xD8F3CC(row, column, cell[0x0C])` - a unit quad wound like
the flat floor.

**UVs come from cell parity**, a 2x2-cell repeat rather than one tile per cell:
row/column even -> `[0.0, 0.5]`, odd -> `[0.5, 1.0]`.

**Tint by type** via `glColor3f`: type 1 `(0.0, 0.91, 0.8)`, type 2 `(0.0, 0.9,
0.55)`. The mount does not apply it - `hrot_color.shader` exposes only
`g_tColor`; the tint is recorded for a future shader.

Water on **22 of 32 maps**, ~4400 cells. Type 1 everywhere; type 2 only on map 9
(Sewage Treatment Plant), 15 cells - an independent cross-check, since the water
types and the level names are unrelated decodes and agree. `0x09`/`0x0C` are
ordinary map data but had to be added to `IsWorldField`; a field census over the
whole constructor, not just the fields believed relevant, is what found them.

### 11.8 Transparent panels (`0x00D8FABC`)

Glass panels are not grid cells: they are 40-byte records written by the level
constructors through `0x00D4D690`, drawn with `sklo.tga` in a separate
translucent mesh. Their coordinates are already in the mount's transposed frame,
so they take the literal `PanelToWorld` transform, not `HrotToWorld`. Record
layout and the four orientation branches are decoded in `HrotExecutableProps` and
`HrotMap.World.cs`. Only the panel quad itself is emitted - the reveal, front
face and base riser around its one-cell recess are left to the traversal's own
bands and risers, to avoid double-covering the boundary.

Some panel rows are emitted from a counted loop whose first argument is an affine
function of the loop counter (the map-1 metro entrance), and some doors compute
an argument through a register rather than pushing a literal. Both go through
`TryReadCallInstances`, which resolves a call site into one instance for literal
pushes, N for a loop, or one for a register-computed constant - see section 12.

### 11.9 Not ported: conveyors and moving volumes

Both are gated on runtime cell state and cannot be replayed statically:

- **Conveyor belts.** Emitter `0xD8831C`, texture `pas` (Czech *belt*), gate
  `cell[0x1D4]`, the third grid pass at `0x00D8C08A`. No tested map has any;
  Factory Farm and Incinerator are where to look.
- **Moving volumes.** `cell[0x19]` assigns a cell to one of six engine-wide
  volumes - moving floors that serve as both **elevators and rising water**. The
  per-frame update `0x00D78654` writes `cell[0x38] = volume.base + volume.level`
  and `cell[0x00]` (the collision flag the door module reads). At rest
  `level = threshold`, and `base + threshold` equals the cell's static map-data
  floor height (measured against the running game on all six of map 5's volumes)
  - so the static water surface in 11.7 already sits at the right height and needs
  nothing at runtime. What `0x19` still gates is the derive pass's liquid clause
  (riser flags on 0.3-1.4% of cells) and those risers' `liquidV` offset.

  `0x19` is written at load by code that reaches the field through a pre-offset
  cell pointer with displacement 0 (as `0x00D78654` reads it), so a
  displacement-keyed instruction scan cannot see the writer. The volume table is
  at `0x17D6154`, stride `0x48`, seeded with 7 entries (index 0 plus volumes
  1-6) by `0xD5DD16`; the trigger system (section 12) drives it.

## 12. Prop placement from executable code

The prop constructor ranges are listed with the world ranges above.

Generic placement calls are recognized by:

```text
66 B8 id16             mov ax, model_id
E8 rel32               call helper
```

Verified helper addresses:

| Address | Meaning |
|---:|---|
| `0x00DBDDE0` | place on floor `(x, z, yaw)` |
| `0x00DBDE24` | place above floor `(x, vertical_offset, z, yaw)` |
| `0x00DBDF04` | place at explicit height `(x, y, z, yaw)` |
| `0x00DBE468` | place at integer cell center |
| `0x00DBDD64` | uniformly scale the most recently placed object |
| `0x00D5CDF4` | floor lamp (`lampa`) |
| `0x00D5CE0C` | one/two-arm lamp post (`lampa4_one` / `lampa4`) |
| `0x00D5CF20` | raised lamp (`lampa2`) |
| `0x00D5CD48` | specialized ceiling fluorescent (`zarivka`) |
| `0x00D5CFE8` | specialized ceiling bakelite lamp |
| `0x00D5D08C` | ceiling chandelier (`lustr`) |
| `0x00D5D120` | second ceiling chandelier (`lustr2`) |

Converted placements:

```text
PlaceOnFloor:
    position = (x, -z, cell.floor)

PlaceAboveFloor:
    position = (x, -z, cell.floor + vertical_offset)

PlaceAtHeight:
    position = (x, -z, explicit_y)

PlaceAtCell:
    position = (cell_x + 0.5, -(cell_z + 0.5), cell.floor)
```

Arguments are normally decoded by walking backward through literal `push`
instructions. A second decoder handles Delphi's x87 constant construction:

```text
store ESI/EDI integer on stack
fild integer
fld tbyte ptr [80-bit constant]
faddp
sub esp, 4
fstp [esp]
wait
```

The implementation reads the 80-bit extended constant and finds the preceding
ESI/EDI immediate assignment.

### Per-instance prop scale

Some static models are authored at a deliberately different base scale. HROT
applies a uniform scale immediately after the placement call:

```text
call Place...
push <float scale>
call 0x00DBDD64
```

The recovered scale belongs to that individual placement, not the numeric
model registration. Store it in the placement record and apply it to the
spawned object's world scale.

This is required generally across the maps. A verified example is map 2 model
430, `kupredu`: its raw 3DS mesh is about 81.8 authored units wide, then HROT
applies scale `0.043`. Ignoring the post-placement call makes it roughly 23
times too large. The 3DS master-scale and object-transform chunks in this file
are both identity/default and are not the cause.

### Specialized ceiling lamps

These helpers do not have `mov ax,id` call sites and must be scanned as direct
calls.

`0x00D5CD48`:

```text
model ID = 13
model = zarivka
position = (first pushed float, -second pushed float,
            cell.ceiling - 0.055)
```

`0x00D5CFE8`:

```text
EDX false -> model ID 130, bakelit
EDX true  -> model ID 131, bakelit_dmg
position = (first pushed float, -second pushed float,
            cell.ceiling - 0.1)
```

Recognized EDX forms:

```text
xor edx,edx / xor edx,edx equivalent -> false
mov dl,imm8                            -> imm8 != 0
mov edx,imm32                          -> imm32 != 0
```

The coordinate push order was experimentally verified. Do not swap it based on
the callee's internal Delphi parameter offsets. In map 1, the two lamps near
ladder model 517 instance 1 are authored near `(75,60)` and `(78,60)`.

Map 1 contains 23 calls to the fluorescent helper and 26 calls to the bakelite
helper. `lampazed.3DS` (static model ID 9) and `zemekoule.3DS` (ID 66) were
investigated but are not the repeated ceiling fixtures in this level.

### Additional specialized lamps

The adjacent helper family was verified visually and recovers several more
real fixture placements:

| Helper | Model | Placement |
|---:|---|---|
| `0x00D5CDF4` | ID 1, `lampa` | floor at `(x,z)` |
| `0x00D5CE0C` | ID 234, `lampa4`; CL true selects ID 337, `lampa4_one` | floor at `(x,z)`, EDX supplies yaw |
| `0x00D5CF20` | ID 8, `lampa2` | floor plus pushed vertical offset, EDX supplies yaw |
| `0x00D5D08C` | ID 12, `lustr` | ceiling minus `0.21` and the pushed drop distance |
| `0x00D5D120` | ID 331, `lustr2` | ceiling minus `0.7` |

`lampa4` is a composite constructor in HROT. It creates the post body and one
or two separate ID 235 `lampa4_bulp` children using transforms derived from
the body's orientation. The mount currently emits the correct one/two-arm body
and places point lights at the decoded child-bulb transforms:

```text
lampa4:     local lateral offsets -0.65 and +0.65, vertical +2.67
lampa4_one: local lateral offset  -0.65, vertical +2.67
```

The separate bulb child meshes are not yet reproduced.

### Doors (`0x00D77C20`)

Level constructors register doors and breakable walls with:

```text
mov cl, orientation
mov dl, behavior
mov eax, owner_pointer
push ... (17 stack args)
call 0x00D77C20
```

`ret 0x44` confirms seventeen 32-bit stack arguments. Records are `0x7C` bytes
in the array at `0x17D40C8`.

| Args | Record field | Meaning |
|---|---:|---|
| 0, 1, 2 | `+0x00` Vec3 | closed position `(X, vertical, Z)`; `+0.5` added to X and Z |
| 3, 4, 5 | `+0x30` Vec3 | travel vector |
| 7, 8 | `+0x64/+0x68` | front atlas `(X 0..31, Y 1..16)` |
| 9, 10 | `+0x6c/+0x70` | back atlas |
| 11 | linked flag | pairs two leaves; see below |
| 16 | `+0x78` (word) | tag/targetname |

Door geometry, shape, thickness and linkage:

- **`+0x5C` is the shape** (not `+0x5D`, which is the incoming `CL` and reads `3`
  on every door). `D77C20` derives it as `travelX == 0`, and constructors
  overwrite it right after the call (`MOV byte [reg+reg*4+0x5C], imm8`) -
  including with `2`, a value the derivation never produces.
- **The draw is `0x00D88A6C`**, called from a loop at `0x00D8C016` inside the
  world renderer that walks the door array (`0x17D413D`, stride `0x7C`) gated on
  `door+0x75`. No field of the door record is read by any vertex-emitting code
  except through this draw. It takes the front atlas in `EAX`/`EDX`, the back in
  `ECX`/`[ebp+0x10]`, the animated position (record `+0x0C`/`+0x10`/`+0x14`), and
  the shape byte, and dispatches on `+0x5C`:

  | `+0x5C` | Geometry (`H = 1.5625`, `W` = half-thickness) |
  |---:|---|
  | 0 | box on the `Dz` axis: faces at `Dz±W` spanning `Dx±0.5`, `Dy..Dy+H`, plus two edge quads. 16 vertices. |
  | 1 | the same box on the `Dx` axis (faces at `Dx±W`). 16 vertices. |
  | 2 | a `0.35 x 0.35` square post: four side faces plus a horizontal cap at `Dy+H` through the stair-tread emitter `0xD881AC`, atlas `(31, 2)`. |

  Doors sample **wall** tiles (1/32 across, 1/16 down, same inset) and emit
  vertices as `(Dz.., Dy.., Dx..)`, so `PanelToWorld` applies. The edge quads on
  shapes 0/1 use a hardcoded tile (column 2, row 7). `W` is set by `0x00D77FA0`
  to `0.25` when `+0x58 == 1000` and `0.026` otherwise, but `+0x58` is transient
  and reads 0 on a running map, so every leaf renders thin. HROT's own door
  **speed** is not decoded.
- **Linked pairs have a leader and a follower.** `D77C20` alternates a global
  toggle at `0x17D51CD`, so within each linked pair the first created leads and
  the second follows; `+0x74` holds the partner's index and the follower's
  `+0x54` is set to `-1`. Verified 8/8 against live memory.
- **Doors are decoded by `TryReadCallInstances`** (shared with glass panels),
  which handles call sites whose arguments are computed in a register or a loop
  as well as literal pushes: 217 call sites yield 230 doors across the eight
  tooled maps.

Doors are spawned as individual GameObjects with their own meshes, tagged
`hrot_door`, `hrot_door_leader`/`hrot_door_follower` and
`hrot_door_partner_NN`.

### Wall signs: decals (`0x00D4D500`) and subtitle triggers (`0x00D98380`)

The signs on HROT's walls are **two unrelated systems** that happen to be
authored at the same place. Both are decoded and spawned by `HrotMap.Signs.cs`;
this section is the decode reference behind it.

**The text is not drawn by the game.** It is painted into a 512x512 decal sheet
and the sign is a quad showing a rectangle of it. `chars.tga` is a real glyph
atlas - HUD icons, an embossed font with Czech capitals, and a pixel font - but
it serves the HUD and subtitles, not walls. Anyone starting from "HROT writes
this text at runtime" will look for a glyph renderer that does not exist.

#### The visible sign

```text
push x0, y0, x1, y1        (rectangle in sheet pixels)
push cellX, cellZ, y, scale
mov dl, facing
call 0x00D4D500
```

Records are `0x28` bytes in the array at `0x17D65E4`.

| Record | Meaning |
|---|---|
| `+0x00` | in-use flag |
| `+0x01` | facing, `0..3` |
| `+0x04`, `+0x08` | cell Z, cell X - the builder adds `0.5` to centre them |
| `+0x0C` | vertical position; the builder adds `0.5` |
| `+0x10` | **half** width `= (x1-x0) * 0.003774 * scale` |
| `+0x14` | **half** height `= (y1-y0) * -0.004100 * scale`, **negative** |
| `+0x18`..`+0x24` | UV rect: `pixel/512`, half-texel inset `0.5/512`, V flipped - see below |

The two size constants are 80-bit extended floats at `0xD4D668` and `0xD4D674`.
The height one is negative because the sheet's V axis runs opposite to world up.

**Both are half-extents.** The emitter is `0xD89B5C`, called from the decal loop
at `0xD8C1A8`, and all four of its facing branches build the quad as
`centre +/- [+0x10]` by `centre +/- [+0x14]`, so halving them again draws the
sign at half size.

**Do not port the V flip.** `D4D500` stores `1 - v/512` because HROT uploads a
bottom-origin image straight to GL. s&box samples from the top left, so applying
the flip reads a different band of the sheet and the sign renders as fragments
of whatever signs live there. The rectangles are plain image-space coordinates:
cropping `vyzdoba.jpg` at `(x0,y0)-(x1,y1)` with any image tool shows the sign,
and that is what the mount should sample.

This is the third time this project has shipped a value that compensated for a
host convention, after the OpenGL texture origin and HROT's axis order.

Facing is an **axis enum, not a rotation**: `0` and `1` are the two Z-facing
walls, `2` and `3` the two X-facing. Confirmed twice over - by writing the byte
live (`1 -> 2` turned the sign 90 degrees right, `1 -> 3` turned it 90 degrees
left, so 2 and 3 are opposite) and by the trigger boxes below, whose thin axis
agrees with the facing on all 11 of map 1's decals.

Map 1 uses `vyzdoba.jpg` for every decal. **Which sheet other maps use is not
known**; `vyzdoba2.jpg` and `nadrazni.jpg` exist and are the obvious candidates.
It is also unconfirmed whether this helper places only signs - it looks like a
general wall-decal system, so posters and stains may come through it too.

#### The English subtitle

Separately, `0x00D98380` records a proximity box that shows the translation
while the player stands near it. `ret 0x1C`; records are `0x20` bytes at
`0x17D3CFC`, with a **signed byte** count at `0x17D3F9C` (so at most 128).

| Record | Meaning |
|---|---|
| `+0x00` | centre `(x, y, z)`, built through the `0x4613F4` vector constructor |
| `+0x0C`, `+0x10`, `+0x14` | half-extents X, Y, Z - one is always thin: the wall normal |
| `+0x18` | unidentified; integral, seen as 2,3,4,5,6,7,8,10 |
| `+0x1C` | string id (word), through `GetString` at `0xDA9FD8` |

83 boxes across the seven mapped constructors. This table drives **only** the
subtitle: moving a record in live memory stopped the subtitle triggering and
left the sign itself untouched, which is what proved the two systems apart.

The id is the **English** string. There is no fixed offset to the Czech text
painted on the sheet - `458` pairs with `1083`, but `+625` does not hold
generally, and the painted text is pixels anyway, so nothing needs the pairing.

#### Coverage: 121 decals against 184 boxes

`Tools/dump_signs.py` finds **121 decals and 184 subtitle boxes** across the 32
map constructors. Map 1, the one verified in every other way, has 11 and 16.

**The difference is not a shortfall.** A subtitle box does not imply a decal,
because plenty of HROT's readable signs are ordinary scenery: painted into the
wall atlas, or carried by a prop model. Those need no decal record and the mount
already draws them - checked in the mount for map 1's five decal-less boxes, all
of which are on the wall today, against the eleven decal-backed ones which are
all missing. The split holds in both directions, which is stronger than the
counts matching would have been.

So the two systems cover different things:

- `0x00D98380` describes **every** readable sign, however it is drawn.
- `0x00D4D500` describes only those needing their own quad.

The decoder is not dropping anything either: every `0x00D4D500` site had all
eight arguments as literal pushes, and both `dump_signs.py` and `ReadDecals`
count a site they cannot read rather than passing over it.

`dump_signs.py` parses `HrotExecutableProps.Constructors` out of the C#, the way
`hrot_world_ranges.py` parses the world ranges, so its map coverage cannot drift
from the mount's - a transcribed copy of the constructor table once listed seven
maps while the mount had thirty-two, reporting a slice of the game as all of it.

Model `804` shows up at six decal-less boxes and almost nowhere else, so it is
probably a dedicated sign prop; the existing prop pass already places it.

#### Verification

- All 11 of map 1's decal rectangles, cut from `vyzdoba.jpg`, read as exactly
  the sign the paired subtitle trigger translates.
- Computed decal half-heights match the trigger half-extents within 0.02 on all
  11, from two tables built by different helpers. **This agreement is what
  identified `+0x10`/`+0x14` as half-extents**, and it was originally recorded
  here as confirming the sizes - a full size matching a half-extent is a
  factor-of-two error, not corroboration. Check that a cross-check compares like
  with like before counting it as agreement.
- Live reads agree with the static decode: 16 trigger records, 11 decals.
- In the mount, map 1's 5 decal-less boxes are all already on the wall and its
  11 decal-backed ones are all absent - which is what says the split between
  "needs a decal quad" and "already scenery" is real rather than a shortfall.

Two mistakes worth not repeating. `Image.sweep` decodes at four alignments and
its docstring says to de-duplicate by address; not doing so inflated every count
by exactly 4x, and "332 signs" survived several minutes of being believed
because it was plausible. And an English/Czech string offset was inferred from a
single corroborating pair, which is the failure this document's own history
keeps repeating.

### Player start (`0x00DBE4AC` and inline)

The player object lives behind the pointer at `0xDE7C74`; its position is fields
`+0x04`, `+0x08` and `+0x0C`. Constructors set the start two ways, and **both
have to be read** - only maps 0, 1, 2 and 101 use the call, so decoding that
alone leaves 28 levels with no spawn.

```text
inline, most maps:
    mov eax, [0xDE7C74] ; mov [eax+4],  x
    mov eax, [0xDE7C74] ; mov [eax+8],  vertical
    mov eax, [0xDE7C74] ; mov [eax+0xC], z
    push yaw ; call 0x004A326C

through the helper:
    push x, vertical, z ; mov eax, facing ; call 0x00DBE4AC
```

`D4D500`-style half-cell centring applies to the call form only: `DBE4AC` adds
`0.5` (at `0xDBE558`) to X and Z, while the inline values already include it.
The facing is a float pushed to the angle setter at `0x004A326C`, or in the call
form an index into the four-entry table at `0xDBE4F0`.

Three things that each looked like data rather than a decoder gap:

- **A zero vertical is not an immediate.** The compiler emits
  `xor edx, edx` then `mov [eax+8], edx`, two bytes shorter than
  `mov [eax+8], imm32`. Walking a fixed stride skips those maps entirely - ten
  of the thirty-two - and the result reads as "these levels have no start".
- **Read the angle call, then its push.** Scanning forward for the first `push`
  after the position found an unrelated `push 1.25` on map 4 and reported it as
  a facing. Every real value is one of `-89.99, 90.01, 0.01, 179.99`; HROT never
  authors an exact axis angle, so anything else is a misread.
- **The yaw needs a quarter turn for s&box.** HROT's zero does not point where
  s&box's does; ported unchanged the player looks 90 degrees right of where the
  level intends. `HrotMap.PlayerStartYawOffset` applies it at spawn time so the
  decoder keeps reporting HROT's own angle.

All 32 maps decode. Map 100 is authored at `(90.5, -90.5, 90.5)` with no angle
call at all - odd, but that is what the executable holds.

### Sounds and the props that emit them

HROT ships 423 WAVs in the PAK root, all plain RIFF/WAVE - mono and stereo, 8
and 16 bit, 22050/44100/48000 Hz. `SoundFile.FromWav` takes all of them
unconverted. None carries a `smpl` loop chunk and there is no `ambience/`
directory to key off, so **nothing in the files says what loops**.

Each is registered once, giving an id the rest of the executable uses:

```text
mov edx, <"name.wav"> ; mov eax, <id> ; call 0x00DCAF38
```

419 registrations over ids 1..427. Id 354 is registered twice - `babicka_dead`
then `hadr1` - and `dump_sounds.py` reports that rather than silently keeping
the last.

#### Finding what plays them

HROT loads OpenAL dynamically, so nothing shows in the import table. The route
in is the name strings:

```text
"alSource3f" etc -> function pointer globals (0xE621F8, 0xE62218, ...)
                 -> one loader at 0x4D1964
                 -> its only caller, audio init at 0xDCAE68
                 -> which clears 13 channels of 12 bytes at 0x18D5820
```

That channel table is readable live and is the fastest way to see what is
sounding right now: the first dword of each slot is a sound id, `-1` when idle.
Standing by a distribution box, slot 0 held 332 (`vn.wav`) across every sample -
stable means looping, transient means one-shot.

#### Positional sound is code, not data

There are no emitter entities. A prop's update case calls

```text
0xDCF7A4( eax = soundId, push gain, near, far, distance )
    distance >= far  -> silent
    distance <  near -> full volume
    else                (far - distance) / (far - near)
```

every frame, so HROT does its own linear attenuation rather than using OpenAL's
3D positioning. Which prop plays what comes from the update switch, in Delphi's
usual two-level form keyed on the **model id**:

```text
movzx eax, word [ebx-0x70]        ; model id
mov   al,  byte [eax + 0xD6E7D3]  ; model -> case index
jmp   dword [eax*4 + 0xD6EB2C]    ; case -> code
```

87 models reach a case that plays a sound; 78 of those pass their radii as
constants and are the ones the mount spawns. The other 10 - `ohen.wav` for fire,
`motor.wav` for machinery - compute the distance at runtime and are left silent
rather than given an invented radius.

`0xDCF7A4` hands `PlaySound` **two** scalars - `push ratio`, `push gain` - so
the final volume is `gain * ratio`. In the mount `Volume` carries the gain and
`SoundEvent.Falloff` carries the ratio.

**Set the falloff curve explicitly.** `SoundEvent` defaults to a steep
near-field curve - `0.22` at a twentieth of the distance, `0.04` at a fifth -
which suits its `15000` unit default radius and is wildly wrong for a prop
audible over `384`: it leaves a `rozvadec` at one metre at `0.014` where HROT
plays `0.300`.

HROT's shape is flat at full volume within `Near`, then straight to silence at
`Far`, so the ported curve uses `Curve.HandleMode.Linear` frames. Do **not**
write it with tangents: a frame's `In` is negated on evaluation
(`it = frameB.In * -1`), so the falling segment given its own slope at both
ends eases into an S - correct at both endpoints, wrong everywhere between.
That is the same class of error as the five host-convention entries in
`CLAUDE.md`.

The result reads as obviously right, which is the point: `zarivka` buzzes,
`umyvadlo` runs water, `metro`/`vagon1`/`bobina` are trains, `stozar` is a
pylon, and all three `rozvadec` variants plus the damaged one share a mains hum
at far 6, near 2, gain 0.3.

#### Background music: three layers, set per map

**Music is not one track per map.** HROT runs three looping layers at once and
crossfades them on independent gains, which is why `mus_9` and `mus_9_a` are
parts of one cue rather than alternates, and why several maps name the same
`_a` track in two slots.

Each map's **prop constructor** points four globals at a sound id:

```text
mov eax, dword ptr [0x00DE7C38]
mov dword ptr [eax], 0x150        ; 336 = mus_21
```

| Global | Role |
|---:|---|
| `0x00DE7C38` | layer 1 - the track a quiet level plays |
| `0x00DE7C90` | layer 2 |
| `0x00DE7EA4` | layer 3 |
| `0x00DE7FC8` | intermission (`mus_inter*` only) |

The mixer at `0x00DCB721` plays each layer whose gain is above zero:

```text
fld   dword ptr [ebx + 0x430]     ; layer gain
fcomp dword ptr [0x00DCB92C]      ; 0.0
jbe   next
push  dword ptr [ebx + 0x430]
push  0x3F800000
mov   eax, dword ptr [0x00DE7C38]
mov   eax, dword ptr [eax]        ; the sound id
mov   dl, 1                       ; looping
call  0x00DCF710
```

Three such blocks sit in a row, with gains at `+0x430`, `+0x438` and `+0x440`
and flags at `+0x42C`/`+0x434` selecting which layer is active. The mount
spawns **layer 1 only**: nothing here has the state the others fade in on.

31 of the 32 maps set a layer 1. Map 100 is the hub and sets only the
intermission slot.

##### Why the earlier searches missed it

The four bullets this section used to carry were each true and each pointed
away from the answer. The decisive one was wrong in a specific way worth
keeping:

- "**Not an id in the constructors**" was right that every `mov ax, <music id>`
  hit is a prop placer where `ax` is the *model* id - and wrong that this
  cleared the constructors. The store is a **dword through a pointer**, not an
  immediate into a register, so no search shaped around registers could see it.
- "**Not through the core play function**" was right that none of `0xDCF710`'s
  19 callers *names* a music id, and that is exactly the tell: the caller at
  `0x00DCB743` loads one from a global instead. A search for constants cannot
  find a call whose argument is a variable, and its absence was the evidence.

The route in was to stop looking for the id and look for the *reader*: of the
19 callers of `0xDCF710`, exactly one takes its sound id from memory and passes
`dl = 1`.

##### Verification

- The reader is confirmed: all three layer globals are read in one function,
  each feeding a looping play call gated on its own gain.
- The control scan is clean. Across the whole image there are 85 writes to
  these four globals and 84 are `mus_*` tracks. The single exception is
  `disko2.wav`, on Strahov Stadium's layer 2 - a diegetic disco, so a real
  music cue rather than a false positive.
- The byte walk in `HrotExecutableSounds.ReadMapMusic` and a Capstone decode of
  the same ranges agree on all 32 maps (`dump_music.py --verify`).
- Map 1 decodes to `mus_21`, which is what `dump_live_channels.py` observed
  live in channel slot 5.

**Still outstanding: a live check on a map that is not map 1.** The decode
predicts `mus_23` on map 5 and `mus_9` on map 14. Everything above is static
plus one live observation on the single map this project has always tested
against, which is the exact shape of the player-start yaw mistake.

#### Two traps

**A sound id is not a search key.** Ids run 1..427, inside the static-model
range and inside nearly every flag and count a constructor passes, so "this
register holds a valid sound id" matches almost anything. The fourth argument of
`RegisterModel` is one such false match - it is the **damaged model** id (181
`rozvadec` names 200 `rozvadec_dmg`, which is also `1khz.wav`, a plausible hum),
not a sound. Anchor on something outside the numbers - the running game, or a
sound someone has actually heard.

**A runtime SoundEvent needs embedding.** `SoundEvent` is a `GameResource` and
serializes as its `ResourcePath`; one built in code has none, so it writes out
null and the scene reloads with emitters that look correct in the inspector and
make no sound. Set `EmbeddedResource` and it is written into the scene instead:

```csharp
soundEvent.EmbeddedResource =
    new Sandbox.Resources.EmbeddedResource { ResourceCompiler = "embed" };
```

`QuakeMap.Sounds.cs` already did this. Read the neighbouring mount before
inventing a way around the engine.

### Triggers and moving volumes

Not yet decoded into the mount, but the reconnaissance is done. Triggers are
**static map data**, attached to the prop just placed by a call immediately after
the placement helper:

```text
0x00DBE688( al = type, edx = param, ecx = param2 )
    -> writes a 12-byte record { byte type, dword param, dword param2 }
       at 0x18CD8D0 + counter*0x78, counter at [0xDE7EC8]
```

The executor `0x00D7A31C` copies that record into locals and dispatches on the
type through the jump table at `0x00D7A392` (90 types). Identified: type 1 is the
door dispatch, type 5 a **volume toggle**, type 9 a **volume raise/lower** -
`param` is a volume index bounds-checked to 1..6. **376 trigger attachments
across 25 maps**, all readable without the game; `Tools/dump_triggers.py` reads
them.

Elevators and rising water are the **same** moving-volume system (11.9): the
per-frame update `0x00D78654` writes a cell's floor height from its volume's
level, and the record's `enable_solid` byte at `+0x1D` separates a solid
elevator floor from water. The seeder at `0xD5DD16` puts the elevator sounds
`vytahstart`/`vytah`/`vytahstop` and `voda` in the records. What a trigger record
does **not** carry is which cells belong to a volume - triggers reference volumes
by index only, so the `0x19` cell assignment (11.9) is still unsourced.

## 13. Lighting

Recovered static fixture models are given approximate s&box point lights.
Fixture-name matching currently includes:

```text
lampa, zariv, bakelit, reflektor, light, lustr, blikack,
svicka, svicen, louc, lampice
```

Names containing `dmg`, `zhas`, or `off` are treated as inactive.

Fixture-specific light offsets:

```text
zariv*, bakelit* = -0.2 from model origin
lampa2           = +0.49 (decoded bulb transform)
lampa4*          = +2.67 (decoded bulb transform)
lustr*           = model origin
other fixtures   = +0.25 approximation
```

Current point-light approximation:

```text
color       = (1.0, 0.78, 0.52) * 2.5
radius      = 7 * 64
attenuation = 1.2
shadows     = false
fog         = 0.35
```

If no real fixture is recovered, the map creates up to 48 sparse fallback
lights. A directional sun and ambient light are always added. These parameters
are visual approximations, not reverse-engineered originals.

### Outdoor floors

Outdoor cells legitimately have a floor without a ceiling. The initialized
cell record still contains a placeholder ceiling height of `1.5625`, which
must not participate in floor validation unless `HasCeiling` is set (or a
ceiling has deliberately been inferred). Comparing an elevated outdoor floor
against that placeholder discarded the entire surface whenever:

```text
floor height >= 1.5625
```

This was verified at the map-1 outdoor rocket area around model 283
`info_raketa`, whose platform floor is at height `3.125`.

## 14. Known heuristic/hacky behavior

These must not be mistaken for decoded game behaviour:

- **Fixture point-light colours and radii are invented.** Nothing about the
  lighting in section 13 is reverse-engineered.
- **Thin 3DS meshes are made double-sided by a bounding-box heuristic.**
- **`IsRealCell` substitutes for cell field `0x01`**, which nothing in the map
  data writes. It reproduces the real field exactly on 30603 cells across three
  maps, but it is a stand-in rather than a port - see section 11.5.

Several entries that used to sit in this list - inferred ceilings, covered-ramp
transparent panels, derived floor and ceiling risers - are gone, because the
code implementing them was deleted with the inferred renderer. Risers are now
ported from HROT's own derive pass and verified against it.

When a new visual mismatch appears, first determine whether the source field or
placement helper is still undecoded, and whether the *decoder* is silently
dropping records rather than the renderer drawing them wrongly. That distinction
accounted for most of the door and panel bugs found so far. Avoid adding a
per-instance correction until coordinate order, cell indexing, helper semantics
and model origin have all been checked.

## 15. Useful investigation workflow

1. Reproduce on one named scene and identify the scene object's model ID and
   per-model instance number.
2. Find the model registration in `HROT.exe` or through
   `HrotExecutableStaticModels`.
3. Disassemble the relevant prop-constructor range with 32-bit Capstone.
4. Locate the model ID or specialized helper call.
5. Print roughly 10-20 preceding instructions.
6. Decode arguments in original push order.
7. Compare against nearby known props and the grid cell's floor/ceiling.
8. Implement the helper generally if it repeats; do not map one instance.
9. Build serially with the command in section 2.
10. Reload the generated scene and inspect the mount log.

For grid fields, run:

```powershell
python engine/Mounting/Sandbox.Mounting.HROT/Tools/hrot_map_probe.py `
  D:\SteamLibrary\steamapps\common\HROT\HROT.exe 1 map1_fields.png
```

The probe requires `capstone`, `pefile`, and Pillow.

### Reading atlas tiles directly

When a surface has the wrong texture, crop the tile out of `pack1.jpg` and look
at it rather than reasoning about which atlas coordinate "should" be right. Wall
tiles are 64x128 with X zero-based and Y one-based, so tile `(X, Y)` is the
pixel box:

```text
(X * 64, (Y - 1) * 128, X * 64 + 64, (Y - 1) * 128 + 128)
```

Floor/ceiling tiles are 64x64 and use `(Y - 1) * 64` instead. A shipped copy
lives at `HROT/re/out/pack1.jpg`. Cropping a handful of candidates into one
labelled contact sheet resolves these questions immediately: it is how map 1
`door_16` was settled, showing that `(17,6)` is a plaster tile with a dark band
across its top (the beam) while `(24,3)` is vertical wood planks, which proved
the fault was the sampled UV range rather than the chosen material.

Cross-checking against a screenshot of the same spot in real HROT is worth the
detour whenever "wrong texture" could equally mean "wrong tile" or "right tile,
wrong slice".

## 16. Highest-value next work

1. **Look at the maps nobody has opened.** The mount builds 32 levels;
   everything verified so far is maps 1, 2 and 5. Maps 6-29 and 100-104 have
   never been inspected.
2. **Decode the trigger/entity system.** It drives the moving-volume system
   (cell field `0x19`) behind elevators and rising water - see section 11.9 -
   and would also cover pickups and scripted objects.
3. **Finish the decoder gaps**: 5 glass-panel and 25 prop call sites still
   unread; the props need stack-slot tracking rather than pattern matching.
4. **Drive the second and third music layers.** Which track each map loads is
   decoded (section 12); what HROT crossfades them on is not. The gain fields
   are `ebx+0x430/+0x438/+0x440` off whatever `ebx` is in the mixer at
   `0x00DCB721`, and the flags at `+0x42C`/`+0x434` select between them.
5. Decode HROT's door speed, and map trigger type 1's `param` onto a door
   index so switch-operated doors are not left press-operated. The doors
   themselves now carry the engine's `Sandbox.Mapping.Door` and move.
6. Determine original per-fixture light colour/radius and damaged/off state.
7. Decode 3DS object matrices and per-face material groups if assets need them.
8. Identify map fields `+0x48/+0x58/+0x68/+0x78` and the remaining auxiliary
   wall header bytes.
