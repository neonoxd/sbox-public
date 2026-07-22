using Sandbox;
using System;
using System.Collections.Generic;
using System.Linq;

/// <summary>Builds a static s&amp;box scene from a HROT executable level.</summary>
/// <remarks>
/// Scene assembly: lighting, static props and their fixture lights, and the
/// scene's metadata. The other halves of this class are HrotMap.World.cs, which
/// builds the world surfaces, and HrotMap.Doors.cs, which spawns door leaves.
/// </remarks>
sealed partial class HrotMap( int mapId ) : SceneLoader<HrotMount>
{
	int MapId => mapId;

	// HROT's geometry is authored in metres; s&box world units are inches.
	const float UnitScale = 64.0f;

	const float TileInset = 0.25f / 2048.0f;

	protected override void BuildScene()
	{
		var grid = Host.GetMapGrid( mapId );
		if ( grid is null )
		{
			Log.Warning( $"HROT map {mapId} could not be reconstructed." );
			return;
		}

		// A missing world model must not abort the rest of the scene - lighting,
		// props and doors are still worth having, and an empty scene is far
		// less informative about what went wrong.
		var model = BuildWorldModel( grid );
		if ( model is not null )
		{
			var world = new GameObject( true, $"hrot_map_{mapId:00}_world" );
			world.AddComponent<ModelRenderer>().Model = model;

			var collider = world.AddComponent<ModelCollider>();
			collider.Model = model;
			collider.Static = true;
		}

		AddSceneInformation();
		AddLighting();
		var doorLeaves = SpawnDoors();
		if ( doorLeaves > 0 )
			Log.Info( $"HROT map {mapId} spawned {doorLeaves} door leaves." );

		SpawnPlayerStart();
		SpawnMusic();

		var signs = SpawnSigns();
		if ( signs > 0 )
			Log.Info( $"HROT map {MapId} spawned {signs} signs." );

		var fixtureLights = SpawnStaticProps( grid );
		if ( soundEmitters > 0 || soundEmittersFailed > 0 )
		{
			Log.Info(
				$"HROT map {mapId} gave {soundEmitters} prop(s) a looping sound"
				+ (soundEmittersFailed > 0
					? $"; {soundEmittersFailed} could not resolve their sound file."
					: "." ) );
		}
		else
		{
			Log.Warning( $"HROT map {mapId} placed no sound emitters." );
		}
		Log.Info( $"HROT map {mapId} attached lights to {fixtureLights} real fixture placements." );
		if ( fixtureLights == 0 )
		{
			Log.Warning( $"HROT map {mapId} found no active light fixtures; using fallback lights." );
			SpawnFallbackPointLights( grid );
		}
	}

	/// <summary>Names the scene, so levels are identifiable in the editor.</summary>
	void AddSceneInformation()
	{
		var go = new GameObject( true, "scene information" );
		var info = go.AddComponent<SceneInformation>();
		info.Title = Host.GetMapName( mapId );
		info.Group = "HROT";
		info.Description = $"HROT map {mapId:00}.";
	}

	static void AddLighting()
	{
		var sunObject = new GameObject( true, "sun" );
		sunObject.WorldRotation = Rotation.From( 55.0f, -35.0f, 0.0f );
		var sun = sunObject.AddComponent<DirectionalLight>();
		sun.LightColor = new Color( 1.15f, 1.08f, 0.95f );
		sun.Shadows = true;
		sun.ShadowCascadeCount = 3;
		sun.ContactShadows = true;

		var ambientObject = new GameObject( true, "ambient" );
		var ambient = ambientObject.AddComponent<AmbientLight>();
		ambient.Color = new Color( 0.22f, 0.25f, 0.30f );
	}

	int SpawnStaticProps( HrotMapGrid grid )
	{
		var placements = Host.GetMapProps( mapId, grid );
		var models = new Dictionary<int, Model>();
		var instanceCounts = new Dictionary<int, int>();
		var fixtureLights = 0;

		foreach ( var placement in placements )
		{
			if ( !models.TryGetValue( placement.ModelId, out var model ) )
			{
				var path = Host.FindStaticModelPath( placement.ModelId );
				model = path is null ? null : Model.Load( $"mount://{Host.Ident}/{path}.vmdl" );
				models[placement.ModelId] = model;
			}

			if ( model is null || model == Model.Error )
				continue;

			var modelName = Host.GetStaticModelName( placement.ModelId );
			instanceCounts.TryGetValue( placement.ModelId, out var instance );
			instanceCounts[placement.ModelId] = ++instance;

			var prop = new GameObject(
				true,
				$"prop_{modelName} (model {placement.ModelId} #{instance})" );
			prop.WorldPosition = placement.Position * UnitScale;
			prop.WorldRotation = Rotation.FromYaw(
				placement.Yaw + Host.GetStaticModelYawOffset( placement.ModelId ) );
			prop.WorldScale = placement.Scale;
			prop.AddComponent<ModelRenderer>().Model = model;

			var collider = prop.AddComponent<ModelCollider>();
			collider.Model = model;
			collider.Static = true;

			if ( LadderModels.Contains( placement.ModelId ) )
				MakeClimbable( prop, model );

			if ( Host.GetStaticModelSound( placement.ModelId ) is { } ambience )
				MakeSoundEmitter( prop, ambience );


			if ( IsLitFixture( placement.ModelId, modelName ) )
			{
				fixtureLights += AddFixtureLights(
					placement.ModelId, modelName, instance, prop );
			}
		}

		return fixtureLights;
	}

	/// <summary>
	/// Turns HROT's yaw into s&amp;box's. See <see cref="SpawnPlayerStart"/>.
	/// </summary>
	const float PlayerStartYawOffset = 90.0f;

	/// <summary>
	/// Places a <see cref="SpawnPoint"/> where HROT starts the player.
	/// </summary>
	/// <remarks>
	/// The decoded position is the player's own origin in HROT, which is not
	/// necessarily where s&amp;box wants a spawn point to sit - if players start
	/// buried or floating, this is the thing to offset, not the decode.
	/// </remarks>
	void SpawnPlayerStart()
	{
		var spawn = Host.GetMapPlayerSpawn( MapId );
		if ( spawn is not { } start )
		{
			// A map with no spawn point looks fine until someone presses play
			// and falls out of the world, so it is worth a warning.
			Log.Warning( $"HROT map {MapId:00}: no player start was decoded." );
			return;
		}

		var go = new GameObject( true, $"hrot_player_start_{MapId:00}" );
		go.WorldPosition = new Vector3(
			start.Position.x, -start.Position.z, start.Position.y ) * UnitScale;

		// The quarter turn is applied here rather than in the decoder, which
		// keeps reporting HROT's own angle. Same shape as the sign V flip and
		// the sign's vertical axis: HROT's zero yaw does not point where
		// s&box's does, and porting the number unchanged left the player
		// looking 90 degrees right of where the level intends.
		go.WorldRotation = Rotation.FromYaw( start.Yaw + PlayerStartYawOffset );
		go.Tags.Add( "spawnpoint" );
		go.AddComponent<SpawnPoint>();

		Log.Info(
			$"HROT map {MapId} player starts at {go.WorldPosition} "
			+ $"facing {start.Yaw:0.##}." );
	}

	/// <summary>Starts the map's background music.</summary>
	/// <remarks>
	/// HROT runs three looping layers at once and crossfades them on gains the
	/// mount has no equivalent for - there is no combat state here to fade the
	/// second and third in on. So only layer 1 is spawned, which is what plays
	/// on a quiet level anyway: standing in map 1, HROT held <c>mus_21</c> and
	/// nothing else.
	///
	/// Non-positional, unlike the prop emitters: this is the level's score, not
	/// something in the world.
	/// </remarks>
	void SpawnMusic()
	{
		if ( Host.GetMapMusic( MapId ) is not { } music || music.Layer1 == 0 )
		{
			// Map 100 is the hub and sets only the intermission slot, so this is
			// not necessarily a decode failure.
			Log.Info( $"HROT map {MapId} sets no background music track." );
			return;
		}

		var name = Host.GetSoundName( music.Layer1 );
		if ( string.IsNullOrEmpty( name ) )
		{
			Log.Warning(
				$"HROT map {MapId} music id {music.Layer1} is not a registered sound." );
			return;
		}

		var file = SoundFile.Load( Host.GetSoundPath( name ) );
		if ( file is null )
		{
			Log.Warning( $"HROT map {MapId} could not load music \"{name}\"." );
			return;
		}

		var soundEvent = new SoundEvent
		{
			Sounds = [file],
			Volume = 0.33f,

			// The mixer passes gain 1.0 and lets the layer gain do the work, and
			// distance never enters it - music is not a point in the world.
			DistanceAttenuation = false,
			OcclusionEnabled = false,
			ReverbEnabled = false,
		};

		// Same reason as the prop emitters: a runtime SoundEvent has no
		// ResourcePath, so without embedding it serializes as null and the scene
		// reloads silent while still looking correct in the inspector.
		soundEvent.EmbeddedResource =
			new Sandbox.Resources.EmbeddedResource { ResourceCompiler = "embed" };

		var go = new GameObject( true, $"hrot_music ({name})" );
		var emitter = go.AddComponent<SoundPointComponent>();
		emitter.SoundEvent = soundEvent;
		emitter.PlayOnStart = true;
		emitter.TargetMixer = "Music";

		// Restarted rather than looped, for the reason the prop emitters are:
		// HROT's WAVs carry no loop points and SoundFile is cached per path, so
		// marking one to loop would loop every other use of the same file.
		emitter.Repeat = true;
		emitter.MinRepeatTime = 0.0f;
		emitter.MaxRepeatTime = 0.0f;

		go.Tags.Add( "hrot_music" );

		Log.Info( $"HROT map {MapId} plays \"{name}\" (id {music.Layer1})." );
	}

	/// <summary>
	/// Gives a prop the looping sound HROT plays from its update case.
	/// </summary>
	/// <remarks>
	/// HROT has no emitter entities: the prop's own update calls an attenuated
	/// play function every frame, recomputing volume from the player's
	/// distance. The decode reproduces that as a <see cref="SoundPointComponent"/>
	/// with the same radius - <c>Far</c> is where HROT goes silent.
	///
	/// Its falloff is linear from <c>Near</c> to <c>Far</c> while s&amp;box's
	/// default curve is not, so the shape between the two is approximate; the
	/// audible radius and the point it disappears are exact.
	/// </remarks>
	int soundEmitters;
	int soundEmittersFailed;

	/// <summary>HROT's own distance falloff, as a s&amp;box curve.</summary>
	/// <remarks>
	/// <c>0xDCF7A4</c> is flat at full volume within <c>Near</c> and linear from
	/// there to silence at <c>Far</c>:
	///
	/// <code>
	/// distance &gt;= far   -&gt; 0
	/// distance &lt;  near  -&gt; 1
	/// else                 (far - distance) / (far - near)
	/// </code>
	///
	/// This has to be set explicitly. <see cref="SoundEvent"/> defaults to a
	/// steep near-field curve - <c>0.22</c> at a twentieth of the distance and
	/// <c>0.04</c> at a fifth - which suits its <c>15000</c> unit default
	/// radius and is wildly wrong for a prop audible over <c>384</c>.
	///
	/// Both segments are <see cref="Curve.HandleMode.Linear"/>, which is a plain
	/// lerp and matches HROT exactly. The tangent route does not: a frame's
	/// <c>In</c> is negated on evaluation (<c>it = frameB.In * -1</c>), so the
	/// falling segment written with the slope at both ends eases into an S
	/// instead of running straight - correct at both endpoints and wrong
	/// everywhere between.
	///
	/// A segment's interpolation comes from the frame it <i>starts</i> at, so
	/// the mode goes on the first two frames rather than the last.
	/// </remarks>
	static Curve HrotFalloff( HrotModelSound ambience )
	{
		var nearFraction = ambience.Far > 0.0f
			? Math.Clamp( ambience.Near / ambience.Far, 0.0f, 0.99f )
			: 0.0f;

		var full = new Curve.Frame( 0.0f, 1.0f ) { Mode = Curve.HandleMode.Linear };
		var silent = new Curve.Frame( 1.0f, 0.0f );

		// Two frames at the same time would divide by zero in the lerp, so a
		// sound with no flat region gets the falling segment alone.
		if ( nearFraction <= 0.0f )
			return new Curve( full, silent );

		var knee = new Curve.Frame( nearFraction, 1.0f ) { Mode = Curve.HandleMode.Linear };
		return new Curve( full, knee, silent );
	}

	void MakeSoundEmitter( GameObject prop, HrotModelSound ambience )
	{
		var path = Host.GetSoundPath( ambience.Sound );

		// Checked rather than assumed: a sound whose file did not resolve is
		// silent in a way that looks exactly like a decode producing nothing.
		var file = SoundFile.Load( path );
		if ( file is null )
		{
			soundEmittersFailed++;
			return;
		}

		var soundEvent = new SoundEvent
		{
			Sounds = [file],

			// 0xDCF7A4 computes a ratio and hands PlaySound both numbers:
			// push ratio, push gain. So the final volume is gain * ratio, and
			// Volume carries the gain while Falloff carries the ratio.
			Volume = ambience.Gain,
			DistanceAttenuation = true,

			// HROT goes silent at Far, so that is the audible radius.
			Distance = ambience.Far * UnitScale,
			Falloff = HrotFalloff( ambience ),
			OcclusionEnabled = false,
			ReverbEnabled = false,
		};

		// Without this the event serializes as its ResourcePath, which a
		// runtime-built resource does not have - so it writes out null and the
		// scene reloads with emitters that look right in the inspector and make
		// no sound. Embedding writes the event into the scene itself. The Quake
		// mount does the same thing for its ambient entities.
		soundEvent.EmbeddedResource =
			new Sandbox.Resources.EmbeddedResource { ResourceCompiler = "embed" };

		var emitter = prop.AddComponent<SoundPointComponent>();
		emitter.SoundEvent = soundEvent;
		emitter.PlayOnStart = true;

		// Mixers resolve by name, so this is safe even in a project that has
		// not defined one - it simply stays unrouted rather than failing.
		emitter.TargetMixer = "Game";

		// Restarted rather than looped: HROT's WAVs carry no loop points, and a
		// SoundFile is cached per path, so marking one to loop would also loop
		// every one-shot use of the same file elsewhere.
		emitter.Repeat = true;
		emitter.MinRepeatTime = 0.0f;
		emitter.MaxRepeatTime = 0.0f;

		prop.Tags.Add( "hrot_sound_emitter" );
		soundEmitters++;
	}

	/// <summary>
	/// The static models that are ladders - <c>zebrik</c> is Czech for ladder.
	/// </summary>
	/// <remarks>
	/// Recovered from the executable's registration table rather than guessed:
	/// these are every id whose registered model name begins <c>zebrik</c>.
	/// 85 placements across 24 maps.
	/// </remarks>
	static readonly HashSet<int> LadderModels = [517, 518, 556, 666];

	/// <summary>
	/// How far in front of a ladder its climb volume sits, in s&amp;box units.
	/// </summary>
	const float LadderVolumeOffset = 20.0f;

	/// <summary>
	/// Tags a ladder and gives it a climb volume standing off its face.
	/// </summary>
	/// <remarks>
	/// The volume is the model's own bounds pushed along the object's right,
	/// which is the direction a ladder faces at its authored yaw. Ladders are
	/// placed at 0, 90, -90, 180 and - on three of them - 45 degrees, so the
	/// offset has to follow the rotation rather than pick an axis.
	///
	/// It is a trigger. A solid box standing 20 units in front of every ladder
	/// would be a wall the player cannot walk through, which is not what a climb
	/// volume is for; the prop keeps its own ModelCollider for the actual
	/// geometry.
	/// </remarks>
	static void MakeClimbable( GameObject prop, Model model )
	{
		prop.Tags.Add( "ladder" );

		var volume = prop.AddComponent<BoxCollider>();
		volume.IsTrigger = true;

		var bounds = model.Bounds;
		volume.Scale = bounds.Size;

		// Center is local to the object, so the offset is a plain axis here and
		// the object's rotation carries it round to the ladder's facing.
		volume.Center = bounds.Center + Vector3.Right * LadderVolumeOffset;
	}

	static int AddFixtureLights(
		int modelId, string modelName, int instance, GameObject prop )
	{
		var baseName =
			$"light_{modelName} (model {modelId} #{instance})";

		if ( modelId is 234 or 337 )
		{
			// D5CE0C derives the bulb child transforms from the post body's
			// transform. The lateral axis is the model's local Y axis.
			var bulbOffsets = modelId == 337
				? new[] { -0.65f }
				: new[] { -0.65f, 0.65f };
			for ( var i = 0; i < bulbOffsets.Length; i++ )
			{
				var localOffset = new Vector3(
					0.0f, bulbOffsets[i] * UnitScale, 2.67f * UnitScale );
				AddPointLight(
					$"{baseName} bulb {i + 1}",
					prop.WorldPosition + prop.WorldRotation * localOffset );
			}
			return bulbOffsets.Length;
		}

		AddPointLight(
			baseName,
			prop.WorldPosition + Vector3.Up * UnitScale *
				GetFixtureLightOffset( modelName ) );
		return 1;
	}

	static bool IsLitFixture( int modelId, string modelName )
	{
		// These IDs are emitted by decoded HROT light constructors. Prefer
		// their actual semantic role over filename heuristics.
		if ( modelId is 1 or 8 or 12 or 13 or 130 or 234 or 295 or 331 or 337 )
			return true;

		if ( string.IsNullOrWhiteSpace( modelName ) )
			return false;

		var name = modelName.ToLowerInvariant();
		if ( name.Contains( "dmg" ) || name.Contains( "zhas" ) || name.Contains( "off" ) )
			return false;

		// HROT uses several Czech fixture names that do not contain "lamp".
		// These are real placed models recovered from the executable; failing
		// to classify e.g. blikacka made the map incorrectly fall back to a
		// synthetic grid of point lights despite having genuine fixtures.
		return name.Contains( "lampa" ) ||
			name.Contains( "zariv" ) ||
			name.Contains( "bakelit" ) ||
			name.Contains( "reflektor" ) ||
			name.Contains( "light" ) ||
			name.Contains( "lustr" ) ||
			name.Contains( "blikack" ) ||
			name.Contains( "svicka" ) ||
			name.Contains( "svicen" ) ||
			name.Contains( "louc" ) ||
			name.Contains( "lampice" );
	}

	static float GetFixtureLightOffset( string modelName )
	{
		var name = modelName?.ToLowerInvariant() ?? string.Empty;

		// These offsets come from the corresponding HROT constructors. lampa4
		// attaches its bulb mesh 2.67 units above the post, while lampa2 uses
		// 0.49. Chandeliers are already positioned at their emitting height.
		if ( name.Contains( "lampa4" ) )
			return 2.67f;
		if ( name.Contains( "lampa2" ) )
			return 0.49f;
		if ( name.Contains( "lustr" ) )
			return 0.0f;
		if ( name.Contains( "zariv" ) || name.Contains( "bakelit" ) )
			return -0.2f;

		return 0.25f;
	}

	static void AddPointLight( string name, Vector3 position )
	{
		var lightObject = new GameObject( true, name );
		lightObject.WorldPosition = position;
		var light = lightObject.AddComponent<PointLight>();
		light.LightColor = new Color( 1.0f, 0.78f, 0.52f ) * 2.5f;
		light.Radius = UnitScale * 7.0f;
		light.Attenuation = 1.2f;
		light.Shadows = false;
		light.FogStrength = 0.35f;
	}

	static void SpawnFallbackPointLights( HrotMapGrid grid )
	{
		// HROT's visible lamp entities are created by gameplay code rather
		// than the static-model constructor. Until those entity constructors
		// are mounted, provide sparse ceiling lights at valid indoor sectors.
		var count = 0;
		for ( var y = 3; y < HrotExecutableMapData.GridSize - 3 && count < 48; y += 6 )
		{
			for ( var x = 3; x < HrotExecutableMapData.GridSize - 3 && count < 48; x += 6 )
			{
				var cell = grid.Cell( x, y );
				if ( !cell.HasFloor || !cell.HasCeiling ||
					cell.CeilingHeight - cell.FloorHeight < 1.0f )
					continue;

				AddPointLight(
					$"light_fallback_{y}_{x}",
					new Vector3(
						(y + 0.5f) * UnitScale,
						-(x + 0.5f) * UnitScale,
						(cell.CeilingHeight - 0.2f) * UnitScale ) );
				count++;
			}
		}
	}
}
